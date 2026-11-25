package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
	"github.com/securesign/rhtas-console/internal/prometheus"
)

// Metrics (Prometheus) defaults. All overridable via environment variables.
const (
	defaultMetricsRefreshSeconds = 60
	metricsWindow                = time.Hour
	// metricsRecentWindow is the short window used to tell whether failures
	// are still happening or have stopped (per-service "recent" counts).
	metricsRecentWindow = 5 * time.Minute
	metricsQueryTimeout = 10 * time.Second
	// serviceAccountTokenFile is the pod's ServiceAccount token, used as the
	// default Prometheus bearer token when running in-cluster.
	serviceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// monitoredSelector returns, per signing service, a selector whose presence in
// Prometheus (within the last window) shows that this service (and not another one using the same
// generic metric, such as another gRPC server) is scraped.
func monitoredSelector(svc, ns string) string {
	switch svc {
	case svcFulcio:
		return fmt.Sprintf(`grpc_server_handled_total{namespace=%s, grpc_service="dev.sigstore.fulcio.v2.CA"}`, ns)
	case svcRekor:
		return fmt.Sprintf(`rekor_qps_by_api{namespace=%s}`, ns)
	default: // svcTsa
		return fmt.Sprintf(`timestamp_authority_http_requests_total{namespace=%s}`, ns)
	}
}

// metricsServices is the stable order of services in byService.
var metricsServices = []string{svcFulcio, svcRekor, svcTsa}

// queryClient is the subset of prometheus.Client used here (fakeable in tests).
type queryClient interface {
	Query(ctx context.Context, query string) ([]prometheus.Sample, error)
}

// metricsSnapshot is the result of one successful query round.
type metricsSnapshot struct {
	at         time.Time
	errorRates models.SigningErrorRates
	activity   models.SigningActivity
	// noneMonitored is true when Prometheus has no metrics for any service.
	noneMonitored bool
}

// metricsCollector periodically queries Prometheus and caches the result. A nil
// collector means the feature is disabled (no PROMETHEUS_URL).
type metricsCollector struct {
	client    queryClient
	namespace string
	interval  time.Duration
	now       func() time.Time

	// configErr is set when PROMETHEUS_URL is set but the client could not be
	// created (e.g. unreadable CA bundle); the feature then reports unavailable.
	configErr error

	mu       sync.RWMutex
	snapshot *metricsSnapshot
	// lastErr is the client-safe reason of the last failed round ("" when the
	// last round succeeded).
	lastErr string
	// lastLoggedErr is the last raw error logged (refresh goroutine only).
	lastLoggedErr string
}

// newMetricsCollectorFromEnv builds the collector from PROMETHEUS_* variables.
// It returns nil when PROMETHEUS_URL is unset (feature disabled).
func newMetricsCollectorFromEnv(namespace string) *metricsCollector {
	rawURL := strings.TrimSpace(os.Getenv("PROMETHEUS_URL"))
	if rawURL == "" {
		return nil
	}
	m := &metricsCollector{
		namespace: namespace,
		interval:  time.Duration(envIntMax("PROMETHEUS_REFRESH_SECONDS", defaultMetricsRefreshSeconds, maxIntervalSeconds)) * time.Second,
		now:       func() time.Time { return time.Now().UTC() },
	}
	tokenPath, ok := os.LookupEnv("PROMETHEUS_TOKEN_PATH")
	if !ok {
		if _, err := os.Stat(serviceAccountTokenFile); err == nil {
			tokenPath = serviceAccountTokenFile
		}
	}
	client, err := prometheus.New(prometheus.Config{
		URL:       rawURL,
		TokenPath: tokenPath,
		CAPath:    os.Getenv("PROMETHEUS_CA_PATH"),
		Namespace: namespace,
		Timeout:   metricsQueryTimeout,
	})
	if err != nil {
		log.Printf("health: invalid Prometheus configuration, signing metrics unavailable: %v", err)
		m.configErr = err
		return m
	}
	m.client = client
	return m
}

// run refreshes immediately, then on every interval until ctx is done or stop
// is closed.
func (m *metricsCollector) run(ctx context.Context, stop <-chan struct{}) {
	if m.configErr != nil {
		return
	}
	m.refresh(ctx)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			m.refresh(ctx)
		}
	}
}

// refresh runs all queries in parallel and publishes the result atomically.
// On failure the previous snapshot is kept (see response for staleness).
func (m *metricsCollector) refresh(ctx context.Context) {
	if m.client == nil { // invalid configuration: nothing to query
		return
	}
	ctx, cancel := context.WithTimeout(ctx, metricsQueryTimeout)
	defer cancel()

	snap, err := m.query(ctx)
	m.logError(err)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.lastErr = publicMetricsError(err)
		return
	}
	m.lastErr = ""
	m.snapshot = snap
}

// promQueries holds the fixed queries of one round.
type promQueries struct {
	monitored, certs, entries string
	// byCode and recentByCode are, per service, the request counts grouped by
	// status code over the full window and over the recent window.
	byCode, recentByCode map[string]string
}

// requestSelector returns, per service, the selector of its signing requests.
func requestSelector(svc, ns string) string {
	switch svc {
	case svcFulcio:
		return fmt.Sprintf(`grpc_server_handled_total{namespace=%s, grpc_service="dev.sigstore.fulcio.v2.CA", grpc_method="CreateSigningCertificate"}`, ns)
	case svcRekor:
		return fmt.Sprintf(`rekor_qps_by_api{namespace=%s, method="POST", path="/api/v1/log/entries"}`, ns)
	default: // svcTsa
		return fmt.Sprintf(`timestamp_authority_http_requests_total{namespace=%s, method="POST", path="/api/v1/timestamp"}`, ns)
	}
}

// codeLabel is the label holding the request outcome for a service.
func codeLabel(svc string) string {
	if svc == svcFulcio {
		return "grpc_code"
	}
	return "code"
}

func (m *metricsCollector) queries() promQueries {
	ns := strconv.Quote(m.namespace)
	w := fmt.Sprintf("%ds", int(metricsWindow.Seconds()))
	recent := fmt.Sprintf("%ds", int(metricsRecentWindow.Seconds()))
	monitored := make([]string, 0, len(metricsServices))
	q := promQueries{byCode: map[string]string{}, recentByCode: map[string]string{}}
	for _, svc := range metricsServices {
		// last_over_time over the window, not an instant selector: an instant
		// selector goes stale 5 minutes after the last scrape, which would drop
		// the hourly history of a service that is down (and so no longer scraped).
		monitored = append(monitored, fmt.Sprintf(`label_replace(count(last_over_time(%s[%s])), "service", %q, "", "")`, monitoredSelector(svc, ns), w, svc))
		q.byCode[svc] = fmt.Sprintf(`sum by (%s) (%s)`, codeLabel(svc), windowCount(requestSelector(svc, ns), w))
		q.recentByCode[svc] = fmt.Sprintf(`sum by (%s) (%s)`, codeLabel(svc), windowCount(requestSelector(svc, ns), recent))
	}
	q.monitored = strings.Join(monitored, " or ")
	q.certs = fmt.Sprintf(`sum(%s)`, windowCount(fmt.Sprintf(`fulcio_new_certs{namespace=%s}`, ns), w))
	q.entries = fmt.Sprintf(`sum(%s)`, windowCount(fmt.Sprintf(`rekor_new_entries{namespace=%s}`, ns), w))
	return q
}

// windowStartLookback is how far before the window start a series' last value
// is looked up, so that a scrape gap at the window boundary is not mistaken
// for a new series (whose whole value would then be counted).
const windowStartLookback = "3600s"

// windowCount returns, per series, how much a counter grew over the window:
//
//   - after a counter reset within the window (resets() > 0, e.g. a container
//     restart that keeps the same labels) for a series that existed at the
//     window start: increase(), which handles resets. This is decided by
//     resets(), not by the sign of the difference: a counter that restarts
//     and then grows past its old value would otherwise look like a normal
//     increase and lose everything counted before the old value;
//   - normally: its last value in the window minus its value at the window
//     start (the last sample in the hour before the window);
//   - for a series created inside the window: its whole last value.
//
// increase() is not used everywhere on purpose: it misses the first events of
// a series created inside the window (a new status code going from "absent" to
// N) and extrapolates small counts (e.g. 4 events reported as 6.3). Both
// distort error counts, where new codes are the norm. Series that disappeared
// during the window (e.g. a replaced pod) are still counted through
// last_over_time.
func windowCount(selector, window string) string {
	last := fmt.Sprintf(`last_over_time(%s[%s])`, selector, window)
	start := fmt.Sprintf(`last_over_time(%s[%s] offset %s)`, selector, windowStartLookback, window)
	return fmt.Sprintf(`((increase(%[3]s[%[4]s]) and (resets(%[3]s[%[4]s]) > 0) and %[2]s) or ((%[1]s - %[2]s) >= 0) or %[1]s)`, last, start, selector, window)
}

// query runs one round of queries and builds a snapshot.
func (m *metricsCollector) query(ctx context.Context) (*metricsSnapshot, error) {
	q := m.queries()
	names := []string{q.monitored, q.certs, q.entries}
	byCodeIdx, recentIdx := map[string]int{}, map[string]int{}
	for _, svc := range metricsServices {
		byCodeIdx[svc] = len(names)
		names = append(names, q.byCode[svc])
		recentIdx[svc] = len(names)
		names = append(names, q.recentByCode[svc])
	}
	results := make([][]prometheus.Sample, len(names))
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, query := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = m.client.Query(ctx, query)
		}()
	}
	wg.Wait()
	// Report the first failure (the others are usually the same cause) with
	// the number of failed queries, so a single log line explains the round.
	var first error
	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
			if first == nil {
				first = err
			}
		}
	}
	if first != nil {
		return nil, fmt.Errorf("%d of %d queries failed: %w", failed, len(names), first)
	}

	monitored := map[string]bool{}
	for _, s := range results[0] {
		if s.Value > 0 {
			monitored[s.Labels["service"]] = true
		}
	}

	snap := &metricsSnapshot{at: m.now()}
	totals := models.SigningErrorRates{
		ByService:           []models.ServiceErrorRate{},
		RecentWindowSeconds: int(metricsRecentWindow.Seconds()),
	}
	anyMonitored := false
	var tsaSuccess int64
	for _, svc := range metricsServices {
		entry := models.ServiceErrorRate{Name: models.ServiceErrorRateName(svc), Monitored: monitored[svc]}
		if monitored[svc] {
			anyMonitored = true
			var requests, errCount int64
			for _, sample := range results[byCodeIdx[svc]] {
				n := count(sample.Value)
				requests += n
				switch classify(svc, sample.Labels) {
				case outcomeServer:
					totals.ServerErrors += n
					errCount += n
				case outcomeClient:
					totals.ClientErrors += n
					errCount += n
				case outcomeTimeout:
					totals.Timeouts += n
					errCount += n
				case outcomeSuccess:
					if svc == svcTsa {
						tsaSuccess += n
					}
				}
			}
			entry.Requests = int64ptr(requests)
			entry.Errors = int64ptr(errCount)
			entry.ErrorRate = ratio(errCount, requests)
			entry.Recent = recentRate(svc, results[recentIdx[svc]])
			totals.TotalRequests += requests
			totals.TotalErrors += errCount
		}
		totals.ByService = append(totals.ByService, entry)
	}
	totals.ErrorRate = ratio(totals.TotalErrors, totals.TotalRequests)
	snap.errorRates = totals
	snap.noneMonitored = !anyMonitored

	if monitored[svcFulcio] {
		snap.activity.CertificatesIssued = int64ptr(sumCount(results[1]))
	}
	if monitored[svcRekor] {
		snap.activity.LogEntriesAdded = int64ptr(sumCount(results[2]))
	}
	if monitored[svcTsa] {
		snap.activity.TimestampsIssued = int64ptr(tsaSuccess)
	}
	return snap, nil
}

// response builds the API representation from the cached state.
func (m *metricsCollector) response() models.SystemHealthMetrics {
	out := models.SystemHealthMetrics{
		Status:        models.Disabled,
		WindowSeconds: int(metricsWindow.Seconds()),
	}
	if m == nil {
		return out
	}
	out.Status = models.Unavailable
	if m.configErr != nil {
		out.Reason = strptr("invalid Prometheus configuration; see the console logs")
		return out
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	snap := m.snapshot
	fresh := snap != nil && m.now().Sub(snap.at) <= 2*m.interval
	if snap != nil {
		at := snap.at
		out.UpdatedAt = &at
	}
	switch {
	case fresh && snap.noneMonitored:
		out.Reason = strptr("no RHTAS component metrics found in Prometheus; enable monitoring for Fulcio, Rekor and TSA in the Securesign CR")
	case fresh:
		out.Status = models.Available
		rates := snap.errorRates
		activity := snap.activity
		out.ErrorRates = &rates
		out.SigningActivity = &activity
	case m.lastErr != "":
		out.Reason = strptr(m.lastErr)
	default:
		out.Reason = strptr("no metrics query has completed yet")
	}
	return out
}

// logError logs query failures when they start or change, and recovery.
func (m *metricsCollector) logError(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg == m.lastLoggedErr {
		return
	}
	if err != nil {
		log.Printf("health: Prometheus query failed, signing metrics unavailable: %v", err)
	} else if m.lastLoggedErr != "" {
		log.Printf("health: Prometheus queries succeed again")
	}
	m.lastLoggedErr = msg
}

// publicMetricsError maps a query error to a short, client-safe reason (the
// raw error can contain the Prometheus URL and is only logged).
func publicMetricsError(err error) string {
	var statusErr *prometheus.StatusError
	var queryErr *prometheus.QueryError
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.As(err, &statusErr) && (statusErr.Code == http.StatusUnauthorized || statusErr.Code == http.StatusForbidden):
		return "not authorized to query Prometheus; check the console ServiceAccount permissions"
	case errors.As(err, &statusErr):
		return fmt.Sprintf("Prometheus returned HTTP %d", statusErr.Code)
	case errors.As(err, &queryErr):
		return "Prometheus rejected the query"
	case errors.Is(err, prometheus.ErrInvalidResponse):
		return "invalid response from Prometheus"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return "Prometheus query timed out"
	case errors.As(err, &dnsErr):
		return "Prometheus endpoint not found (DNS lookup failed)"
	case errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission):
		return "cannot read the Prometheus token file"
	default:
		return "Prometheus unreachable"
	}
}

// outcome classifies a request result.
type outcome int

const (
	outcomeSuccess outcome = iota
	outcomeServer
	outcomeClient
	outcomeTimeout
)

// grpcOutcomes classifies gRPC status codes (go-grpc-prometheus names).
var grpcOutcomes = map[string]outcome{
	"OK":                 outcomeSuccess,
	"DeadlineExceeded":   outcomeTimeout,
	"InvalidArgument":    outcomeClient,
	"NotFound":           outcomeClient,
	"AlreadyExists":      outcomeClient,
	"PermissionDenied":   outcomeClient,
	"Unauthenticated":    outcomeClient,
	"FailedPrecondition": outcomeClient,
	"OutOfRange":         outcomeClient,
	"ResourceExhausted":  outcomeClient,
	"Canceled":           outcomeClient,
	"Internal":           outcomeServer,
	"Unavailable":        outcomeServer,
	"Unknown":            outcomeServer,
	"DataLoss":           outcomeServer,
	"Aborted":            outcomeServer,
	"Unimplemented":      outcomeServer,
}

// classify maps a sample's status label to an outcome. Only 2xx is a success:
// the counted signing endpoints never redirect, so a 3xx (e.g. from a proxy)
// means the request was not processed. 3xx and any other unrecognized code are
// treated as server errors.
func classify(svc string, labels map[string]string) outcome {
	if svc == svcFulcio {
		if o, ok := grpcOutcomes[labels["grpc_code"]]; ok {
			return o
		}
		return outcomeServer
	}
	code, err := strconv.Atoi(labels["code"])
	switch {
	case err != nil:
		return outcomeServer
	case code >= 200 && code < 300:
		return outcomeSuccess
	case code == http.StatusGatewayTimeout || code == http.StatusRequestTimeout:
		return outcomeTimeout
	case code >= 400 && code < 500:
		return outcomeClient
	default:
		return outcomeServer
	}
}

// recentRate summarizes a service's request outcomes over the recent window.
func recentRate(svc string, samples []prometheus.Sample) *models.RecentErrorRate {
	var requests, errCount int64
	for _, sample := range samples {
		n := count(sample.Value)
		requests += n
		if classify(svc, sample.Labels) != outcomeSuccess {
			errCount += n
		}
	}
	return &models.RecentErrorRate{Requests: requests, Errors: errCount, ErrorRate: ratio(errCount, requests)}
}

// count converts a counter delta to a whole number of events (counters are
// integers, so this only guards against float noise); NaN/Inf/negative count
// as zero.
func count(v float64) int64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return int64(math.Round(v))
}

func sumCount(samples []prometheus.Sample) int64 {
	var total int64
	for _, s := range samples {
		total += count(s.Value)
	}
	return total
}

func ratio(part, whole int64) *float32 {
	if whole <= 0 {
		return nil
	}
	return f32ptr(float64(part) / float64(whole))
}

func int64ptr(v int64) *int64 { return &v }
