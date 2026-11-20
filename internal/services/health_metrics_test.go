package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
	"github.com/securesign/rhtas-console/internal/prometheus"
)

// fakeProm answers queries by matching a distinctive substring of the query.
type fakeProm struct {
	mu      sync.Mutex
	answers map[string][]prometheus.Sample
	err     error
	queries []string
}

func (f *fakeProm) Query(_ context.Context, q string) ([]prometheus.Sample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if f.err != nil {
		return nil, f.err
	}
	// The longest matching key wins, so a specific key (e.g. a recent-window
	// query) takes precedence over a more general one.
	best := ""
	for key := range f.answers {
		if strings.Contains(q, key) && len(key) > len(best) {
			best = key
		}
	}
	if best == "" {
		return nil, nil
	}
	return f.answers[best], nil
}

func s(labels map[string]string, v float64) prometheus.Sample {
	return prometheus.Sample{Labels: labels, Value: v}
}

func code(c string) map[string]string     { return map[string]string{"code": c} }
func grpcCode(c string) map[string]string { return map[string]string{"grpc_code": c} }
func name(n string) map[string]string     { return map[string]string{"__name__": n} }

// Query keys used by fakeProm (distinctive parts of each fixed query).
const (
	qMonitored = "count by (__name__)"
	qFulcio    = "CreateSigningCertificate"
	qRekor     = `path="/api/v1/log/entries"`
	qTSA       = `path="/api/v1/timestamp"`
	qCerts     = "fulcio_new_certs"
	qEntries   = "rekor_new_entries"
	// Recent-window (5 minute) variants of the request queries.
	qFulcioRecent = `CreateSigningCertificate"}[300s]`
	qRekorRecent  = `path="/api/v1/log/entries"}[300s]`
	qTSARecent    = `path="/api/v1/timestamp"}[300s]`
)

func allMonitored() []prometheus.Sample {
	return []prometheus.Sample{
		s(name("grpc_server_handled_total"), 1),
		s(name("rekor_qps_by_api"), 1),
		s(name("timestamp_authority_http_requests_total"), 1),
	}
}

func newTestCollector(fp *fakeProm) (*metricsCollector, *time.Time) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m := &metricsCollector{
		client:    fp,
		namespace: "tas",
		interval:  time.Minute,
		now:       func() time.Time { return now },
	}
	return m, &now
}

func TestMetricsDisabled(t *testing.T) {
	var m *metricsCollector // PROMETHEUS_URL unset
	got := m.response()
	if got.Status != models.Disabled || got.Reason != nil || got.ErrorRates != nil || got.SigningActivity != nil || got.UpdatedAt != nil {
		t.Errorf("disabled response = %+v", got)
	}
	if got.WindowSeconds != 3600 {
		t.Errorf("windowSeconds = %d, want 3600", got.WindowSeconds)
	}
}

func TestMetricsAvailableMixedOutcomes(t *testing.T) {
	fp := &fakeProm{answers: map[string][]prometheus.Sample{
		qMonitored: allMonitored(),
		qFulcio: {
			s(grpcCode("OK"), 100),
			s(grpcCode("Internal"), 3),
			s(grpcCode("DeadlineExceeded"), 2),
			s(grpcCode("InvalidArgument"), 1),
		},
		qRekor: {s(code("201"), 50), s(code("500"), 5), s(code("400"), 1), s(code("504"), 1)},
		qTSA:   {s(code("200"), 40), s(code("503"), 1.6)}, // float noise is rounded
		qCerts: {s(map[string]string{}, 98)},
		qEntries: {
			s(map[string]string{}, 50),
		},
	}}
	m, _ := newTestCollector(fp)
	m.refresh(context.Background())

	got := m.response()
	if got.Status != models.Available || got.Reason != nil || got.UpdatedAt == nil {
		t.Fatalf("response = %+v", got)
	}
	r := got.ErrorRates
	// fulcio 106 req / 6 err, rekor 57 / 7, tsa 42 / 2
	if r.TotalRequests != 205 || r.TotalErrors != 15 || r.ServerErrors != 3+5+2 || r.ClientErrors != 1+1 || r.Timeouts != 2+1 {
		t.Errorf("totals = %+v", r)
	}
	assertRate(t, "errorRate", r.ErrorRate, 15.0/205)
	want := map[string][2]int64{"fulcio": {106, 6}, "rekor": {57, 7}, "tsa": {42, 2}}
	if len(r.ByService) != 3 {
		t.Fatalf("byService = %+v", r.ByService)
	}
	for _, e := range r.ByService {
		w := want[string(e.Name)]
		if !e.Monitored || e.Requests == nil || *e.Requests != w[0] || e.Errors == nil || *e.Errors != w[1] {
			t.Errorf("%s = %+v, want requests=%d errors=%d", e.Name, e, w[0], w[1])
		}
	}
	a := got.SigningActivity
	if a.CertificatesIssued == nil || *a.CertificatesIssued != 98 || a.LogEntriesAdded == nil || *a.LogEntriesAdded != 50 ||
		a.TimestampsIssued == nil || *a.TimestampsIssued != 40 {
		t.Errorf("activity = %+v", a)
	}
}

// Every query is scoped to the Securesign namespace and only signing
// operations are counted (probe and health-check traffic excluded).
func TestMetricsQueriesAreScoped(t *testing.T) {
	fp := &fakeProm{answers: map[string][]prometheus.Sample{qMonitored: allMonitored()}}
	m, _ := newTestCollector(fp)
	m.refresh(context.Background())

	if len(fp.queries) != 9 {
		t.Fatalf("ran %d queries, want 9 (3 per round + 2 windows x 3 services)", len(fp.queries))
	}
	for _, q := range fp.queries {
		if !strings.Contains(q, `namespace="tas"`) {
			t.Errorf("query not scoped to the namespace: %s", q)
		}
		if strings.Contains(q, "/api/v1/log\"") || strings.Contains(q, "/ping") || strings.Contains(q, "certchain") {
			t.Errorf("query must not count probe or health-check paths: %s", q)
		}
	}
	joined := strings.Join(fp.queries, "\n")
	for _, want := range []string{`method="POST", path="/api/v1/log/entries"`, `method="POST", path="/api/v1/timestamp"`, `grpc_method="CreateSigningCertificate"`, "[3600s]", "[300s]"} {
		if !strings.Contains(joined, want) {
			t.Errorf("queries missing %q", want)
		}
	}
	// increase() is avoided: it misses series created inside the window and
	// extrapolates small counts.
	if strings.Contains(joined, "increase(") {
		t.Error("queries must not use increase()")
	}
}

func TestWindowCount(t *testing.T) {
	got := windowCount(`m{namespace="tas"}`, "3600s")
	want := `((last_over_time(m{namespace="tas"}[3600s]) - (m{namespace="tas"} offset 3600s)) >= 0 or last_over_time(m{namespace="tas"}[3600s]))`
	if got != want {
		t.Errorf("windowCount =\n%s\nwant\n%s", got, want)
	}
}

// An idle deployment reports zero counts and no error rate (not "0% errors").
func TestMetricsIdle(t *testing.T) {
	fp := &fakeProm{answers: map[string][]prometheus.Sample{qMonitored: allMonitored()}}
	m, _ := newTestCollector(fp)
	m.refresh(context.Background())

	got := m.response()
	r := got.ErrorRates
	if got.Status != models.Available || r.TotalRequests != 0 || r.TotalErrors != 0 || r.ErrorRate != nil {
		t.Errorf("idle response = %+v / %+v", got, r)
	}
	for _, e := range r.ByService {
		if e.Requests == nil || *e.Requests != 0 || e.ErrorRate != nil {
			t.Errorf("idle %s = %+v", e.Name, e)
		}
	}
	if a := got.SigningActivity; a.CertificatesIssued == nil || *a.CertificatesIssued != 0 {
		t.Errorf("idle activity = %+v", a)
	}
}

// Services without metrics in Prometheus are reported as not monitored with
// null counts instead of zeros.
func TestMetricsPartiallyMonitored(t *testing.T) {
	fp := &fakeProm{answers: map[string][]prometheus.Sample{
		qMonitored: {s(name("rekor_qps_by_api"), 1)},
		qRekor:     {s(code("201"), 10), s(code("500"), 1)},
		qEntries:   {s(map[string]string{}, 10)},
	}}
	m, _ := newTestCollector(fp)
	m.refresh(context.Background())

	got := m.response()
	if got.Status != models.Available {
		t.Fatalf("status = %q", got.Status)
	}
	for _, e := range got.ErrorRates.ByService {
		switch e.Name {
		case models.ServiceErrorRateNameRekor:
			if !e.Monitored || *e.Requests != 11 || *e.Errors != 1 {
				t.Errorf("rekor = %+v", e)
			}
		default:
			if e.Monitored || e.Requests != nil || e.Errors != nil || e.ErrorRate != nil {
				t.Errorf("%s should be unmonitored with null counts: %+v", e.Name, e)
			}
		}
	}
	if got.ErrorRates.TotalRequests != 11 {
		t.Errorf("totals must only include monitored services: %+v", got.ErrorRates)
	}
	a := got.SigningActivity
	if a.CertificatesIssued != nil || a.TimestampsIssued != nil || a.LogEntriesAdded == nil || *a.LogEntriesAdded != 10 {
		t.Errorf("activity = %+v", a)
	}
}

func TestMetricsNoComponentMonitored(t *testing.T) {
	m, _ := newTestCollector(&fakeProm{})
	m.refresh(context.Background())

	got := m.response()
	if got.Status != models.Unavailable || got.ErrorRates != nil || got.SigningActivity != nil {
		t.Errorf("response = %+v", got)
	}
	if got.Reason == nil || !strings.Contains(*got.Reason, "enable monitoring") {
		t.Errorf("reason = %v, want a hint to enable monitoring", got.Reason)
	}
}

// A failed refresh keeps the last good data while it is fresh (up to two
// refresh intervals), then reports unavailable with the reason.
func TestMetricsStaleAfterFailures(t *testing.T) {
	fp := &fakeProm{answers: map[string][]prometheus.Sample{qMonitored: allMonitored()}}
	m, now := newTestCollector(fp)
	m.refresh(context.Background())
	firstAt := *now

	fp.err = &prometheus.StatusError{Code: http.StatusServiceUnavailable}
	*now = now.Add(time.Minute)
	m.refresh(context.Background())
	if got := m.response(); got.Status != models.Available || !got.UpdatedAt.Equal(firstAt) {
		t.Errorf("within 2 intervals: status=%q updatedAt=%v, want available with the old data", got.Status, got.UpdatedAt)
	}

	*now = firstAt.Add(3 * time.Minute)
	m.refresh(context.Background())
	got := m.response()
	if got.Status != models.Unavailable || got.ErrorRates != nil {
		t.Errorf("after expiry: %+v", got)
	}
	if got.Reason == nil || *got.Reason != "Prometheus returned HTTP 503" {
		t.Errorf("reason = %v", got.Reason)
	}
	if got.UpdatedAt == nil || !got.UpdatedAt.Equal(firstAt) {
		t.Errorf("updatedAt should still show the last successful query, got %v", got.UpdatedAt)
	}

	fp.err = nil
	m.refresh(context.Background())
	if got := m.response(); got.Status != models.Available || got.Reason != nil {
		t.Errorf("after recovery: %+v", got)
	}
}

func TestMetricsBeforeFirstQuery(t *testing.T) {
	m, _ := newTestCollector(&fakeProm{})
	got := m.response()
	if got.Status != models.Unavailable || got.Reason == nil || got.UpdatedAt != nil {
		t.Errorf("response = %+v", got)
	}
}

func TestPublicMetricsError(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{&prometheus.StatusError{Code: http.StatusForbidden}, "not authorized to query Prometheus; check the console ServiceAccount permissions"},
		{&prometheus.StatusError{Code: http.StatusUnauthorized}, "not authorized to query Prometheus; check the console ServiceAccount permissions"},
		{&prometheus.StatusError{Code: http.StatusBadGateway}, "Prometheus returned HTTP 502"},
		{&prometheus.QueryError{Type: "bad_data"}, "Prometheus rejected the query"},
		{fmt.Errorf("x: %w", prometheus.ErrInvalidResponse), "invalid response from Prometheus"},
		{fmt.Errorf("x: %w", context.DeadlineExceeded), "Prometheus query timed out"},
		{fmt.Errorf("read prometheus token: %w", os.ErrNotExist), "cannot read the Prometheus token file"},
		{errors.New(`Get "https://thanos.internal:9091/api/v1/query": connection refused`), "Prometheus unreachable"},
	}
	for _, tt := range tests {
		got := publicMetricsError(tt.err)
		if got != tt.want {
			t.Errorf("publicMetricsError(%v) = %q, want %q", tt.err, got, tt.want)
		}
		if strings.Contains(got, "thanos.internal") {
			t.Errorf("reason leaks the URL: %q", got)
		}
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		svc    string
		labels map[string]string
		want   outcome
	}{
		{svcFulcio, grpcCode("OK"), outcomeSuccess},
		{svcFulcio, grpcCode("Unavailable"), outcomeServer},
		{svcFulcio, grpcCode("Unauthenticated"), outcomeClient},
		{svcFulcio, grpcCode("DeadlineExceeded"), outcomeTimeout},
		{svcFulcio, grpcCode("SomethingNew"), outcomeServer},
		{svcRekor, code("201"), outcomeSuccess},
		{svcRekor, code("409"), outcomeClient},
		{svcRekor, code("408"), outcomeTimeout},
		{svcRekor, code("504"), outcomeTimeout},
		{svcRekor, code("502"), outcomeServer},
		{svcTsa, code(""), outcomeServer},
	}
	for _, tt := range tests {
		if got := classify(tt.svc, tt.labels); got != tt.want {
			t.Errorf("classify(%s, %v) = %v, want %v", tt.svc, tt.labels, got, tt.want)
		}
	}
}

// Invalid configuration (e.g. a bad URL) reports unavailable instead of
// disabling the whole health endpoint.
func TestMetricsInvalidConfiguration(t *testing.T) {
	t.Setenv("PROMETHEUS_URL", "thanos:9091") // no scheme
	m := newMetricsCollectorFromEnv("tas")
	if m == nil || m.configErr == nil {
		t.Fatalf("collector = %+v, want a configuration error", m)
	}
	got := m.response()
	if got.Status != models.Unavailable || got.Reason == nil || !strings.Contains(*got.Reason, "invalid Prometheus configuration") {
		t.Errorf("response = %+v", got)
	}
	m.run(context.Background(), make(chan struct{})) // must return immediately
}

func TestMetricsDisabledWithoutURL(t *testing.T) {
	t.Setenv("PROMETHEUS_URL", "")
	if m := newMetricsCollectorFromEnv("tas"); m != nil {
		t.Errorf("collector = %+v, want nil (disabled)", m)
	}
}

// End-to-end through the real client against a fake Prometheus server: the
// namespace parameter and the bearer token are sent, and the health response
// carries the metrics.
func TestMetricsEndToEndInHealthResponse(t *testing.T) {
	var mu sync.Mutex
	var namespaces, auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		namespaces = append(namespaces, r.URL.Query().Get("namespace"))
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		q := r.URL.Query().Get("query")
		result := []map[string]any{}
		switch {
		case strings.Contains(q, qMonitored):
			result = append(result, map[string]any{"metric": map[string]string{"__name__": "rekor_qps_by_api"}, "value": []any{1, "1"}})
		case strings.Contains(q, qRekor):
			result = append(result, map[string]any{"metric": map[string]string{"code": "201"}, "value": []any{1, "4"}})
		case strings.Contains(q, qEntries):
			result = append(result, map[string]any{"metric": map[string]string{}, "value": []any{1, "4"}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": result}})
	}))
	defer srv.Close()

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROMETHEUS_URL", srv.URL)
	t.Setenv("PROMETHEUS_TOKEN_PATH", tokenPath)

	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.metrics = newMetricsCollectorFromEnv(testNamespace)
	h.metrics.refresh(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	if resp.Metrics.Status != models.Available {
		t.Fatalf("metrics = %+v", resp.Metrics)
	}
	if a := resp.Metrics.SigningActivity; a.LogEntriesAdded == nil || *a.LogEntriesAdded != 4 {
		t.Errorf("activity = %+v", a)
	}
	mu.Lock()
	defer mu.Unlock()
	for i := range namespaces {
		if namespaces[i] != testNamespace || auths[i] != "Bearer tok" {
			t.Errorf("request %d: namespace=%q auth=%q", i, namespaces[i], auths[i])
		}
	}
}

// Without Prometheus configured, the health response is unchanged apart from
// metrics.status = disabled.
func TestHealthResponseMetricsDisabledByDefault(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	if resp.Metrics.Status != models.Disabled || resp.Metrics.ErrorRates != nil || resp.Metrics.SigningActivity != nil {
		t.Errorf("metrics = %+v", resp.Metrics)
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"metrics":{"errorRates":null,"reason":null,"signingActivity":null,"status":"disabled","updatedAt":null,"windowSeconds":3600}`) {
		t.Errorf("unexpected metrics JSON in %s", body)
	}
}

func TestMetricsRunStops(t *testing.T) {
	fp := &fakeProm{answers: map[string][]prometheus.Sample{qMonitored: allMonitored()}}
	m, _ := newTestCollector(fp)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		m.run(context.Background(), stop)
		close(done)
	}()
	waitFor(t, "first refresh", func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.snapshot != nil
	})
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop")
	}
}

// The recent window tells "failing now" apart from "recovered": here Fulcio
// failed 9 times in the hour, but its recent request succeeded, while Rekor's
// recent requests are still failing.
func TestMetricsRecentWindow(t *testing.T) {
	fp := &fakeProm{answers: map[string][]prometheus.Sample{
		qMonitored:    allMonitored(),
		qFulcio:       {s(grpcCode("OK"), 1), s(grpcCode("InvalidArgument"), 9)},
		qFulcioRecent: {s(grpcCode("OK"), 1)},
		qRekor:        {s(code("201"), 5), s(code("500"), 4)},
		qRekorRecent:  {s(code("500"), 2)},
		qTSA:          {s(code("200"), 3)},
		qTSARecent:    nil, // no recent activity
	}}
	m, _ := newTestCollector(fp)
	m.refresh(context.Background())

	got := m.response()
	if got.Status != models.Available {
		t.Fatalf("status = %q", got.Status)
	}
	if got.ErrorRates.RecentWindowSeconds != 300 {
		t.Errorf("recentWindowSeconds = %d, want 300", got.ErrorRates.RecentWindowSeconds)
	}
	recent := map[string]*models.RecentErrorRate{}
	for _, e := range got.ErrorRates.ByService {
		recent[string(e.Name)] = e.Recent
	}

	// Fulcio: recovered (errors in the hour, recent request succeeded).
	if r := recent["fulcio"]; r == nil || r.Requests != 1 || r.Errors != 0 {
		t.Errorf("fulcio recent = %+v", r)
	} else {
		assertRate(t, "fulcio recent errorRate", r.ErrorRate, 0)
	}
	// Rekor: still failing.
	if r := recent["rekor"]; r == nil || r.Requests != 2 || r.Errors != 2 {
		t.Errorf("rekor recent = %+v", r)
	} else {
		assertRate(t, "rekor recent errorRate", r.ErrorRate, 1)
	}
	// TSA: no recent activity, so no rate.
	if r := recent["tsa"]; r == nil || r.Requests != 0 || r.ErrorRate != nil {
		t.Errorf("tsa recent = %+v, want 0 requests and errorRate nil", r)
	}

	// The full-window counts are unchanged by the recent window.
	for _, e := range got.ErrorRates.ByService {
		if e.Name == models.ServiceErrorRateNameFulcio && (*e.Requests != 10 || *e.Errors != 9) {
			t.Errorf("fulcio window counts = %+v", e)
		}
	}
}

// Services without metrics have no recent counts either.
func TestMetricsRecentNullWhenUnmonitored(t *testing.T) {
	fp := &fakeProm{answers: map[string][]prometheus.Sample{
		qMonitored:   {s(name("rekor_qps_by_api"), 1)},
		qRekorRecent: {s(code("201"), 1)},
	}}
	m, _ := newTestCollector(fp)
	m.refresh(context.Background())

	for _, e := range m.response().ErrorRates.ByService {
		if e.Name == models.ServiceErrorRateNameRekor {
			if e.Recent == nil || e.Recent.Requests != 1 {
				t.Errorf("rekor recent = %+v", e.Recent)
			}
		} else if e.Recent != nil {
			t.Errorf("%s recent = %+v, want nil (not monitored)", e.Name, e.Recent)
		}
	}
}
