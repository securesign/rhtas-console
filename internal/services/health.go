package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/securesign/rhtas-console/internal/httpclient"
	"github.com/securesign/rhtas-console/internal/models"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var securesignGVR = schema.GroupVersionResource{
	Group:    "rhtas.redhat.com",
	Version:  "v1",
	Resource: "securesigns",
}

// Default prober tuning. All overridable via environment variables.
const (
	defaultProbeIntervalSeconds = 30
	defaultProbeHistorySize     = 120 // ~1h at a 30s interval
	defaultProbeTimeoutSeconds  = 5
	// defaultFailureThreshold is the number of consecutive failed HTTP probes
	// required before a service is reported unhealthy. It absorbs one-off
	// timeouts (e.g. cold connections through the ingress router) that would
	// otherwise flip the status for a whole probe interval.
	defaultFailureThreshold = 2
	// maxProbeBodyBytes bounds how much of a probe response is drained.
	maxProbeBodyBytes = 1 << 20
)

// Component service identifiers.
const (
	svcRekor    = "rekor"
	svcFulcio   = "fulcio"
	svcCtlog    = "ctlog"
	svcTrillian = "trillian"
	svcTsa      = "tsa"
	svcTuf      = "tuf"
)

// serviceSpec describes how a single component is observed.
type serviceSpec struct {
	name string
	// condition is the Securesign CR status condition type that reports this
	// component's availability.
	condition string
	// urlStatusPath is the Securesign CR `.status.<...>.url` location that holds
	// this component's externally reachable endpoint, or nil when the component
	// has no public endpoint and can only be observed via CR conditions.
	urlStatusPath []string
	// probePath is appended to the discovered URL to form the probe target.
	probePath string
}

// readyCondition is the Securesign CR condition the operator derives from all
// component conditions; it is exposed as the top-level securesignStatus.
const readyCondition = "Ready"

// serviceSpecs lists all components in a stable order. Services with a
// urlStatusPath are actively HTTP-probed; the rest are observed from CR
// conditions only (no latency data is fabricated for them).
var serviceSpecs = []serviceSpec{
	{name: svcRekor, condition: "RekorAvailable", urlStatusPath: []string{"status", "rekor", "url"}, probePath: "/api/v1/log"},
	{name: svcFulcio, condition: "FulcioAvailable", urlStatusPath: []string{"status", "fulcio", "url"}, probePath: "/api/v2/trustBundle"},
	{name: svcCtlog, condition: "CTlogAvailable"},
	{name: svcTrillian, condition: "TrillianAvailable"},
	// The TSA CR `.status.tsa.url` already includes the `/api/v1/timestamp` base
	// path, so only the cert-chain suffix is appended here.
	{name: svcTsa, condition: "TsaAvailable", urlStatusPath: []string{"status", "tsa", "url"}, probePath: "/certchain"},
	{name: svcTuf, condition: "TufAvailable", urlStatusPath: []string{"status", "tuf", "url"}, probePath: "/root.json"},
}

type HealthService interface {
	// GetSystemHealth returns the latest completed probe round. Per-service
	// probe samples are only included when includeHistory is true.
	GetSystemHealth(ctx context.Context, includeHistory bool) (models.SystemHealthResponse, int, error)
	// Start launches the background prober without blocking. It collects
	// immediately, then on the configured interval until ctx is cancelled or
	// Stop is called. Services report unknown until the first collection ends.
	Start(ctx context.Context)
	// Stop halts the background prober.
	Stop()
}

// sample is an internal probe observation.
type sample struct {
	timestamp time.Time
	// status is the outcome of this observation. Unknown means the outcome
	// could not be determined (e.g. the Securesign CR could not be read or the
	// condition is not reported) and is never counted as a failure.
	status     models.ServiceHealthStatus
	latency    time.Duration // valid only when source == "http" and a response was received
	hasLatency bool
	httpStatus int
	source     models.ProbeSampleSource
	err        string
}

func (s sample) success() bool { return s.status == models.ServiceHealthStatusHealthy }

// ringBuffer is a fixed-capacity, oldest-first buffer of samples for one service.
type ringBuffer struct {
	samples          []sample
	cap              int
	failureThreshold int
	consecutiveFail  int
	lastStateChange  *time.Time
	status           models.ServiceHealthStatus
	endpointURL      string
	probed           bool
}

func newRingBuffer(capacity, failureThreshold int, probed bool) *ringBuffer {
	if failureThreshold < 1 {
		failureThreshold = 1
	}
	return &ringBuffer{
		samples:          make([]sample, 0, capacity),
		cap:              capacity,
		failureThreshold: failureThreshold,
		status:           models.ServiceHealthStatusUnknown,
		probed:           probed,
	}
}

// add appends a sample and updates the derived service status.
//
// Condition-derived failures are reported immediately (the operator already
// debounces them). HTTP probe failures only mark the service unhealthy after
// failureThreshold consecutive failures; until then the previous status is kept.
func (b *ringBuffer) add(s sample) {
	if len(b.samples) >= b.cap && b.cap > 0 {
		b.samples = b.samples[1:]
	}
	b.samples = append(b.samples, s)

	newStatus := b.status
	switch s.status {
	case models.ServiceHealthStatusHealthy:
		b.consecutiveFail = 0
		newStatus = models.ServiceHealthStatusHealthy
	case models.ServiceHealthStatusUnhealthy:
		b.consecutiveFail++
		if s.source == models.Condition || b.consecutiveFail >= b.failureThreshold {
			newStatus = models.ServiceHealthStatusUnhealthy
		}
	default:
		b.consecutiveFail = 0
		newStatus = models.ServiceHealthStatusUnknown
	}

	if b.status != newStatus {
		ts := s.timestamp
		b.lastStateChange = &ts
		b.status = newStatus
	}
}

type healthService struct {
	dynamicClient dynamic.Interface
	namespace     string
	crName        string

	interval         time.Duration
	timeout          time.Duration
	historySize      int
	failureThreshold int

	httpClient *http.Client

	mu      sync.RWMutex
	buffers map[string]*ringBuffer
	// securesignStatus is the latest observation of the CR Ready condition, and
	// securesignStatusReason explains it when it is not healthy.
	securesignStatus       models.SystemHealthResponseSecuresignStatus
	securesignStatusReason *string
	// lastReadErr is the last CR read error that was logged (collector goroutine only).
	lastReadErr string
	// lastRoundAt is when the most recent probe round completed (nil before the first).
	lastRoundAt *time.Time
	// probeURLs optionally overrides the endpoint discovered from the CR status
	// for a service (e.g. an in-cluster Service URL instead of the external route).
	probeURLs map[string]string

	stopOnce sync.Once
	stopCh   chan struct{}

	// now and probeHTTP are injectable for testing.
	now       func() time.Time
	probeHTTP func(ctx context.Context, url string) (latency time.Duration, statusCode int, err error)
}

func NewHealthService() (HealthService, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	timeout := time.Duration(envInt("PROBE_TIMEOUT_SECONDS", defaultProbeTimeoutSeconds)) * time.Second

	h := &healthService{
		dynamicClient: dynamicClient,
		namespace:     resolveNamespace(),
		// Empty means: discover the single Securesign CR in the namespace.
		crName:           os.Getenv("TAS_DEPLOYMENT_NAME"),
		interval:         time.Duration(envInt("PROBE_INTERVAL_SECONDS", defaultProbeIntervalSeconds)) * time.Second,
		timeout:          timeout,
		historySize:      envInt("PROBE_HISTORY_SIZE", defaultProbeHistorySize),
		failureThreshold: envInt("PROBE_FAILURE_THRESHOLD", defaultFailureThreshold),
		httpClient:       newProbeClient(timeout),
		probeURLs:        probeURLOverrides(),
		stopCh:           make(chan struct{}),
		now:              func() time.Time { return time.Now().UTC() },
	}
	h.probeHTTP = h.defaultProbeHTTP
	h.initBuffers()
	return h, nil
}

// serviceAccountNamespaceFile holds the pod's namespace when running in-cluster.
var serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// resolveNamespace returns the namespace of the Securesign CR: the NAMESPACE
// environment variable, else the pod's own namespace when running in-cluster,
// else the default trusted-artifact-signer.
func resolveNamespace() string {
	if ns := strings.TrimSpace(os.Getenv("NAMESPACE")); ns != "" {
		return ns
	}
	if b, err := os.ReadFile(serviceAccountNamespaceFile); err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns
		}
	}
	return "trusted-artifact-signer"
}

// newProbeClient returns the HTTP client used for probes. Redirects are not
// followed: a probe judges the endpoint's own response, so a redirect (e.g. to
// a login page that returns 200) must not make a service look healthy.
func newProbeClient(timeout time.Duration) *http.Client {
	c := httpclient.New(timeout, timeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// probeURLOverrides reads optional PROBE_URL_<SERVICE> environment variables
// (e.g. PROBE_URL_REKOR). When set, the service is probed at that base URL
// instead of the URL published in the Securesign CR status. This lets a
// deployment probe in-cluster Service URLs rather than the external routes,
// so the check measures the service itself and not the ingress path. The value
// has the same shape as the CR status URL (for TSA it includes
// /api/v1/timestamp).
func probeURLOverrides() map[string]string {
	overrides := map[string]string{}
	for _, spec := range serviceSpecs {
		if spec.urlStatusPath == nil {
			continue
		}
		if v := strings.TrimRight(os.Getenv("PROBE_URL_"+strings.ToUpper(spec.name)), "/"); v != "" {
			overrides[spec.name] = v
		}
	}
	return overrides
}

func (h *healthService) initBuffers() {
	h.buffers = make(map[string]*ringBuffer, len(serviceSpecs))
	for _, spec := range serviceSpecs {
		h.buffers[spec.name] = newRingBuffer(h.historySize, h.failureThreshold, spec.urlStatusPath != nil)
	}
	h.securesignStatus = models.SystemHealthResponseSecuresignStatusUnknown
	h.securesignStatusReason = strptr("no probe round has completed yet")
}

func getKubeConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.ExpandEnv("$HOME/.kube/config")
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func (h *healthService) Start(ctx context.Context) {
	go func() {
		// Collect immediately without blocking server startup; until the first
		// round completes every service reports unknown.
		h.collect(ctx)

		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-h.stopCh:
				return
			case <-ticker.C:
				h.collect(ctx)
			}
		}
	}()
}

func (h *healthService) Stop() {
	h.stopOnce.Do(func() { close(h.stopCh) })
}

// crCondition is a status condition of the Securesign CR.
type crCondition struct {
	status string
	reason string
}

// collect performs one round of probing for every service and appends the
// results to the ring buffers. It reads the Securesign CR once to obtain both
// condition statuses and endpoint URLs.
//
// Services are probed concurrently, so a round takes as long as the slowest
// probe rather than the sum of all of them, and the whole round (including
// securesignStatus) is published atomically: readers never observe a
// half-finished round.
func (h *healthService) collect(ctx context.Context) {
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conditions, urls, readErr := h.readSecuresign(readCtx)
	h.logReadError(readErr)
	now := h.now()

	// When the CR cannot be read (e.g. a transient API server error), keep
	// probing the endpoints discovered in earlier rounds instead of losing the
	// HTTP-probed services to unknown.
	if readErr != nil {
		h.mu.RLock()
		for _, spec := range serviceSpecs {
			if buf := h.buffers[spec.name]; buf != nil && spec.urlStatusPath != nil && buf.endpointURL != "" {
				urls[spec.name] = buf.endpointURL
			}
		}
		h.mu.RUnlock()
	}

	endpoints := make([]string, len(serviceSpecs))
	samples := make([]sample, len(serviceSpecs))
	var wg sync.WaitGroup
	for i, spec := range serviceSpecs {
		if spec.urlStatusPath != nil {
			endpoints[i] = h.probeURLs[spec.name]
			if endpoints[i] == "" {
				endpoints[i] = strings.TrimRight(urls[spec.name], "/")
			}
		}
		if url := endpoints[i]; url != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				samples[i] = h.probeService(ctx, spec, url, now)
			}()
		} else {
			// No endpoint to probe (condition-only component, or the URL is not
			// published yet / the CR is unreadable): fall back to the condition.
			samples[i] = conditionSample(conditions[spec.condition], spec.condition, readErr, now)
		}
	}
	wg.Wait()
	completedAt := h.now()
	status, reason := readyState(conditions[readyCondition], readErr)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.securesignStatus = status
	h.securesignStatusReason = reason
	h.lastRoundAt = &completedAt
	for i, spec := range serviceSpecs {
		buf := h.buffers[spec.name]
		if buf == nil {
			continue
		}
		buf.endpointURL = endpoints[i]
		buf.add(samples[i])
	}
}

// logReadError logs CR read failures when they start or change, and when the
// CR becomes readable again, instead of on every probe round.
func (h *healthService) logReadError(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg == h.lastReadErr {
		return
	}
	if err != nil {
		log.Printf("health: cannot read Securesign CR, reporting unknown: %v", err)
	} else {
		log.Printf("health: Securesign CR is readable again")
	}
	h.lastReadErr = msg
}

// probeService builds a sample from an HTTP probe of spec.probePath under the
// base URL. Only a 2xx response is healthy; redirects are not followed and
// count as failures.
func (h *healthService) probeService(ctx context.Context, spec serviceSpec, url string, now time.Time) sample {
	latency, statusCode, err := h.probeHTTP(ctx, strings.TrimRight(url, "/")+spec.probePath)
	s := sample{
		timestamp:  now,
		source:     models.Http,
		status:     models.ServiceHealthStatusUnhealthy,
		latency:    latency,
		hasLatency: err == nil,
		httpStatus: statusCode,
	}
	switch {
	case err != nil:
		s.err = err.Error()
	case statusCode >= 200 && statusCode < 300:
		s.status = models.ServiceHealthStatusHealthy
	case statusCode >= 300 && statusCode < 400:
		s.err = fmt.Sprintf("unexpected redirect (status code %d)", statusCode)
	default:
		s.err = fmt.Sprintf("unexpected status code %d", statusCode)
	}
	return s
}

// conditionSample builds a sample from a Securesign CR condition observation.
// Only an explicit False is a failure; an unreadable CR or a missing or
// Unknown condition yields an unknown sample whose error says which.
func conditionSample(cond crCondition, condType string, readErr error, now time.Time) sample {
	s := sample{
		timestamp: now,
		source:    models.Condition,
		status:    models.ServiceHealthStatusUnknown,
	}
	switch {
	case readErr != nil:
		s.err = "Securesign CR unavailable: " + publicReadError(readErr)
	case cond.status == "True":
		s.status = models.ServiceHealthStatusHealthy
	case cond.status == "False":
		s.status = models.ServiceHealthStatusUnhealthy
		s.err = "Securesign condition " + describeCondition(condType, cond)
	case cond.status == "":
		s.err = fmt.Sprintf("Securesign condition %s not reported", condType)
	default:
		s.err = "Securesign condition " + describeCondition(condType, cond)
	}
	return s
}

// describeCondition renders a condition as "Type=Status (reason: Reason)".
func describeCondition(condType string, cond crCondition) string {
	if cond.reason == "" {
		return condType + "=" + cond.status
	}
	return fmt.Sprintf("%s=%s (reason: %s)", condType, cond.status, cond.reason)
}

func (h *healthService) defaultProbeHTTP(ctx context.Context, url string) (time.Duration, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	resp, err := h.httpClient.Do(req)
	latency := time.Since(start)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("health: failed to close probe response body for %s: %v", url, err)
		}
	}()
	// Drain (bounded) so the keep-alive connection can be reused by the next
	// probe instead of dialing again.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBodyBytes))
	return latency, resp.StatusCode, nil
}

func (h *healthService) GetSystemHealth(_ context.Context, includeHistory bool) (models.SystemHealthResponse, int, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	services := make([]models.ServiceHealth, 0, len(serviceSpecs))
	for _, spec := range serviceSpecs {
		services = append(services, buildServiceHealth(spec.name, h.buffers[spec.name], includeHistory))
	}

	return models.SystemHealthResponse{
		SecuresignStatus:       h.securesignStatus,
		SecuresignStatusReason: h.securesignStatusReason,
		RekorStatus:            models.SystemHealthResponseRekorStatus(statusOf(services, svcRekor)),
		FulcioStatus:           models.SystemHealthResponseFulcioStatus(statusOf(services, svcFulcio)),
		CtlogStatus:            models.SystemHealthResponseCtlogStatus(statusOf(services, svcCtlog)),
		TrillianStatus:         models.SystemHealthResponseTrillianStatus(statusOf(services, svcTrillian)),
		TsaStatus:              models.SystemHealthResponseTsaStatus(statusOf(services, svcTsa)),
		TufStatus:              models.SystemHealthResponseTufStatus(statusOf(services, svcTuf)),
		Services:               services,
		ProbeIntervalSeconds:   int(h.interval.Seconds()),
		WindowSeconds:          int(h.interval.Seconds()) * h.historySize,
		UpdatedAt:              h.lastRoundAt,
	}, http.StatusOK, nil
}

// buildServiceHealth computes the public per-service metrics from a buffer.
func buildServiceHealth(name string, buf *ringBuffer, includeHistory bool) models.ServiceHealth {
	sh := models.ServiceHealth{
		Name:   models.ServiceHealthName(name),
		Status: models.ServiceHealthStatusUnknown,
	}
	if buf == nil {
		if includeHistory {
			sh.ProbeHistory = &[]models.ProbeSample{}
		}
		return sh
	}

	sh.Probed = buf.probed
	if buf.endpointURL != "" {
		url := buf.endpointURL
		sh.EndpointUrl = &url
	}
	sh.ConsecutiveFailures = buf.consecutiveFail
	sh.LastStateChange = buf.lastStateChange
	sh.ProbeCount = len(buf.samples)

	sh.Status = buf.status

	var history []models.ProbeSample
	if includeHistory {
		history = make([]models.ProbeSample, 0, len(buf.samples))
	}
	var successes, failures int
	var latencies []float64
	for _, s := range buf.samples {
		ps := models.ProbeSample{
			Timestamp: s.timestamp,
			Status:    models.ProbeSampleStatus(s.status),
			Success:   s.success(),
			Source:    s.source,
		}
		if s.hasLatency {
			ms := float32(s.latency.Seconds() * 1000)
			ps.LatencyMs = &ms
			latencies = append(latencies, float64(ms))
		}
		if s.source == models.Http && s.httpStatus != 0 {
			code := s.httpStatus
			ps.HttpStatusCode = &code
		}
		if s.err != "" {
			e := s.err
			ps.Error = &e
		}
		if includeHistory {
			history = append(history, ps)
		}

		switch s.status {
		case models.ServiceHealthStatusHealthy:
			successes++
			ts := s.timestamp
			sh.LastSuccessfulProbe = &ts
		case models.ServiceHealthStatusUnhealthy:
			failures++
		}
	}
	if includeHistory {
		sh.ProbeHistory = &history
	}

	if n := len(buf.samples); n > 0 {
		ts := buf.samples[n-1].timestamp
		sh.LastProbe = &ts
	}
	// Rates only consider samples with a known outcome; unknown observations
	// are neither successes nor failures.
	if known := successes + failures; known > 0 {
		sh.ErrorRate = f32ptr(float64(failures) / float64(known))
		sh.UptimePercentage = f32ptr(float64(successes) / float64(known) * 100)
	}

	if len(latencies) > 0 {
		sh.LatencyP50Ms = f32ptr(percentile(latencies, 50))
		sh.LatencyP95Ms = f32ptr(percentile(latencies, 95))
		sh.MeanLatencyMs = f32ptr(mean(latencies))
	}

	return sh
}

// readyState maps the Securesign CR Ready condition to securesignStatus and
// the reason it is not healthy. Only True/False are trusted; an unreadable CR
// or a missing or Unknown condition is reported as unknown.
func readyState(cond crCondition, readErr error) (models.SystemHealthResponseSecuresignStatus, *string) {
	switch {
	case readErr != nil:
		return models.SystemHealthResponseSecuresignStatusUnknown, strptr("Securesign CR unavailable: " + publicReadError(readErr))
	case cond.status == "True":
		return models.SystemHealthResponseSecuresignStatusHealthy, nil
	case cond.status == "False":
		return models.SystemHealthResponseSecuresignStatusUnhealthy, strptr(describeCondition(readyCondition, cond))
	case cond.status == "":
		return models.SystemHealthResponseSecuresignStatusUnknown, strptr(readyCondition + " condition not reported")
	default:
		return models.SystemHealthResponseSecuresignStatusUnknown, strptr(describeCondition(readyCondition, cond))
	}
}

// readSecuresign reads the Securesign CR and returns its conditions and the
// per-service endpoint URLs. On error it returns empty maps together with the
// error, so callers report unknown rather than failing.
func (h *healthService) readSecuresign(ctx context.Context) (map[string]crCondition, map[string]string, error) {
	conditions := map[string]crCondition{}
	urls := map[string]string{}

	resource, err := h.getSecuresign(ctx)
	if err != nil {
		return conditions, urls, err
	}

	if rawConditions, found, _ := unstructured.NestedSlice(resource.Object, "status", "conditions"); found {
		for _, c := range rawConditions {
			condMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			condType, _ := condMap["type"].(string)
			condStatus, _ := condMap["status"].(string)
			condReason, _ := condMap["reason"].(string)
			if condType != "" {
				conditions[condType] = crCondition{status: condStatus, reason: condReason}
			}
		}
	}

	for _, spec := range serviceSpecs {
		if spec.urlStatusPath == nil {
			continue
		}
		if url, found, _ := unstructured.NestedString(resource.Object, spec.urlStatusPath...); found {
			urls[spec.name] = url
		}
	}

	return conditions, urls, nil
}

// getSecuresign fetches the configured Securesign CR. When no name is
// configured (TAS_DEPLOYMENT_NAME unset), it uses the only Securesign CR in the
// namespace and fails clearly if there is none or more than one.
func (h *healthService) getSecuresign(ctx context.Context) (*unstructured.Unstructured, error) {
	client := h.dynamicClient.Resource(securesignGVR).Namespace(h.namespace)
	if h.crName != "" {
		resource, err := client.Get(ctx, h.crName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get Securesign %s/%s: %w", h.namespace, h.crName, err)
		}
		return resource, nil
	}

	list, err := client.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Securesign CRs in namespace %s: %w", h.namespace, err)
	}
	switch len(list.Items) {
	case 1:
		return &list.Items[0], nil
	case 0:
		return nil, fmt.Errorf("%w in namespace %s", errNoSecuresign, h.namespace)
	default:
		names := make([]string, 0, len(list.Items))
		for _, item := range list.Items {
			names = append(names, item.GetName())
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%w in namespace %s (%s)", errMultipleSecuresign, h.namespace, strings.Join(names, ", "))
	}
}

var (
	errNoSecuresign       = errors.New("no Securesign CR found")
	errMultipleSecuresign = errors.New("multiple Securesign CRs found; set TAS_DEPLOYMENT_NAME to select one")
)

// publicReadError maps a Securesign CR read error to a short message that is
// safe to return to API clients. The raw error can carry the API server URL,
// namespace and CR names, so it is only written to the log (logReadError).
func publicReadError(err error) string {
	switch {
	case errors.Is(err, errNoSecuresign):
		return "no Securesign CR in the namespace"
	case errors.Is(err, errMultipleSecuresign):
		return "several Securesign CRs in the namespace; set TAS_DEPLOYMENT_NAME to select one"
	case apierrors.IsNotFound(err):
		return "not found; check TAS_DEPLOYMENT_NAME and NAMESPACE"
	case apierrors.IsForbidden(err):
		return "permission denied; the console needs get and list access to securesigns.rhtas.redhat.com"
	case apierrors.IsUnauthorized(err):
		return "not authorized by the Kubernetes API"
	case errors.Is(err, context.DeadlineExceeded) || apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err):
		return "request timed out"
	case apierrors.IsTooManyRequests(err):
		return "Kubernetes API is throttling requests"
	default:
		return "Kubernetes API request failed; see the console logs for details"
	}
}

// --- numeric helpers ---

// statusOf returns the status of the named service, or unknown if absent.
func statusOf(services []models.ServiceHealth, name string) models.ServiceHealthStatus {
	for _, s := range services {
		if string(s.Name) == name {
			return s.Status
		}
	}
	return models.ServiceHealthStatusUnknown
}

func strptr(s string) *string { return &s }

func f32ptr(v float64) *float32 {
	f := float32(v)
	return &f
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// percentile returns the p-th percentile (0..100) of values using the
// nearest-rank method. values is copied before sorting.
func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}
