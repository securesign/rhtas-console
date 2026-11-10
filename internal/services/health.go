package services

import (
	"context"
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
	// securesignStatus is the latest observation of the CR Ready condition.
	securesignStatus models.SystemHealthResponseSecuresignStatus
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

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "trusted-artifact-signer"
	}

	crName := os.Getenv("TAS_DEPLOYMENT_NAME")
	if crName == "" {
		crName = "securesign-sample"
	}

	timeout := time.Duration(envInt("PROBE_TIMEOUT_SECONDS", defaultProbeTimeoutSeconds)) * time.Second

	h := &healthService{
		dynamicClient:    dynamicClient,
		namespace:        namespace,
		crName:           crName,
		interval:         time.Duration(envInt("PROBE_INTERVAL_SECONDS", defaultProbeIntervalSeconds)) * time.Second,
		timeout:          timeout,
		historySize:      envInt("PROBE_HISTORY_SIZE", defaultProbeHistorySize),
		failureThreshold: envInt("PROBE_FAILURE_THRESHOLD", defaultFailureThreshold),
		httpClient:       httpclient.New(timeout, timeout),
		probeURLs:        probeURLOverrides(),
		stopCh:           make(chan struct{}),
		now:              func() time.Time { return time.Now().UTC() },
	}
	h.probeHTTP = h.defaultProbeHTTP
	h.initBuffers()
	return h, nil
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

	conditions, urls, err := h.readSecuresign(readCtx)
	if err != nil {
		log.Printf("health: failed to read Securesign CR %s/%s, reporting unknown: %v", h.namespace, h.crName, err)
	}
	now := h.now()

	endpoints := make([]string, len(serviceSpecs))
	samples := make([]sample, len(serviceSpecs))
	var wg sync.WaitGroup
	for i, spec := range serviceSpecs {
		if spec.urlStatusPath != nil {
			endpoints[i] = h.probeURLs[spec.name]
			if endpoints[i] == "" {
				endpoints[i] = urls[spec.name]
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
			samples[i] = conditionSample(conditions[spec.condition], spec.condition, now)
		}
	}
	wg.Wait()
	completedAt := h.now()

	h.mu.Lock()
	defer h.mu.Unlock()
	h.securesignStatus = readyStatus(conditions[readyCondition])
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

// probeService builds a sample from an HTTP probe against url.
func (h *healthService) probeService(ctx context.Context, spec serviceSpec, url string, now time.Time) sample {
	latency, statusCode, err := h.probeHTTP(ctx, url+spec.probePath)
	s := sample{
		timestamp:  now,
		source:     models.Http,
		status:     models.ServiceHealthStatusUnhealthy,
		latency:    latency,
		hasLatency: err == nil,
		httpStatus: statusCode,
	}
	if err != nil {
		s.err = err.Error()
		return s
	}
	if statusCode >= 200 && statusCode < 400 {
		s.status = models.ServiceHealthStatusHealthy
	} else {
		s.err = fmt.Sprintf("unexpected status code %d", statusCode)
	}
	return s
}

// conditionSample builds a sample from a Securesign CR condition observation.
// Only an explicit False is a failure; a missing or Unknown condition (including
// an unreadable CR) yields an unknown sample.
func conditionSample(condStatus, condType string, now time.Time) sample {
	s := sample{
		timestamp: now,
		source:    models.Condition,
	}
	switch condStatus {
	case "True":
		s.status = models.ServiceHealthStatusHealthy
	case "False":
		s.status = models.ServiceHealthStatusUnhealthy
		s.err = fmt.Sprintf("Securesign condition %s=False", condType)
	case "":
		s.status = models.ServiceHealthStatusUnknown
		s.err = fmt.Sprintf("Securesign condition %s not reported", condType)
	default:
		s.status = models.ServiceHealthStatusUnknown
		s.err = fmt.Sprintf("Securesign condition %s=%s", condType, condStatus)
	}
	return s
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
		SecuresignStatus:     h.securesignStatus,
		Services:             services,
		ProbeIntervalSeconds: int(h.interval.Seconds()),
		WindowSeconds:        int(h.interval.Seconds()) * h.historySize,
		UpdatedAt:            h.lastRoundAt,
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

// readyStatus maps the Securesign CR Ready condition to securesignStatus.
// Only True/False are trusted; a missing or Unknown condition (including an
// unreadable CR) is reported as unknown.
func readyStatus(condStatus string) models.SystemHealthResponseSecuresignStatus {
	switch condStatus {
	case "True":
		return models.SystemHealthResponseSecuresignStatusHealthy
	case "False":
		return models.SystemHealthResponseSecuresignStatusUnhealthy
	default:
		return models.SystemHealthResponseSecuresignStatusUnknown
	}
}

// readSecuresign reads the Securesign CR and returns both the condition map and
// the per-service endpoint URLs. On error it returns empty maps together with
// the error, so callers report unknown rather than failing.
func (h *healthService) readSecuresign(ctx context.Context) (conditions map[string]string, urls map[string]string, err error) {
	conditions = map[string]string{}
	urls = map[string]string{}

	resource, err := h.dynamicClient.Resource(securesignGVR).Namespace(h.namespace).Get(ctx, h.crName, metav1.GetOptions{})
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
			if condType != "" {
				conditions[condType] = condStatus
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

// --- numeric helpers ---

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
