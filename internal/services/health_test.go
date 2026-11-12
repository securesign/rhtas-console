package services

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securesign/rhtas-console/internal/httpclient"
	"github.com/securesign/rhtas-console/internal/models"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

const testNamespace = "test-ns"

// fixedNow returns a deterministic clock advancing by one second per call.
// It is safe for concurrent use (Start collects in a background goroutine).
func fixedNow() func() time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	n := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

func newTestHealthService(dynamicObjs ...runtime.Object) *healthService {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		securesignGVR: "SecuresignList",
	}
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, dynamicObjs...)
	h := &healthService{
		dynamicClient:    dynamicClient,
		namespace:        testNamespace,
		crName:           "securesign-sample",
		interval:         30 * time.Second,
		timeout:          5 * time.Second,
		historySize:      5,
		failureThreshold: defaultFailureThreshold,
		stopCh:           make(chan struct{}),
		now:              fixedNow(),
	}
	// Default probe: always healthy with a fixed latency. Tests override as needed.
	h.probeHTTP = func(context.Context, string) (time.Duration, int, error) {
		return 10 * time.Millisecond, http.StatusOK, nil
	}
	h.initBuffers()
	return h
}

func makeSecuresignCR(name, namespace string, conditions []interface{}, urls map[string]string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "rhtas.redhat.com",
		Version: "v1",
		Kind:    "Securesign",
	})
	obj.SetName(name)
	obj.SetNamespace(namespace)
	status := map[string]interface{}{}
	if conditions != nil {
		status["conditions"] = conditions
	}
	for svc, url := range urls {
		status[svc] = map[string]interface{}{"url": url}
	}
	if len(status) > 0 {
		obj.Object["status"] = status
	}
	return obj
}

func cond(condType, status string) map[string]interface{} {
	return map[string]interface{}{"type": condType, "status": status}
}

func allHealthyConditions() []interface{} {
	return []interface{}{
		cond("Ready", "True"),
		cond("RekorAvailable", "True"),
		cond("FulcioAvailable", "True"),
		cond("CTlogAvailable", "True"),
		cond("TrillianAvailable", "True"),
		cond("TsaAvailable", "True"),
		cond("TufAvailable", "True"),
	}
}

func allURLs() map[string]string {
	return map[string]string{
		"rekor":  "https://rekor.example.com",
		"fulcio": "https://fulcio.example.com",
		"tsa":    "https://tsa.example.com",
		"tuf":    "https://tuf.example.com",
	}
}

// assertRate checks a nullable rate is present and approximately want.
func assertRate(t *testing.T, name string, got *float32, want float64) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %v", name, want)
		return
	}
	if math.Abs(float64(*got)-want) > 1e-4 {
		t.Errorf("%s = %v, want %v", name, *got, want)
	}
}

// history returns a service's probe samples, failing if they were omitted.
func history(t *testing.T, s models.ServiceHealth) []models.ProbeSample {
	t.Helper()
	if s.ProbeHistory == nil {
		t.Fatalf("%s: probeHistory missing", s.Name)
	}
	return *s.ProbeHistory
}

func findService(resp models.SystemHealthResponse, name string) (models.ServiceHealth, bool) {
	for _, s := range resp.Services {
		if string(s.Name) == name {
			return s, true
		}
	}
	return models.ServiceHealth{}, false
}

func TestReadSecuresign(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)

	conditions, urls, err := h.readSecuresign(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conditions["Ready"].status != "True" {
		t.Errorf("Ready = %+v, want True", conditions["Ready"])
	}
	if len(conditions) != 7 {
		t.Errorf("expected 7 conditions, got %d", len(conditions))
	}
	if urls["rekor"] != "https://rekor.example.com" {
		t.Errorf("rekor url = %q", urls["rekor"])
	}
	if _, ok := urls["ctlog"]; ok {
		t.Error("ctlog should have no URL")
	}
}

func TestReadSecuresignMissingCR(t *testing.T) {
	h := newTestHealthService() // no CR
	conditions, urls, err := h.readSecuresign(context.Background())
	if err == nil {
		t.Error("expected an error for a missing CR")
	}
	if len(conditions) != 0 || len(urls) != 0 {
		t.Errorf("expected empty maps for missing CR, got conditions=%v urls=%v", conditions, urls)
	}
}

// An unreadable CR (missing, RBAC, wrong name) must surface as unknown, not as
// every service being down.
func TestCollectMissingCRReportsUnknown(t *testing.T) {
	h := newTestHealthService() // no CR
	probed := false
	h.probeHTTP = func(context.Context, string) (time.Duration, int, error) {
		probed = true
		return 0, 0, errors.New("should not be called")
	}

	h.collect(context.Background())
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusUnknown {
		t.Errorf("securesignStatus = %q, want unknown", resp.SecuresignStatus)
	}
	// The read failure is visible in the API, not only in the pod logs.
	if r := resp.SecuresignStatusReason; r == nil || *r != "Securesign CR unavailable: not found; check TAS_DEPLOYMENT_NAME and NAMESPACE" {
		t.Errorf("securesignStatusReason = %v, want the sanitized not-found reason", r)
	}
	for _, s := range resp.Services {
		if s.Status != models.ServiceHealthStatusUnknown {
			t.Errorf("%s status = %q, want unknown", s.Name, s.Status)
		}
		if h := history(t, s); len(h) == 0 || h[len(h)-1].Error == nil || !strings.HasPrefix(*h[len(h)-1].Error, "Securesign CR unavailable: ") {
			t.Errorf("%s: sample error must name the CR read failure, got %+v", s.Name, h)
		}
		if s.ConsecutiveFailures != 0 || s.ErrorRate != nil || s.UptimePercentage != nil {
			t.Errorf("%s: unknown samples must not count (consecutive=%d errorRate=%v uptime=%v)",
				s.Name, s.ConsecutiveFailures, s.ErrorRate, s.UptimePercentage)
		}
	}
	if probed {
		t.Error("services without a URL must not be HTTP-probed")
	}
}

// A condition reported as Unknown (e.g. while the operator is initializing) is
// unknown, not unhealthy.
func TestConditionUnknownIsUnknown(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, []interface{}{
		cond("Ready", "True"),
		cond("RekorAvailable", "True"),
		cond("FulcioAvailable", "True"),
		cond("CTlogAvailable", "Unknown"),
		cond("TrillianAvailable", "True"),
		cond("TsaAvailable", "True"),
		cond("TufAvailable", "True"),
	}, allURLs())
	h := newTestHealthService(cr)
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	ctlog, _ := findService(resp, "ctlog")
	if ctlog.Status != models.ServiceHealthStatusUnknown {
		t.Errorf("ctlog status = %q, want unknown", ctlog.Status)
	}
	// securesignStatus mirrors the Ready condition; it is not recomputed from services.
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusHealthy {
		t.Errorf("securesignStatus = %q, want healthy (Ready=True)", resp.SecuresignStatus)
	}
}

// A probed service whose URL is not published yet falls back to its condition.
func TestProbedServiceWithoutURLUsesCondition(t *testing.T) {
	urls := allURLs()
	delete(urls, "rekor")
	conds := allHealthyConditions()
	conds[1] = cond("RekorAvailable", "False")
	cr := makeSecuresignCR("securesign-sample", testNamespace, conds, urls)
	h := newTestHealthService(cr)
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	rekor, _ := findService(resp, "rekor")
	if rekor.Status != models.ServiceHealthStatusUnhealthy {
		t.Errorf("rekor status = %q, want unhealthy (condition False)", rekor.Status)
	}
	if rekor.EndpointUrl != nil {
		t.Errorf("rekor endpoint should be nil, got %v", *rekor.EndpointUrl)
	}
	if h := history(t, rekor); len(h) != 1 || h[0].Source != models.Condition {
		t.Errorf("rekor sample should come from the condition: %+v", h)
	}
}

// A single transient HTTP failure must not flip a service to unhealthy.
func TestSingleHTTPFailureIsDebounced(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)

	fail := false
	h.probeHTTP = func(_ context.Context, url string) (time.Duration, int, error) {
		if fail && url == "https://rekor.example.com/api/v1/log" {
			return 0, 0, errors.New("context deadline exceeded")
		}
		return 10 * time.Millisecond, http.StatusOK, nil
	}

	h.collect(context.Background()) // healthy
	fail = true
	h.collect(context.Background()) // 1st failure: still healthy

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	rekor, _ := findService(resp, "rekor")
	if rekor.Status != models.ServiceHealthStatusHealthy {
		t.Errorf("after one failure rekor = %q, want healthy", rekor.Status)
	}
	if rekor.ConsecutiveFailures != 1 {
		t.Errorf("consecutiveFailures = %d, want 1", rekor.ConsecutiveFailures)
	}

	h.collect(context.Background()) // 2nd failure: threshold reached
	resp, _, _ = h.GetSystemHealth(context.Background(), true)
	rekor, _ = findService(resp, "rekor")
	if rekor.Status != models.ServiceHealthStatusUnhealthy {
		t.Errorf("after two failures rekor = %q, want unhealthy", rekor.Status)
	}
}

// A failing first probe (cold start) reports unknown rather than unhealthy.
func TestFirstHTTPFailureIsUnknown(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.probeHTTP = func(context.Context, string) (time.Duration, int, error) {
		return 0, 0, errors.New("timeout")
	}
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	tuf, _ := findService(resp, "tuf")
	if tuf.Status != models.ServiceHealthStatusUnknown {
		t.Errorf("tuf status = %q, want unknown after a single failed first probe", tuf.Status)
	}
}

func TestCollectAndGetSystemHealthAllHealthy(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)

	h.collect(context.Background())

	resp, code, err := h.GetSystemHealth(context.Background(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("code = %d, want 200", code)
	}
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusHealthy {
		t.Errorf("securesignStatus = %q, want healthy", resp.SecuresignStatus)
	}
	if len(resp.Services) != 6 {
		t.Fatalf("expected 6 services, got %d", len(resp.Services))
	}
	if _, ok := findService(resp, "securesign"); ok {
		t.Error("securesign must not be listed as a service")
	}
	if resp.ProbeIntervalSeconds != 30 {
		t.Errorf("interval = %d, want 30", resp.ProbeIntervalSeconds)
	}
	if resp.WindowSeconds != 30*5 {
		t.Errorf("window = %d, want 150", resp.WindowSeconds)
	}

	// HTTP-probed service carries latency + endpoint; condition-only does not.
	rekor, _ := findService(resp, "rekor")
	if !rekor.Probed {
		t.Error("rekor should be probed")
	}
	if rekor.EndpointUrl == nil || *rekor.EndpointUrl != "https://rekor.example.com" {
		t.Errorf("rekor endpoint = %v", rekor.EndpointUrl)
	}
	if rekor.LatencyP95Ms == nil {
		t.Error("rekor should have p95 latency")
	}
	if rekor.Status != models.ServiceHealthStatusHealthy {
		t.Errorf("rekor status = %q", rekor.Status)
	}

	ctlog, _ := findService(resp, "ctlog")
	if ctlog.Probed {
		t.Error("ctlog should not be probed")
	}
	if ctlog.EndpointUrl != nil {
		t.Errorf("ctlog endpoint should be nil, got %v", *ctlog.EndpointUrl)
	}
	if ctlog.LatencyP95Ms != nil {
		t.Error("ctlog should not have latency")
	}
	if ctlog.Status != models.ServiceHealthStatusHealthy {
		t.Errorf("ctlog status = %q", ctlog.Status)
	}
	if h := history(t, ctlog); len(h) != 1 || h[0].Source != models.Condition {
		t.Errorf("ctlog history unexpected: %+v", h)
	}
}

func TestCollectFailureMetrics(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, []interface{}{
		cond("Ready", "False"),
		cond("RekorAvailable", "True"),
		cond("CTlogAvailable", "False"),
	}, allURLs())
	h := newTestHealthService(cr)

	// Fulcio probe fails (connection error); others succeed.
	h.probeHTTP = func(_ context.Context, url string) (time.Duration, int, error) {
		if url == "https://fulcio.example.com/api/v2/trustBundle" {
			return 0, 0, errors.New("connection refused")
		}
		return 20 * time.Millisecond, http.StatusOK, nil
	}

	// Two rounds so error rate / consecutive failures accumulate.
	h.collect(context.Background())
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusUnhealthy {
		t.Errorf("securesignStatus = %q, want unhealthy (Ready=False)", resp.SecuresignStatus)
	}

	fulcio, _ := findService(resp, "fulcio")
	if fulcio.Status != models.ServiceHealthStatusUnhealthy {
		t.Errorf("fulcio status = %q, want unhealthy", fulcio.Status)
	}
	if fulcio.ConsecutiveFailures != 2 {
		t.Errorf("fulcio consecutiveFailures = %d, want 2", fulcio.ConsecutiveFailures)
	}
	assertRate(t, "fulcio errorRate", fulcio.ErrorRate, 1)
	assertRate(t, "fulcio uptime", fulcio.UptimePercentage, 0)
	if fulcio.LastSuccessfulProbe != nil {
		t.Error("fulcio should have no successful probe")
	}
	// A connection error yields no latency sample.
	if fulcio.LatencyP95Ms != nil {
		t.Error("fulcio should have no latency (connection errors)")
	}

	ctlog, _ := findService(resp, "ctlog")
	if ctlog.Status != models.ServiceHealthStatusUnhealthy {
		t.Errorf("ctlog status = %q, want unhealthy", ctlog.Status)
	}
}

func TestProbeBadStatusCodeIsFailureWithLatency(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.probeHTTP = func(context.Context, string) (time.Duration, int, error) {
		return 15 * time.Millisecond, http.StatusInternalServerError, nil
	}

	h.collect(context.Background())
	h.collect(context.Background())
	resp, _, _ := h.GetSystemHealth(context.Background(), true)

	rekor, _ := findService(resp, "rekor")
	if rekor.Status != models.ServiceHealthStatusUnhealthy {
		t.Errorf("rekor status = %q, want unhealthy", rekor.Status)
	}
	// A 5xx still produced a response, so latency IS recorded.
	if rekor.LatencyP95Ms == nil {
		t.Error("rekor should record latency even on 5xx")
	}
	if h := history(t, rekor); len(h) == 0 || h[0].HttpStatusCode == nil {
		t.Error("rekor sample should carry http status code")
	}
}

func TestRingBufferCapAndStateChange(t *testing.T) {
	buf := newRingBuffer(3, 1, true)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		buf.add(sample{timestamp: base.Add(time.Duration(i) * time.Second), status: models.ServiceHealthStatusHealthy, source: models.Http})
	}
	if len(buf.samples) != 3 {
		t.Errorf("buffer len = %d, want 3 (capped)", len(buf.samples))
	}
	// First retained sample should be the 3rd added (index 2).
	if !buf.samples[0].timestamp.Equal(base.Add(2 * time.Second)) {
		t.Errorf("oldest retained = %v", buf.samples[0].timestamp)
	}

	// Flip to failure: state change recorded, consecutive failures count.
	buf.add(sample{timestamp: base.Add(5 * time.Second), status: models.ServiceHealthStatusUnhealthy, source: models.Http})
	if buf.consecutiveFail != 1 {
		t.Errorf("consecutiveFail = %d, want 1", buf.consecutiveFail)
	}
	if buf.lastStateChange == nil || !buf.lastStateChange.Equal(base.Add(5*time.Second)) {
		t.Errorf("lastStateChange = %v", buf.lastStateChange)
	}
}

// Unknown observations are neither successes nor failures: they reset the
// consecutive-failure count and are excluded from errorRate/uptime.
func TestUnknownSamplesExcludedFromRates(t *testing.T) {
	buf := newRingBuffer(10, 2, true)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	add := func(i int, st models.ServiceHealthStatus) {
		buf.add(sample{timestamp: base.Add(time.Duration(i) * time.Second), status: st, source: models.Http})
	}
	add(0, models.ServiceHealthStatusHealthy)
	add(1, models.ServiceHealthStatusUnhealthy)
	add(2, models.ServiceHealthStatusUnknown)
	add(3, models.ServiceHealthStatusUnknown)
	add(4, models.ServiceHealthStatusUnhealthy)

	if buf.consecutiveFail != 1 {
		t.Errorf("consecutiveFail = %d, want 1 (reset by unknown)", buf.consecutiveFail)
	}
	// Debounce restarts after unknown: one failure keeps the unknown status.
	if buf.status != models.ServiceHealthStatusUnknown {
		t.Errorf("status = %q, want unknown", buf.status)
	}

	sh := buildServiceHealth("rekor", buf, true)
	// 1 success + 2 failures known; the 2 unknown samples are ignored.
	assertRate(t, "errorRate", sh.ErrorRate, 2.0/3)
	assertRate(t, "uptime", sh.UptimePercentage, 100.0/3)
	if sh.ProbeCount != 5 {
		t.Errorf("probeCount = %d, want 5", sh.ProbeCount)
	}
}

func TestPercentile(t *testing.T) {
	vals := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	if got := percentile(vals, 50); got != 50 {
		t.Errorf("p50 = %v, want 50", got)
	}
	if got := percentile(vals, 95); got != 100 {
		t.Errorf("p95 = %v, want 100", got)
	}
	if got := percentile([]float64{42}, 95); got != 42 {
		t.Errorf("single-value p95 = %v, want 42", got)
	}
	if got := percentile(nil, 95); got != 0 {
		t.Errorf("empty p95 = %v, want 0", got)
	}
}

func TestReadyState(t *testing.T) {
	tests := []struct {
		name       string
		cond       crCondition
		readErr    error
		want       models.SystemHealthResponseSecuresignStatus
		wantReason string // "" means nil
	}{
		{"true", crCondition{status: "True"}, nil, models.SystemHealthResponseSecuresignStatusHealthy, ""},
		{"false with reason", crCondition{status: "False", reason: "Creating"}, nil,
			models.SystemHealthResponseSecuresignStatusUnhealthy, "Ready=False (reason: Creating)"},
		{"false without reason", crCondition{status: "False"}, nil,
			models.SystemHealthResponseSecuresignStatusUnhealthy, "Ready=False"},
		{"unknown", crCondition{status: "Unknown", reason: "Pending"}, nil,
			models.SystemHealthResponseSecuresignStatusUnknown, "Ready=Unknown (reason: Pending)"},
		{"missing", crCondition{}, nil, models.SystemHealthResponseSecuresignStatusUnknown, "Ready condition not reported"},
		{"read error", crCondition{status: "True"},
			apierrors.NewForbidden(securesignGVR.GroupResource(), "securesign-sample", errors.New("RBAC: access denied")),
			models.SystemHealthResponseSecuresignStatusUnknown,
			"Securesign CR unavailable: permission denied; the console needs get and list access to securesigns.rhtas.redhat.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := readyState(tt.cond, tt.readErr)
			if got != tt.want {
				t.Errorf("status = %q, want %q", got, tt.want)
			}
			switch {
			case tt.wantReason == "" && reason != nil:
				t.Errorf("reason = %q, want nil", *reason)
			case tt.wantReason != "" && (reason == nil || *reason != tt.wantReason):
				t.Errorf("reason = %v, want %q", reason, tt.wantReason)
			}
		})
	}
}

// securesignStatus follows the operator's Ready condition even when an HTTP
// probe disagrees: it is never recomputed from services.
func TestSecuresignStatusFollowsReadyCondition(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.probeHTTP = func(context.Context, string) (time.Duration, int, error) {
		return 0, 0, errors.New("connection refused")
	}
	h.collect(context.Background())
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusHealthy {
		t.Errorf("securesignStatus = %q, want healthy (Ready=True)", resp.SecuresignStatus)
	}
	rekor, _ := findService(resp, "rekor")
	if rekor.Status != models.ServiceHealthStatusUnhealthy {
		t.Errorf("rekor status = %q, want unhealthy", rekor.Status)
	}
}

func TestGetSystemHealthBeforeAnyProbe(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)

	// No collect() called yet: buffers empty -> everything unknown, no panic.
	resp, code, err := h.GetSystemHealth(context.Background(), true)
	if err != nil || code != http.StatusOK {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusUnknown {
		t.Errorf("securesignStatus = %q, want unknown", resp.SecuresignStatus)
	}
	for _, s := range resp.Services {
		if s.Status != models.ServiceHealthStatusUnknown {
			t.Errorf("%s status = %q, want unknown", s.Name, s.Status)
		}
		if s.ProbeHistory == nil || *s.ProbeHistory == nil {
			t.Errorf("%s ProbeHistory should be a non-nil empty list", s.Name)
		}
	}
}

func TestStartStop(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.Start(ctx) // non-blocking: first collection runs in the background

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, _, _ := h.GetSystemHealth(context.Background(), true)
		if resp.SecuresignStatus == models.SystemHealthResponseSecuresignStatusHealthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after Start, securesignStatus = %q, want healthy", resp.SecuresignStatus)
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.Stop()
	h.Stop() // idempotent, must not panic
}

// The real probe client drains response bodies so keep-alive connections are
// reused: repeated probes must not open a new connection each time (each new
// dial is another chance to hit a dead load-balancer address).
func TestDefaultProbeHTTPReusesConnections(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 64*1024)))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	h := &healthService{httpClient: httpclient.New(5*time.Second, 5*time.Second)}
	for i := 0; i < 5; i++ {
		latency, code, err := h.defaultProbeHTTP(context.Background(), srv.URL)
		if err != nil || code != http.StatusOK {
			t.Fatalf("probe %d: code=%d err=%v", i, code, err)
		}
		if latency <= 0 {
			t.Errorf("probe %d: latency = %v, want > 0", i, latency)
		}
	}
	if n := newConns.Load(); n != 1 {
		t.Errorf("new connections = %d, want 1 (keep-alive reuse)", n)
	}
}

func TestDefaultProbeHTTPTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	h := &healthService{httpClient: httpclient.New(100*time.Millisecond, 100*time.Millisecond)}
	if _, _, err := h.defaultProbeHTTP(context.Background(), srv.URL); err == nil {
		t.Fatal("expected a timeout error")
	}
}

// Probes run concurrently and a round is published atomically: while a round
// is in flight readers still see the previous complete state, and the round
// takes roughly as long as the slowest probe, not the sum.
func TestCollectIsConcurrentAndAtomic(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)

	const probeDelay = 200 * time.Millisecond
	release := make(chan struct{})
	var started atomic.Int32
	h.probeHTTP = func(context.Context, string) (time.Duration, int, error) {
		started.Add(1)
		<-release
		time.Sleep(probeDelay)
		return probeDelay, http.StatusOK, nil
	}

	done := make(chan time.Duration)
	go func() {
		start := time.Now()
		h.collect(context.Background())
		done <- time.Since(start)
	}()

	// All 4 HTTP probes must be in flight at the same time.
	deadline := time.Now().Add(2 * time.Second)
	for started.Load() < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d probes started concurrently, want 4", started.Load())
		}
		time.Sleep(time.Millisecond)
	}

	// Mid-round, nothing from this round is visible yet (not even the
	// condition-only services or securesignStatus).
	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusUnknown {
		t.Errorf("mid-round securesignStatus = %q, want unknown", resp.SecuresignStatus)
	}
	for _, s := range resp.Services {
		if s.ProbeCount != 0 {
			t.Errorf("mid-round %s probeCount = %d, want 0", s.Name, s.ProbeCount)
		}
	}

	close(release)
	if elapsed := <-done; elapsed > 3*probeDelay {
		t.Errorf("round took %v, want about %v (probes not concurrent)", elapsed, probeDelay)
	}

	resp, _, _ = h.GetSystemHealth(context.Background(), true)
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusHealthy {
		t.Errorf("securesignStatus = %q, want healthy", resp.SecuresignStatus)
	}
	for _, s := range resp.Services {
		if s.ProbeCount != 1 || s.Status != models.ServiceHealthStatusHealthy {
			t.Errorf("%s probeCount=%d status=%q, want 1/healthy", s.Name, s.ProbeCount, s.Status)
		}
	}
}

// Before any sample, rates are null rather than a misleading 0% uptime.
func TestRatesNullWithoutSamples(t *testing.T) {
	sh := buildServiceHealth("rekor", newRingBuffer(5, 2, true), false)
	if sh.ErrorRate != nil || sh.UptimePercentage != nil {
		t.Errorf("errorRate=%v uptime=%v, want nil/nil", sh.ErrorRate, sh.UptimePercentage)
	}
}

// The summary omits probe samples unless requested.
func TestHistoryOnlyWhenRequested(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	for _, s := range resp.Services {
		if s.ProbeHistory != nil {
			t.Errorf("%s: probeHistory must be omitted by default", s.Name)
		}
		if s.ProbeCount != 1 || s.Status != models.ServiceHealthStatusHealthy {
			t.Errorf("%s: summary fields must still be populated (count=%d status=%q)", s.Name, s.ProbeCount, s.Status)
		}
	}

	resp, _, _ = h.GetSystemHealth(context.Background(), true)
	rekor, _ := findService(resp, "rekor")
	if got := history(t, rekor); len(got) != 1 || got[0].Status != models.ProbeSampleStatusHealthy {
		t.Errorf("rekor history = %+v, want one healthy sample", got)
	}
}

// updatedAt reports when the last round completed, not the request time, and
// is null before the first round.
func TestUpdatedAtIsRoundCompletion(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	if resp.UpdatedAt != nil {
		t.Errorf("updatedAt before first round = %v, want nil", *resp.UpdatedAt)
	}

	h.collect(context.Background())
	first, _, _ := h.GetSystemHealth(context.Background(), false)
	if first.UpdatedAt == nil {
		t.Fatal("updatedAt must be set after a round")
	}
	// Further requests (no new round) must not move updatedAt.
	again, _, _ := h.GetSystemHealth(context.Background(), false)
	if !again.UpdatedAt.Equal(*first.UpdatedAt) {
		t.Errorf("updatedAt moved without a new round: %v -> %v", *first.UpdatedAt, *again.UpdatedAt)
	}

	h.collect(context.Background())
	next, _, _ := h.GetSystemHealth(context.Background(), false)
	if !next.UpdatedAt.After(*first.UpdatedAt) {
		t.Errorf("updatedAt did not advance after a new round: %v -> %v", *first.UpdatedAt, *next.UpdatedAt)
	}
}

// Unknown observations are distinguishable from failures in the history.
func TestProbeSampleStatusDistinguishesUnknown(t *testing.T) {
	h := newTestHealthService() // no CR: every sample is unknown
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	for _, s := range resp.Services {
		for _, ps := range history(t, s) {
			if ps.Status != models.ProbeSampleStatusUnknown || ps.Success {
				t.Errorf("%s sample status=%q success=%v, want unknown/false", s.Name, ps.Status, ps.Success)
			}
		}
	}
}

// PROBE_URL_<SERVICE> overrides the CR status URL (e.g. an in-cluster Service).
func TestProbeURLOverride(t *testing.T) {
	t.Setenv("PROBE_URL_REKOR", "http://rekor-server.tas.svc/")
	t.Setenv("PROBE_URL_CTLOG", "http://ignored") // condition-only service: not probed

	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.probeURLs = probeURLOverrides()

	var mu sync.Mutex
	var probed []string
	h.probeHTTP = func(_ context.Context, url string) (time.Duration, int, error) {
		mu.Lock()
		probed = append(probed, url)
		mu.Unlock()
		return time.Millisecond, http.StatusOK, nil
	}
	h.collect(context.Background())

	mu.Lock()
	defer mu.Unlock()
	want := map[string]bool{
		"http://rekor-server.tas.svc/api/v1/log":        true, // override, trailing slash trimmed
		"https://fulcio.example.com/api/v2/trustBundle": true, // CR status URL
		"https://tsa.example.com/certchain":             true,
		"https://tuf.example.com/root.json":             true,
	}
	if len(probed) != len(want) {
		t.Fatalf("probed %v, want %d URLs", probed, len(want))
	}
	for _, u := range probed {
		if !want[u] {
			t.Errorf("unexpected probe URL %q", u)
		}
	}

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	rekor, _ := findService(resp, "rekor")
	if rekor.EndpointUrl == nil || *rekor.EndpointUrl != "http://rekor-server.tas.svc" {
		t.Errorf("rekor endpointUrl = %v, want the override", rekor.EndpointUrl)
	}
	ctlog, _ := findService(resp, "ctlog")
	if ctlog.EndpointUrl != nil || ctlog.Probed {
		t.Error("condition-only services must ignore PROBE_URL_* overrides")
	}
}

// With an override set, a probed service keeps being probed even when the CR
// cannot be read (the override does not depend on the CR).
func TestProbeURLOverrideWithoutCR(t *testing.T) {
	h := newTestHealthService() // no CR
	h.probeURLs = map[string]string{"tuf": "http://tuf.tas.svc"}
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	tuf, _ := findService(resp, "tuf")
	if tuf.Status != models.ServiceHealthStatusHealthy {
		t.Errorf("tuf status = %q, want healthy (probed via override)", tuf.Status)
	}
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusUnknown {
		t.Errorf("securesignStatus = %q, want unknown (CR unreadable)", resp.SecuresignStatus)
	}
}

// Redirects are not followed and are not healthy (e.g. a route redirecting to
// a login page must not make a service look up).
func TestProbeRedirectIsUnhealthy(t *testing.T) {
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer login.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, login.URL, http.StatusFound)
	}))
	defer redirecting.Close()

	h := &healthService{httpClient: newProbeClient(5 * time.Second)}
	h.probeHTTP = h.defaultProbeHTTP
	s := h.probeService(context.Background(), serviceSpecs[0], redirecting.URL, time.Now())
	if s.status != models.ServiceHealthStatusUnhealthy || s.httpStatus != http.StatusFound {
		t.Errorf("status=%q httpStatus=%d, want unhealthy/302 (redirect not followed)", s.status, s.httpStatus)
	}
	if !strings.Contains(s.err, "redirect") {
		t.Errorf("err = %q, want it to mention the redirect", s.err)
	}
}

// A CR-published base URL with a trailing slash must not produce "//" paths.
func TestProbeJoinsTrailingSlash(t *testing.T) {
	urls := allURLs()
	urls["rekor"] = "https://rekor.example.com/"
	urls["tsa"] = "https://tsa.example.com/api/v1/timestamp/"
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), urls)
	h := newTestHealthService(cr)

	var mu sync.Mutex
	var probed []string
	h.probeHTTP = func(_ context.Context, url string) (time.Duration, int, error) {
		mu.Lock()
		probed = append(probed, url)
		mu.Unlock()
		return time.Millisecond, http.StatusOK, nil
	}
	h.collect(context.Background())

	mu.Lock()
	defer mu.Unlock()
	for _, u := range probed {
		if strings.Contains(strings.TrimPrefix(u, "https://"), "//") {
			t.Errorf("probe URL %q contains a double slash", u)
		}
	}
	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	rekor, _ := findService(resp, "rekor")
	if rekor.EndpointUrl == nil || *rekor.EndpointUrl != "https://rekor.example.com" {
		t.Errorf("rekor endpointUrl = %v, want it without trailing slash", rekor.EndpointUrl)
	}
}

// Without TAS_DEPLOYMENT_NAME the single Securesign CR in the namespace is used.
func TestDiscoverSingleSecuresign(t *testing.T) {
	cr := makeSecuresignCR("my-tas", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.crName = ""
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusHealthy {
		t.Errorf("securesignStatus = %q (reason %v), want healthy via discovery", resp.SecuresignStatus, resp.SecuresignStatusReason)
	}
}

func TestDiscoverAmbiguousOrMissingSecuresign(t *testing.T) {
	for name, objs := range map[string][]runtime.Object{
		"none":     nil,
		"multiple": {makeSecuresignCR("b-tas", testNamespace, nil, nil), makeSecuresignCR("a-tas", testNamespace, nil, nil)},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHealthService(objs...)
			h.crName = ""
			h.collect(context.Background())

			resp, _, _ := h.GetSystemHealth(context.Background(), false)
			if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusUnknown {
				t.Errorf("securesignStatus = %q, want unknown", resp.SecuresignStatus)
			}
			r := resp.SecuresignStatusReason
			if r == nil {
				t.Fatal("securesignStatusReason must explain the failure")
			}
			if name == "multiple" {
				if !strings.Contains(*r, "set TAS_DEPLOYMENT_NAME") {
					t.Errorf("reason = %q, want it to mention TAS_DEPLOYMENT_NAME", *r)
				}
				if strings.Contains(*r, "a-tas") || strings.Contains(*r, testNamespace) {
					t.Errorf("reason = %q must not expose CR names or the namespace", *r)
				}
			}
			if name == "none" && !strings.Contains(*r, "no Securesign CR in the namespace") {
				t.Errorf("reason = %q", *r)
			}
		})
	}
}

func TestResolveNamespace(t *testing.T) {
	dir := t.TempDir()
	nsFile := filepath.Join(dir, "namespace")
	orig := serviceAccountNamespaceFile
	serviceAccountNamespaceFile = nsFile
	defer func() { serviceAccountNamespaceFile = orig }()

	t.Setenv("NAMESPACE", "")
	if got := resolveNamespace(); got != "trusted-artifact-signer" {
		t.Errorf("default = %q, want trusted-artifact-signer", got)
	}
	if err := os.WriteFile(nsFile, []byte("tas-prod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveNamespace(); got != "tas-prod" {
		t.Errorf("in-cluster = %q, want tas-prod", got)
	}
	t.Setenv("NAMESPACE", "explicit")
	if got := resolveNamespace(); got != "explicit" {
		t.Errorf("env = %q, want explicit", got)
	}
}

// The deprecated flat status fields mirror services[] for older clients.
func TestDeprecatedFlatStatusFields(t *testing.T) {
	conds := allHealthyConditions()
	conds[3] = cond("CTlogAvailable", "False")
	cr := makeSecuresignCR("securesign-sample", testNamespace, conds, allURLs())
	h := newTestHealthService(cr)

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	if resp.RekorStatus != models.SystemHealthResponseRekorStatusUnknown {
		t.Errorf("before any round rekorStatus = %q, want unknown", resp.RekorStatus)
	}

	h.collect(context.Background())
	resp, _, _ = h.GetSystemHealth(context.Background(), false)
	if resp.CtlogStatus != models.SystemHealthResponseCtlogStatusUnhealthy {
		t.Errorf("ctlogStatus = %q, want unhealthy", resp.CtlogStatus)
	}
	for name, got := range map[string]string{
		"rekor": string(resp.RekorStatus), "fulcio": string(resp.FulcioStatus), "trillian": string(resp.TrillianStatus),
		"tsa": string(resp.TsaStatus), "tuf": string(resp.TufStatus),
	} {
		if got != "healthy" {
			t.Errorf("%sStatus = %q, want healthy", name, got)
		}
	}
}

// A transient CR read failure must not blank the HTTP-probed services: they
// keep being probed at the endpoints discovered in earlier rounds, while the
// condition-only services and securesignStatus report unknown with the reason.
func TestCRReadFailureKeepsProbingLastKnownURLs(t *testing.T) {
	cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions(), allURLs())
	h := newTestHealthService(cr)
	h.collect(context.Background())

	// The CR becomes unreadable (simulated with an empty fake API server).
	h.dynamicClient = newTestHealthService().dynamicClient
	var mu sync.Mutex
	var probed []string
	h.probeHTTP = func(_ context.Context, url string) (time.Duration, int, error) {
		mu.Lock()
		probed = append(probed, url)
		mu.Unlock()
		return time.Millisecond, http.StatusOK, nil
	}
	h.collect(context.Background())

	mu.Lock()
	if len(probed) != 4 {
		t.Errorf("probed %v, want the 4 last-known endpoints", probed)
	}
	mu.Unlock()

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	for _, name := range []string{"rekor", "fulcio", "tsa", "tuf"} {
		s, _ := findService(resp, name)
		if s.Status != models.ServiceHealthStatusHealthy {
			t.Errorf("%s status = %q, want healthy (probed at last-known URL)", name, s.Status)
		}
	}
	for _, name := range []string{"ctlog", "trillian"} {
		s, _ := findService(resp, name)
		if s.Status != models.ServiceHealthStatusUnknown {
			t.Errorf("%s status = %q, want unknown", name, s.Status)
		}
	}
	if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusUnknown || resp.SecuresignStatusReason == nil {
		t.Errorf("securesignStatus = %q reason = %v, want unknown with a reason", resp.SecuresignStatus, resp.SecuresignStatusReason)
	}
}

func TestPublicReadError(t *testing.T) {
	gr := securesignGVR.GroupResource()
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"not found", apierrors.NewNotFound(gr, "my-cr"), "not found; check TAS_DEPLOYMENT_NAME and NAMESPACE"},
		{"forbidden", apierrors.NewForbidden(gr, "my-cr", errors.New("denied")),
			"permission denied; the console needs get and list access to securesigns.rhtas.redhat.com"},
		{"unauthorized", apierrors.NewUnauthorized("bad token"), "not authorized by the Kubernetes API"},
		{"deadline", fmt.Errorf("get: %w", context.DeadlineExceeded), "request timed out"},
		{"server timeout", apierrors.NewServerTimeout(gr, "get", 1), "request timed out"},
		{"throttled", apierrors.NewTooManyRequests("slow down", 1), "Kubernetes API is throttling requests"},
		{"none", fmt.Errorf("%w in namespace ns-x", errNoSecuresign), "no Securesign CR in the namespace"},
		{"multiple", fmt.Errorf("%w in namespace ns-x (a, b)", errMultipleSecuresign),
			"several Securesign CRs in the namespace; set TAS_DEPLOYMENT_NAME to select one"},
		{"network", errors.New(`Get "https://api.cluster.example:6443/apis/...": dial tcp: lookup api.cluster.example: no such host`),
			"Kubernetes API request failed; see the console logs for details"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := publicReadError(tt.err); got != tt.want {
				t.Errorf("publicReadError = %q, want %q", got, tt.want)
			}
		})
	}
}

// Neither securesignStatusReason nor the sample errors may expose the CR name,
// namespace or API server details from the raw Kubernetes error.
func TestReadErrorDetailsNotExposed(t *testing.T) {
	h := newTestHealthService() // no CR: Get returns NotFound naming the CR
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	texts := []string{}
	if resp.SecuresignStatusReason != nil {
		texts = append(texts, *resp.SecuresignStatusReason)
	}
	for _, s := range resp.Services {
		for _, ps := range history(t, s) {
			if ps.Error != nil {
				texts = append(texts, *ps.Error)
			}
		}
	}
	if len(texts) == 0 {
		t.Fatal("expected reasons to check")
	}
	for _, txt := range texts {
		for _, secret := range []string{"securesign-sample", testNamespace, "securesigns.rhtas.redhat.com \""} {
			if strings.Contains(txt, secret) {
				t.Errorf("exposed %q in %q", secret, txt)
			}
		}
	}
}

// An explicit False condition is the operator's verdict: the service is
// unhealthy immediately even if its endpoint still answers 2xx, while the
// probe measurements are kept.
func TestOperatorFalseOverridesHealthyProbe(t *testing.T) {
	conds := []interface{}{
		cond("Ready", "False"),
		map[string]interface{}{"type": "RekorAvailable", "status": "False", "reason": "Failure"},
		cond("FulcioAvailable", "True"),
		cond("CTlogAvailable", "True"),
		cond("TrillianAvailable", "True"),
		cond("TsaAvailable", "True"),
		cond("TufAvailable", "True"),
	}
	cr := makeSecuresignCR("securesign-sample", testNamespace, conds, allURLs())
	h := newTestHealthService(cr)   // default probe: 200 OK for every endpoint
	h.collect(context.Background()) // a single round: no debounce for operator failures

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	rekor, _ := findService(resp, "rekor")
	if rekor.Status != models.ServiceHealthStatusUnhealthy {
		t.Errorf("rekor status = %q, want unhealthy (RekorAvailable=False)", rekor.Status)
	}
	if resp.RekorStatus != models.SystemHealthResponseRekorStatusUnhealthy {
		t.Errorf("legacy rekorStatus = %q, want unhealthy", resp.RekorStatus)
	}
	got := history(t, rekor)
	if len(got) != 1 {
		t.Fatalf("history = %+v", got)
	}
	ps := got[0]
	if ps.Status != models.ProbeSampleStatusUnhealthy || ps.Source != models.Http {
		t.Errorf("sample status=%q source=%q, want unhealthy/http", ps.Status, ps.Source)
	}
	if ps.Error == nil || *ps.Error != "Securesign condition RekorAvailable=False (reason: Failure)" {
		t.Errorf("sample error = %v, want the operator condition", ps.Error)
	}
	if ps.LatencyMs == nil || ps.HttpStatusCode == nil || *ps.HttpStatusCode != http.StatusOK {
		t.Errorf("probe measurements must be kept: latency=%v code=%v", ps.LatencyMs, ps.HttpStatusCode)
	}

	fulcio, _ := findService(resp, "fulcio")
	if fulcio.Status != models.ServiceHealthStatusHealthy {
		t.Errorf("fulcio status = %q, want healthy (condition True, probe OK)", fulcio.Status)
	}
}

// When both the operator and the probe report a failure, the error carries both.
func TestOperatorFalseAndProbeFailureCombined(t *testing.T) {
	conds := allHealthyConditions()
	conds[5] = cond("TsaAvailable", "False")
	cr := makeSecuresignCR("securesign-sample", testNamespace, conds, allURLs())
	h := newTestHealthService(cr)
	h.probeHTTP = func(_ context.Context, url string) (time.Duration, int, error) {
		if strings.HasPrefix(url, "https://tsa.example.com") {
			return 0, 0, errors.New("connection refused")
		}
		return time.Millisecond, http.StatusOK, nil
	}
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), true)
	tsa, _ := findService(resp, "tsa")
	if tsa.Status != models.ServiceHealthStatusUnhealthy {
		t.Errorf("tsa status = %q, want unhealthy after one round", tsa.Status)
	}
	if e := history(t, tsa)[0].Error; e == nil || *e != "Securesign condition TsaAvailable=False; probe: connection refused" {
		t.Errorf("tsa error = %v", e)
	}
}

// An Unknown or missing condition is not an operator failure: the probe decides.
func TestUnknownConditionLeavesProbeInCharge(t *testing.T) {
	conds := allHealthyConditions()
	conds[6] = cond("TufAvailable", "Unknown")
	cr := makeSecuresignCR("securesign-sample", testNamespace, conds, allURLs())
	h := newTestHealthService(cr)
	h.collect(context.Background())

	resp, _, _ := h.GetSystemHealth(context.Background(), false)
	tuf, _ := findService(resp, "tuf")
	if tuf.Status != models.ServiceHealthStatusHealthy {
		t.Errorf("tuf status = %q, want healthy (probe OK, condition Unknown)", tuf.Status)
	}
}
