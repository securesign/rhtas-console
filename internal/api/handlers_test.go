package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	console_errors "github.com/securesign/rhtas-console/internal/errors"
	"github.com/securesign/rhtas-console/internal/models"
	"github.com/securesign/rhtas-console/internal/services"
)

// ---------------------------------------------------------------------------
// Mock services
// ---------------------------------------------------------------------------

type mockArtifactService struct {
	verifyFn        func(models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error)
	policiesFn      func(context.Context, string) (models.ArtifactPolicies, error)
	imageMetadataFn func(context.Context, string, string, string) (models.ImageMetadataResponse, error)
}

func (m *mockArtifactService) VerifyArtifact(req models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error) {
	return m.verifyFn(req)
}
func (m *mockArtifactService) GetArtifactPolicies(ctx context.Context, artifact string) (models.ArtifactPolicies, error) {
	return m.policiesFn(ctx, artifact)
}
func (m *mockArtifactService) GetImageMetadata(ctx context.Context, image, username, password string) (models.ImageMetadataResponse, error) {
	return m.imageMetadataFn(ctx, image, username, password)
}

type mockRekorService struct {
	getEntryFn     func(context.Context, string) (models.TransparencyLogEntry, error)
	getPublicKeyFn func(context.Context) (models.RekorPublicKey, error)
}

func (m *mockRekorService) GetRekorEntry(ctx context.Context, uuid string) (models.TransparencyLogEntry, error) {
	return m.getEntryFn(ctx, uuid)
}
func (m *mockRekorService) GetRekorPublicKey(ctx context.Context) (models.RekorPublicKey, error) {
	return m.getPublicKeyFn(ctx)
}

type mockTrustService struct {
	getTrustConfigFn       func(context.Context, string) (models.TrustConfig, int, error)
	getTrustMetadataInfoFn func(context.Context, string) (models.MetadataInfoResponse, int, error)
	getTargetFn            func(context.Context, string, string) (models.TargetContent, int, error)
	getCertificatesInfoFn  func(context.Context, string) (models.CertificateInfoList, int, error)
	getAllTargetsFn        func(context.Context, string) (models.TargetsList, int, error)
	getTrustCoverageFn     func(context.Context, string, *string, string) (models.TrustCoverageResponse, int, error)
	getTUFRepoURLFn        func() string
}

func (m *mockTrustService) GetTrustConfig(ctx context.Context, url string) (models.TrustConfig, int, error) {
	return m.getTrustConfigFn(ctx, url)
}
func (m *mockTrustService) GetTrustMetadataInfo(ctx context.Context, url string) (models.MetadataInfoResponse, int, error) {
	return m.getTrustMetadataInfoFn(ctx, url)
}
func (m *mockTrustService) GetTarget(ctx context.Context, url, target string) (models.TargetContent, int, error) {
	return m.getTargetFn(ctx, url, target)
}
func (m *mockTrustService) GetCertificatesInfo(ctx context.Context, url string) (models.CertificateInfoList, int, error) {
	return m.getCertificatesInfoFn(ctx, url)
}
func (m *mockTrustService) GetAllTargets(ctx context.Context, url string) (models.TargetsList, int, error) {
	return m.getAllTargetsFn(ctx, url)
}
func (m *mockTrustService) GetTrustCoverage(ctx context.Context, tw string, env *string, url string) (models.TrustCoverageResponse, int, error) {
	return m.getTrustCoverageFn(ctx, tw, env, url)
}
func (m *mockTrustService) GetTUFRepoURL() string {
	return m.getTUFRepoURLFn()
}
func (m *mockTrustService) Close() error { return nil }

type mockHealthService struct {
	getSystemHealthFn func(context.Context) (models.SystemHealthResponse, int, error)
}

func (m *mockHealthService) GetSystemHealth(ctx context.Context) (models.SystemHealthResponse, int, error) {
	return m.getSystemHealthFn(ctx)
}

// Verify interfaces are satisfied at compile time.
var (
	_ services.ArtifactService = (*mockArtifactService)(nil)
	_ services.RekorService    = (*mockRekorService)(nil)
	_ services.TrustService    = (*mockTrustService)(nil)
	_ services.HealthService   = (*mockHealthService)(nil)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestHandler(as services.ArtifactService, rs services.RekorService, ts services.TrustService, hs services.HealthService) *Handler {
	return NewHandler(as, rs, ts, hs)
}

func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func decodeErrorResponse(t *testing.T, body []byte) string {
	t.Helper()
	var e models.Error
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	return e.Error
}

// ---------------------------------------------------------------------------
// Tests: utility functions
// ---------------------------------------------------------------------------

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, map[string]string{"key": "value"})

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["key"] != "value" {
		t.Errorf("body[key] = %q, want %q", body["key"], "value")
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "bad input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	msg := decodeErrorResponse(t, w.Body.Bytes())
	if msg != "bad input" {
		t.Errorf("error = %q, want %q", msg, "bad input")
	}
}

// ---------------------------------------------------------------------------
// Tests: health
// ---------------------------------------------------------------------------

func TestGetHealthz(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.GetHealthz(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestGetApiV1SystemHealth(t *testing.T) {
	t.Run("nil health service", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/system/health", nil)
		h.GetApiV1SystemHealth(w, r)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
		}
	})

	t.Run("service error", func(t *testing.T) {
		hs := &mockHealthService{
			getSystemHealthFn: func(context.Context) (models.SystemHealthResponse, int, error) {
				return models.SystemHealthResponse{}, http.StatusInternalServerError, fmt.Errorf("k8s unavailable")
			},
		}
		h := newTestHandler(nil, nil, nil, hs)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/system/health", nil)
		h.GetApiV1SystemHealth(w, r)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})

	t.Run("success", func(t *testing.T) {
		hs := &mockHealthService{
			getSystemHealthFn: func(context.Context) (models.SystemHealthResponse, int, error) {
				return models.SystemHealthResponse{
					RekorStatus:      models.SystemHealthResponseRekorStatusHealthy,
					SigstoreServices: models.SystemHealthResponseSigstoreServicesHealthy,
					TufStatus:        models.SystemHealthResponseTufStatusHealthy,
				}, http.StatusOK, nil
			},
		}
		h := newTestHandler(nil, nil, nil, hs)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/system/health", nil)
		h.GetApiV1SystemHealth(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

// ---------------------------------------------------------------------------
// Tests: artifacts
// ---------------------------------------------------------------------------

func TestPostApiV1ArtifactsVerify(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		as := &mockArtifactService{
			verifyFn: func(req models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error) {
				return models.VerifyArtifactResponse{}, nil
			},
		}
		h := newTestHandler(as, nil, nil, nil)
		body := `{"ociImage":"registry.example.com/image:latest"}`
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/verify", strings.NewReader(body))
		h.PostApiV1ArtifactsVerify(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("invalid JSON body", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/verify", strings.NewReader("{bad"))
		h.PostApiV1ArtifactsVerify(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("service error", func(t *testing.T) {
		as := &mockArtifactService{
			verifyFn: func(req models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error) {
				return models.VerifyArtifactResponse{}, fmt.Errorf("verification failed")
			},
		}
		h := newTestHandler(as, nil, nil, nil)
		body := `{"ociImage":"registry.example.com/image:latest"}`
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/verify", strings.NewReader(body))
		h.PostApiV1ArtifactsVerify(w, r)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})

	t.Run("max bytes exceeded", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil, nil)
		w := httptest.NewRecorder()
		bigBody := strings.NewReader(`{"ociImage":"` + strings.Repeat("x", 100) + `"}`)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/verify", bigBody)
		r.Body = http.MaxBytesReader(w, r.Body, 1)
		h.PostApiV1ArtifactsVerify(w, r)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
		}
	})
}

func TestGetApiV1ArtifactsImage(t *testing.T) {
	t.Run("missing uri param", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/image", nil)
		h.GetApiV1ArtifactsImage(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("success", func(t *testing.T) {
		as := &mockArtifactService{
			imageMetadataFn: func(_ context.Context, image, _, _ string) (models.ImageMetadataResponse, error) {
				return models.ImageMetadataResponse{Digest: "sha256:abc"}, nil
			},
		}
		h := newTestHandler(as, nil, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/image?uri=registry.example.com/img:v1", nil)
		h.GetApiV1ArtifactsImage(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	errorTests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"image not found", console_errors.ErrImageNotFound, http.StatusNotFound},
		{"auth failed", console_errors.ErrArtifactAuthFailed, http.StatusUnauthorized},
		{"invalid image URI", console_errors.ErrArtifactInvalidImageURI, http.StatusBadRequest},
		{"failed to fetch image", console_errors.ErrArtifactFailedToFetchImage, http.StatusInternalServerError},
		{"failed to compute digest", console_errors.ErrArtifactFailedToComputeDigest, http.StatusInternalServerError},
		{"failed to fetch config", console_errors.ErrArtifactFailedToFetchConfig, http.StatusInternalServerError},
		{"connection refused", console_errors.ErrArtifactConnectionRefused, http.StatusServiceUnavailable},
		{"unknown error", fmt.Errorf("something unexpected"), http.StatusInternalServerError},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			as := &mockArtifactService{
				imageMetadataFn: func(context.Context, string, string, string) (models.ImageMetadataResponse, error) {
					return models.ImageMetadataResponse{}, tt.err
				},
			}
			h := newTestHandler(as, nil, nil, nil)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/image?uri=registry.example.com/img:v1", nil)
			h.GetApiV1ArtifactsImage(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestGetApiV1ArtifactsArtifactPolicies(t *testing.T) {
	t.Run("missing artifact", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/policies", nil)
		r = withChiURLParam(r, "artifact", "")
		h.GetApiV1ArtifactsArtifactPolicies(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("success", func(t *testing.T) {
		as := &mockArtifactService{
			policiesFn: func(_ context.Context, artifact string) (models.ArtifactPolicies, error) {
				return models.ArtifactPolicies{Artifact: artifact}, nil
			},
		}
		h := newTestHandler(as, nil, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/test-artifact/policies", nil)
		r = withChiURLParam(r, "artifact", "test-artifact")
		h.GetApiV1ArtifactsArtifactPolicies(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

// ---------------------------------------------------------------------------
// Tests: rekor
// ---------------------------------------------------------------------------

func TestGetApiV1RekorEntriesUuid(t *testing.T) {
	t.Run("missing uuid", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/rekor/entries/", nil)
		r = withChiURLParam(r, "uuid", "")
		h.GetApiV1RekorEntriesUuid(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("service error", func(t *testing.T) {
		rs := &mockRekorService{
			getEntryFn: func(_ context.Context, _ string) (models.TransparencyLogEntry, error) {
				return models.TransparencyLogEntry{}, fmt.Errorf("not found")
			},
		}
		h := newTestHandler(nil, rs, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/rekor/entries/abc123", nil)
		r = withChiURLParam(r, "uuid", "abc123")
		h.GetApiV1RekorEntriesUuid(w, r)

		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})

	t.Run("success", func(t *testing.T) {
		rs := &mockRekorService{
			getEntryFn: func(_ context.Context, uuid string) (models.TransparencyLogEntry, error) {
				return models.TransparencyLogEntry{LogIndex: 42}, nil
			},
		}
		h := newTestHandler(nil, rs, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/rekor/entries/abc123", nil)
		r = withChiURLParam(r, "uuid", "abc123")
		h.GetApiV1RekorEntriesUuid(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestGetApiV1RekorPublicKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rs := &mockRekorService{
			getPublicKeyFn: func(context.Context) (models.RekorPublicKey, error) {
				return models.RekorPublicKey{PublicKey: "test-key"}, nil
			},
		}
		h := newTestHandler(nil, rs, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/rekor/public-key", nil)
		h.GetApiV1RekorPublicKey(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("error", func(t *testing.T) {
		rs := &mockRekorService{
			getPublicKeyFn: func(context.Context) (models.RekorPublicKey, error) {
				return models.RekorPublicKey{}, fmt.Errorf("unavailable")
			},
		}
		h := newTestHandler(nil, rs, nil, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/rekor/public-key", nil)
		h.GetApiV1RekorPublicKey(w, r)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})
}

// ---------------------------------------------------------------------------
// Tests: trust
// ---------------------------------------------------------------------------

func defaultMockTrustService() *mockTrustService {
	return &mockTrustService{
		getTUFRepoURLFn: func() string { return "https://tuf.example.com" },
	}
}

func TestGetApiV1TrustConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getTrustConfigFn = func(context.Context, string) (models.TrustConfig, int, error) {
			return models.TrustConfig{}, http.StatusOK, nil
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/config", nil)
		h.GetApiV1TrustConfig(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("error", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getTrustConfigFn = func(context.Context, string) (models.TrustConfig, int, error) {
			return models.TrustConfig{}, http.StatusServiceUnavailable, fmt.Errorf("unavailable")
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/config", nil)
		h.GetApiV1TrustConfig(w, r)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
		}
	})
}

func TestGetApiV1TrustMetadataInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getTrustMetadataInfoFn = func(context.Context, string) (models.MetadataInfoResponse, int, error) {
			return models.MetadataInfoResponse{}, http.StatusOK, nil
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/metadata-info", nil)
		h.GetApiV1TrustMetadataInfo(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("error", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getTrustMetadataInfoFn = func(context.Context, string) (models.MetadataInfoResponse, int, error) {
			return models.MetadataInfoResponse{}, http.StatusServiceUnavailable, fmt.Errorf("metadata unavailable")
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/metadata-info", nil)
		h.GetApiV1TrustMetadataInfo(w, r)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
		}
	})
}

func TestGetApiV1TrustTargets(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getAllTargetsFn = func(context.Context, string) (models.TargetsList, int, error) {
			return models.TargetsList{Data: []models.TargetInfo{{Name: "fulcio.crt.pem"}}}, http.StatusOK, nil
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/targets", nil)
		h.GetApiV1TrustTargets(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("error", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getAllTargetsFn = func(context.Context, string) (models.TargetsList, int, error) {
			return models.TargetsList{}, http.StatusInternalServerError, fmt.Errorf("failed")
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/targets", nil)
		h.GetApiV1TrustTargets(w, r)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})
}

func TestGetApiV1TrustTarget(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getTargetFn = func(_ context.Context, _, target string) (models.TargetContent, int, error) {
			return models.TargetContent{Content: "cert-pem-data"}, http.StatusOK, nil
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/target?target=fulcio.crt.pem", nil)
		h.GetApiV1TrustTarget(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("error", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getTargetFn = func(context.Context, string, string) (models.TargetContent, int, error) {
			return models.TargetContent{}, http.StatusNotFound, fmt.Errorf("target not found")
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/target?target=missing", nil)
		h.GetApiV1TrustTarget(w, r)

		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestGetApiV1TrustTargetsCertificates(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getCertificatesInfoFn = func(context.Context, string) (models.CertificateInfoList, int, error) {
			return models.CertificateInfoList{Data: []models.CertificateInfo{}}, http.StatusOK, nil
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/targets/certificates", nil)
		h.GetApiV1TrustTargetsCertificates(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("error", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getCertificatesInfoFn = func(context.Context, string) (models.CertificateInfoList, int, error) {
			return models.CertificateInfoList{}, http.StatusInternalServerError, fmt.Errorf("parse failed")
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/targets/certificates", nil)
		h.GetApiV1TrustTargetsCertificates(w, r)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})
}

func TestGetApiV1TrustCoverage(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getTrustCoverageFn = func(context.Context, string, *string, string) (models.TrustCoverageResponse, int, error) {
			return models.TrustCoverageResponse{TotalArtifacts: 100}, http.StatusOK, nil
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/coverage", nil)
		h.GetApiV1TrustCoverage(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("error", func(t *testing.T) {
		ts := defaultMockTrustService()
		ts.getTrustCoverageFn = func(context.Context, string, *string, string) (models.TrustCoverageResponse, int, error) {
			return models.TrustCoverageResponse{}, http.StatusInternalServerError, fmt.Errorf("unavailable")
		}
		h := newTestHandler(nil, nil, ts, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/trust/coverage", nil)
		h.GetApiV1TrustCoverage(w, r)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})
}

// ---------------------------------------------------------------------------
// Tests: static content
// ---------------------------------------------------------------------------

func TestServeSwaggerUI(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/swagger-ui", nil)
	h.ServeSwaggerUI(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
	}
	if !strings.Contains(w.Body.String(), "swagger-ui") {
		t.Error("body should contain 'swagger-ui'")
	}
}

func TestServeOpenAPIFile(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/rhtas-console.yaml", nil)
	h.ServeOpenAPIFile(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "openapi") {
		t.Errorf("Content-Type = %q, want it to contain 'openapi'", ct)
	}
	if w.Body.Len() == 0 {
		t.Error("body should not be empty")
	}
}
