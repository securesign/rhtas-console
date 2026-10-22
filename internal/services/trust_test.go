package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func generateTestCert(t *testing.T, notBefore, notAfter time.Time, subject string) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subject},
		Issuer:       pkix.Name{CommonName: subject},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return string(pemBytes), certDER
}

func TestCertFingerprint(t *testing.T) {
	input := []byte("test data for fingerprint")
	got := certFingerprint(input)
	h := sha256.Sum256(input)
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("certFingerprint() = %q, want %q", got, want)
	}
}

func TestExtractCertDetails(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)

	t.Run("valid single cert", func(t *testing.T) {
		pemStr, certDER := generateTestCert(t, notBefore, notAfter, "test-subject")
		results, err := extractCertDetails(pemStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		entry := results[0]
		if entry.info.Subject != "CN=test-subject" {
			t.Errorf("subject = %q, want %q", entry.info.Subject, "CN=test-subject")
		}
		if entry.info.Issuer != "CN=test-subject" {
			t.Errorf("issuer = %q, want %q", entry.info.Issuer, "CN=test-subject")
		}
		if _, err := time.Parse(time.RFC3339, entry.info.CertExpiration); err != nil {
			t.Errorf("certExpiration %q is not RFC3339: %v", entry.info.CertExpiration, err)
		}
		h := sha256.Sum256(certDER)
		wantFP := hex.EncodeToString(h[:])
		if entry.fingerprint != wantFP {
			t.Errorf("fingerprint = %q, want %q", entry.fingerprint, wantFP)
		}
		if entry.notAfter.IsZero() {
			t.Error("notAfter should not be zero")
		}
	})

	t.Run("multi cert PEM", func(t *testing.T) {
		pem1, _ := generateTestCert(t, notBefore, notAfter, "cert-one")
		pem2, _ := generateTestCert(t, notBefore, notAfter, "cert-two")
		combined := pem1 + pem2
		results, err := extractCertDetails(combined)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}
		if results[0].info.Subject != "CN=cert-one" {
			t.Errorf("first subject = %q, want %q", results[0].info.Subject, "CN=cert-one")
		}
		if results[1].info.Subject != "CN=cert-two" {
			t.Errorf("second subject = %q, want %q", results[1].info.Subject, "CN=cert-two")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := extractCertDetails("not a valid PEM")
		if err == nil {
			t.Error("expected error for invalid PEM")
		}
	})

	t.Run("non-certificate PEM block", func(t *testing.T) {
		rsaBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")})
		_, err := extractCertDetails(string(rsaBlock))
		if err == nil {
			t.Error("expected error for non-certificate PEM block")
		}
	})
}

func TestComputeCertStatus(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		notAfter time.Time
		validFor *validForWindow
		want     models.CertificateStatus
	}{
		{
			name:     "active, no validFor",
			notAfter: now.Add(365 * 24 * time.Hour),
			want:     models.Active,
		},
		{
			name:     "expiring in 29 days",
			notAfter: now.Add(29 * 24 * time.Hour),
			want:     models.Expiring,
		},
		{
			name:     "expiring at exactly 30 days boundary",
			notAfter: now.Add(30 * 24 * time.Hour),
			want:     models.Expiring,
		},
		{
			name:     "active at 31 days",
			notAfter: now.Add(31 * 24 * time.Hour),
			want:     models.Active,
		},
		{
			name:     "expired cert",
			notAfter: now.Add(-1 * time.Hour),
			want:     models.Expired,
		},
		{
			name:     "revoked: validFor.end passed, cert still valid",
			notAfter: now.Add(365 * 24 * time.Hour),
			validFor: &validForWindow{
				start: now.Add(-2 * 365 * 24 * time.Hour),
				end:   now.Add(-30 * 24 * time.Hour),
			},
			want: models.Revoked,
		},
		{
			name:     "expired takes precedence over revoked",
			notAfter: now.Add(-1 * time.Hour),
			validFor: &validForWindow{
				start: now.Add(-2 * 365 * 24 * time.Hour),
				end:   now.Add(-30 * 24 * time.Hour),
			},
			want: models.Expired,
		},
		{
			name:     "validFor.end in future, cert valid",
			notAfter: now.Add(365 * 24 * time.Hour),
			validFor: &validForWindow{
				start: now.Add(-30 * 24 * time.Hour),
				end:   now.Add(365 * 24 * time.Hour),
			},
			want: models.Active,
		},
		{
			name:     "validFor.end in future, cert expiring",
			notAfter: now.Add(15 * 24 * time.Hour),
			validFor: &validForWindow{
				start: now.Add(-30 * 24 * time.Hour),
				end:   now.Add(365 * 24 * time.Hour),
			},
			want: models.Expiring,
		},
		{
			name:     "pending: validFor.start in future",
			notAfter: now.Add(365 * 24 * time.Hour),
			validFor: &validForWindow{
				start: now.Add(30 * 24 * time.Hour),
				end:   now.Add(2 * 365 * 24 * time.Hour),
			},
			want: models.Pending,
		},
		{
			name:     "revoked takes precedence over pending when end already passed",
			notAfter: now.Add(365 * 24 * time.Hour),
			validFor: &validForWindow{
				start: now.Add(30 * 24 * time.Hour),
				end:   now.Add(-30 * 24 * time.Hour),
			},
			want: models.Revoked,
		},
		{
			name:     "expired takes precedence over pending",
			notAfter: now.Add(-1 * time.Hour),
			validFor: &validForWindow{
				start: now.Add(30 * 24 * time.Hour),
				end:   now.Add(2 * 365 * 24 * time.Hour),
			},
			want: models.Expired,
		},
		{
			name:     "active once validFor.start has passed",
			notAfter: now.Add(365 * 24 * time.Hour),
			validFor: &validForWindow{
				start: now.Add(-1 * time.Hour),
				end:   now.Add(365 * 24 * time.Hour),
			},
			want: models.Active,
		},
		{
			name: "zero notAfter defaults to active",
			want: models.Active,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeCertStatus(tt.notAfter, tt.validFor, now)
			if got != tt.want {
				t.Errorf("computeCertStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetValidForLookupCaching(t *testing.T) {
	t.Run("cache hit with matching URL", func(t *testing.T) {
		s := &trustService{
			refreshInterval: 5 * time.Minute,
		}
		cached := map[string]validForWindow{
			"abc123": {start: time.Now(), end: time.Time{}},
		}
		s.validForCache = cached
		s.validForRepoUrl = "https://tuf.example.com"
		s.validForExpiry = time.Now().Add(5 * time.Minute)

		got := s.getValidForLookup(context.TODO(), "https://tuf.example.com")
		if len(got) != 1 {
			t.Errorf("expected cached map with 1 entry, got %d", len(got))
		}
		if _, ok := got["abc123"]; !ok {
			t.Error("expected key 'abc123' in cached result")
		}
	})

	t.Run("cache miss on different URL", func(t *testing.T) {
		s := &trustService{
			refreshInterval: 5 * time.Minute,
		}
		cached := map[string]validForWindow{
			"abc123": {start: time.Now(), end: time.Time{}},
		}
		s.validForCache = cached
		s.validForRepoUrl = "https://tuf.example.com"
		s.validForExpiry = time.Now().Add(5 * time.Minute)

		got := s.getValidForLookup(context.TODO(), "https://other.example.com")
		if _, ok := got["abc123"]; ok {
			t.Error("should not return cached result for different URL")
		}
	})

	t.Run("cache miss on expired TTL", func(t *testing.T) {
		s := &trustService{
			refreshInterval: 5 * time.Minute,
		}
		cached := map[string]validForWindow{
			"abc123": {start: time.Now(), end: time.Time{}},
		}
		s.validForCache = cached
		s.validForRepoUrl = "https://tuf.example.com"
		s.validForExpiry = time.Now().Add(-1 * time.Minute)

		got := s.getValidForLookup(context.TODO(), "https://tuf.example.com")
		if _, ok := got["abc123"]; ok {
			t.Error("should not return expired cached result")
		}
	})

	t.Run("cache hit with trailing slash URL equivalence", func(t *testing.T) {
		s := &trustService{
			refreshInterval: 5 * time.Minute,
		}
		cached := map[string]validForWindow{
			"abc123": {start: time.Now(), end: time.Time{}},
		}
		s.validForCache = cached
		s.validForRepoUrl = "https://tuf.example.com/"
		s.validForExpiry = time.Now().Add(5 * time.Minute)

		got := s.getValidForLookup(context.TODO(), "https://tuf.example.com")
		if len(got) != 1 {
			t.Errorf("expected cached map with 1 entry for equivalent URL, got %d", len(got))
		}
	})
}

func TestExtractRootMetadataInfo(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantStatus string
		wantVer    string
		wantErr    bool
	}{
		{
			name:       "valid, far future expiry",
			input:      []byte(`{"signed":{"expires":"2099-01-01T00:00:00Z","version":5}}`),
			wantStatus: "valid",
			wantVer:    "5",
		},
		{
			name: "expiring within 30 days",
			input: func() []byte {
				exp := time.Now().UTC().Add(15 * 24 * time.Hour).Format(time.RFC3339)
				b, _ := json.Marshal(map[string]interface{}{
					"signed": map[string]interface{}{"expires": exp, "version": 3},
				})
				return b
			}(),
			wantStatus: "expiring",
			wantVer:    "3",
		},
		{
			name:       "expired",
			input:      []byte(`{"signed":{"expires":"2020-01-01T00:00:00Z","version":1}}`),
			wantStatus: "expired",
			wantVer:    "1",
		},
		{
			name:    "invalid JSON",
			input:   []byte(`{not json`),
			wantErr: true,
		},
		{
			name:    "bad time format",
			input:   []byte(`{"signed":{"expires":"not-a-date","version":1}}`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractRootMetadataInfo(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if got.Version != tt.wantVer {
				t.Errorf("version = %q, want %q", got.Version, tt.wantVer)
			}
		})
	}
}

func TestExtractTargetMetadataInfo(t *testing.T) {
	t.Run("valid targets", func(t *testing.T) {
		input := []byte(`{
			"signed": {
				"targets": {
					"fulcio.crt.pem": {
						"custom": {"sigstore": {"status": "Active", "usage": "Fulcio"}}
					},
					"rekor.pub": {
						"custom": {"sigstore": {"status": "Active", "usage": "Rekor"}}
					}
				}
			}
		}`)
		got, err := extractTargetMetadataInfo(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 targets, got %d", len(got))
		}
		fulcio := got["fulcio.crt.pem"]
		if fulcio["status"] != "Active" {
			t.Errorf("fulcio status = %q, want %q", fulcio["status"], "Active")
		}
		if fulcio["type"] != "Fulcio" {
			t.Errorf("fulcio type = %q, want %q", fulcio["type"], "Fulcio")
		}
	})

	t.Run("empty targets", func(t *testing.T) {
		input := []byte(`{"signed": {"targets": {}}}`)
		got, err := extractTargetMetadataInfo(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected 0 targets, got %d", len(got))
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := extractTargetMetadataInfo([]byte(`{bad`))
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("malformed target is skipped, valid targets survive", func(t *testing.T) {
		// "poisoned.pem" has a non-string status; it must be dropped while the
		// valid targets (including the revoked ctfe.pub) are still returned.
		input := []byte(`{
			"signed": {
				"targets": {
					"fulcio.crt.pem": {"custom": {"sigstore": {"status": "Active", "usage": "Fulcio"}}},
					"rekor.pub": {"custom": {"sigstore": {"status": "Active", "usage": "Rekor"}}},
					"poisoned.pem": {"custom": {"sigstore": {"status": 123, "usage": "Fulcio"}}},
					"ctfe.pub": {"custom": {"sigstore": {"status": "Revoked", "usage": "CTFE"}}}
				}
			}
		}`)
		got, err := extractTargetMetadataInfo(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 valid targets, got %d: %v", len(got), got)
		}
		if _, ok := got["poisoned.pem"]; ok {
			t.Error("malformed target should have been skipped")
		}
		if got["ctfe.pub"]["status"] != "Revoked" {
			t.Errorf("ctfe.pub status = %q, want %q", got["ctfe.pub"]["status"], "Revoked")
		}
	})

	t.Run("all targets malformed returns error", func(t *testing.T) {
		// A non-empty inventory where every entry is malformed must error rather
		// than masquerade as an empty repository.
		input := []byte(`{
			"signed": {
				"targets": {
					"a.pem": {"custom": {"sigstore": {"status": 1, "usage": "Fulcio"}}},
					"b.pem": {"custom": {"sigstore": {"status": 2, "usage": "TSA"}}}
				}
			}
		}`)
		_, err := extractTargetMetadataInfo(input)
		if err == nil {
			t.Fatal("expected error when every target is malformed")
		}
	})
}

func TestUrlsEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "https://example.com/path", "https://example.com/path", true},
		{"trailing slash", "https://example.com/", "https://example.com", true},
		{"different hosts", "https://a.com", "https://b.com", false},
		{"different paths", "https://a.com/x", "https://a.com/y", false},
		{"both empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := urlsEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("urlsEqual(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMetadataInfoFromVersionAndExpires(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name       string
		version    int64
		expires    time.Time
		wantStatus string
	}{
		{
			name:       "valid, far future",
			version:    15,
			expires:    now.Add(365 * 24 * time.Hour),
			wantStatus: "valid",
		},
		{
			name:       "expiring within 30 days",
			version:    5,
			expires:    now.Add(15 * 24 * time.Hour),
			wantStatus: "expiring",
		},
		{
			name:       "expired",
			version:    1,
			expires:    now.Add(-1 * time.Hour),
			wantStatus: "expired",
		},
		{
			name:       "boundary: exactly 30 days",
			version:    10,
			expires:    now.Add(30 * 24 * time.Hour),
			wantStatus: "expiring",
		},
		{
			name:       "boundary: 31 days",
			version:    10,
			expires:    now.Add(31 * 24 * time.Hour),
			wantStatus: "valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := metadataInfoFromVersionAndExpires(tt.version, tt.expires)
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			wantVersion := strconv.FormatInt(tt.version, 10)
			if got.Version != wantVersion {
				t.Errorf("version = %q, want %q", got.Version, wantVersion)
			}
			if _, err := time.Parse(time.RFC3339, got.Expires); err != nil {
				t.Errorf("expires %q is not valid RFC3339: %v", got.Expires, err)
			}
		})
	}
}

func clearRootCache(t *testing.T) {
	t.Helper()
	rootCache.Lock()
	rootCache.m = make(map[string]*cachedTufRootResponse)
	rootCache.Unlock()
}

func TestFetchRootJSON(t *testing.T) {
	t.Run("200 OK returns body and caches", func(t *testing.T) {
		clearRootCache(t)
		body := []byte(`{"signed":{"version":1}}`)
		var reqCount atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqCount.Add(1)
			w.Header().Set("ETag", `"v1"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		got, err := fetchRootJSON(context.Background(), srv.URL+"/root.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(body) {
			t.Errorf("body = %q, want %q", got, body)
		}
		if reqCount.Load() != 1 {
			t.Errorf("requests = %d, want 1", reqCount.Load())
		}
	})

	t.Run("cache hit skips HTTP request", func(t *testing.T) {
		clearRootCache(t)
		body := []byte(`{"signed":{"version":2}}`)
		var reqCount atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqCount.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		url := srv.URL + "/root.json"
		_, err := fetchRootJSON(context.Background(), url)
		if err != nil {
			t.Fatalf("first call: %v", err)
		}

		got, err := fetchRootJSON(context.Background(), url)
		if err != nil {
			t.Fatalf("second call: %v", err)
		}
		if string(got) != string(body) {
			t.Errorf("body = %q, want %q", got, body)
		}
		if reqCount.Load() != 1 {
			t.Errorf("requests = %d, want 1 (cache hit should skip second request)", reqCount.Load())
		}
	})

	t.Run("304 Not Modified reuses cached body", func(t *testing.T) {
		clearRootCache(t)
		body := []byte(`{"signed":{"version":3}}`)
		var reqCount atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqCount.Add(1)
			if r.Header.Get("If-None-Match") == `"v3"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v3"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		url := srv.URL + "/root.json"
		_, err := fetchRootJSON(context.Background(), url)
		if err != nil {
			t.Fatalf("first call: %v", err)
		}

		// Expire the cache entry to force a network request
		rootCache.Lock()
		if entry, ok := rootCache.m[url]; ok {
			entry.expiresAt = time.Now().Add(-1 * time.Minute)
		}
		rootCache.Unlock()

		got, err := fetchRootJSON(context.Background(), url)
		if err != nil {
			t.Fatalf("second call after expiry: %v", err)
		}
		if string(got) != string(body) {
			t.Errorf("body = %q, want %q", got, body)
		}
		if reqCount.Load() != 2 {
			t.Errorf("requests = %d, want 2", reqCount.Load())
		}
	})

	t.Run("500 error", func(t *testing.T) {
		clearRootCache(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		_, err := fetchRootJSON(context.Background(), srv.URL+"/root.json")
		if err == nil {
			t.Error("expected error for 500 response")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		clearRootCache(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := fetchRootJSON(ctx, srv.URL+"/root.json")
		if err == nil {
			t.Error("expected error for cancelled context")
		}
	})
}

func TestGetTrustCoverage(t *testing.T) {
	s := &trustService{}

	t.Run("MOCK_MODE not set returns 503", func(t *testing.T) {
		t.Setenv("MOCK_MODE", "")
		_, statusCode, err := s.GetTrustCoverage(context.Background(), "24h", nil, "https://tuf.example.com")
		if err == nil {
			t.Fatal("expected error when MOCK_MODE is not set")
		}
		if statusCode != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", statusCode, http.StatusServiceUnavailable)
		}
	})

	t.Run("MOCK_MODE=true returns mock data", func(t *testing.T) {
		t.Setenv("MOCK_MODE", "true")
		resp, statusCode, err := s.GetTrustCoverage(context.Background(), "24h", nil, "https://tuf.example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if statusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", statusCode, http.StatusOK)
		}
		if resp.TotalArtifacts != 1000 {
			t.Errorf("TotalArtifacts = %d, want 1000", resp.TotalArtifacts)
		}
		if resp.AttestedCount != 610 {
			t.Errorf("AttestedCount = %d, want 610", resp.AttestedCount)
		}
		if resp.VerifiedPercentage != 61.0 {
			t.Errorf("VerifiedPercentage = %v, want 61.0", resp.VerifiedPercentage)
		}
	})

	t.Run("MOCK_MODE=false returns 503", func(t *testing.T) {
		t.Setenv("MOCK_MODE", "false")
		_, statusCode, err := s.GetTrustCoverage(context.Background(), "24h", nil, "https://tuf.example.com")
		if err == nil {
			t.Fatal("expected error when MOCK_MODE is not 'true'")
		}
		if statusCode != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", statusCode, http.StatusServiceUnavailable)
		}
	})
}

// ---------------------------------------------------------------------------
// Fake TUF repository fixture
// ---------------------------------------------------------------------------

// testTUFTarget describes a single target file to publish in the fake repo.
type testTUFTarget struct {
	name    string
	usage   string // sigstore custom "usage" -> target type (e.g. Fulcio, TSA, TrustedRoot)
	content string
}

// newTestTUFServer builds a minimal but correctly-signed consistent-snapshot TUF
// repository (root/timestamp/snapshot/targets at version 1) and serves it over
// httptest. It returns the server. Callers must redirect the TUF cache away from
// the real home directory (t.Setenv("HOME", t.TempDir())) before using it.
func newTestTUFServer(t *testing.T, targets []testTUFTarget) *httptest.Server {
	t.Helper()
	expires := time.Now().UTC().Add(365 * 24 * time.Hour)

	// One ed25519 key per top-level role.
	keys := map[string]ed25519.PrivateKey{}
	root := metadata.Root(expires)
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate %s key: %v", role, err)
		}
		keys[role] = priv
		key, err := metadata.KeyFromPublicKey(priv.Public())
		if err != nil {
			t.Fatalf("convert %s key: %v", role, err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatalf("add %s key to root: %v", role, err)
		}
	}

	// Targets metadata + the hash-prefixed target blobs that will be served.
	served := map[string][]byte{}
	targetsMeta := metadata.Targets(expires)
	for _, tgt := range targets {
		sum := sha256.Sum256([]byte(tgt.content))
		tf := &metadata.TargetFiles{
			Length: int64(len(tgt.content)),
			Hashes: metadata.Hashes{"sha256": sum[:]},
			Path:   tgt.name,
		}
		custom := json.RawMessage(fmt.Sprintf(`{"sigstore":{"status":"Active","usage":%q}}`, tgt.usage))
		tf.Custom = &custom
		targetsMeta.Signed.Targets[tgt.name] = tf
		// Consistent-snapshot target path: <sha256hex>.<name>
		served["/targets/"+hex.EncodeToString(sum[:])+"."+tgt.name] = []byte(tgt.content)
	}

	snapshot := metadata.Snapshot(expires)
	timestamp := metadata.Timestamp(expires)

	// Sign each role with its key.
	signWith := func(role string) signature.Signer {
		signer, err := signature.LoadSigner(keys[role], crypto.Hash(0))
		if err != nil {
			t.Fatalf("load %s signer: %v", role, err)
		}
		return signer
	}
	if _, err := targetsMeta.Sign(signWith("targets")); err != nil {
		t.Fatalf("sign targets: %v", err)
	}
	if _, err := snapshot.Sign(signWith("snapshot")); err != nil {
		t.Fatalf("sign snapshot: %v", err)
	}
	if _, err := timestamp.Sign(signWith("timestamp")); err != nil {
		t.Fatalf("sign timestamp: %v", err)
	}
	if _, err := root.Sign(signWith("root")); err != nil {
		t.Fatalf("sign root: %v", err)
	}

	rootBytes, err := root.ToBytes(true)
	if err != nil {
		t.Fatalf("serialize root: %v", err)
	}
	timestampBytes, err := timestamp.ToBytes(true)
	if err != nil {
		t.Fatalf("serialize timestamp: %v", err)
	}
	snapshotBytes, err := snapshot.ToBytes(true)
	if err != nil {
		t.Fatalf("serialize snapshot: %v", err)
	}
	targetsBytes, err := targetsMeta.ToBytes(true)
	if err != nil {
		t.Fatalf("serialize targets: %v", err)
	}
	served["/root.json"] = rootBytes   // fetched by setOptsRoot
	served["/1.root.json"] = rootBytes // harmless, not requested at v1
	served["/timestamp.json"] = timestampBytes
	served["/1.snapshot.json"] = snapshotBytes
	served["/1.targets.json"] = targetsBytes

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := served[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		// 404 for e.g. /2.root.json so the updater stops the root-rotation loop.
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func defaultTestTargets(t *testing.T) []testTUFTarget {
	t.Helper()
	now := time.Now().UTC()
	fulcioPEM, _ := generateTestCert(t, now.Add(-time.Hour), now.Add(365*24*time.Hour), "Test Fulcio CA")
	tsaPEM, _ := generateTestCert(t, now.Add(-time.Hour), now.Add(365*24*time.Hour), "Test TSA")
	trustedRoot := `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1",` +
		`"tlogs":[],"certificateAuthorities":[],"ctlogs":[],"timestampAuthorities":[]}`
	return []testTUFTarget{
		{name: "fulcio.crt.pem", usage: "Fulcio", content: fulcioPEM},
		{name: "tsa.crt.pem", usage: "TSA", content: tsaPEM},
		{name: "trusted_root.json", usage: "TrustedRoot", content: trustedRoot},
	}
}

// ---------------------------------------------------------------------------
// Trust service integration tests against the fake TUF repository
// ---------------------------------------------------------------------------

func TestTrustServiceTUFIntegration(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // redirect TUF cache away from real home
	srv := newTestTUFServer(t, defaultTestTargets(t))
	s := &trustService{refreshInterval: time.Hour}
	ctx := context.Background()

	t.Run("GetTarget downloads and returns content", func(t *testing.T) {
		tc, code, err := s.GetTarget(ctx, srv.URL, "fulcio.crt.pem")
		if err != nil {
			t.Fatalf("GetTarget: %v", err)
		}
		if code != http.StatusOK {
			t.Errorf("status = %d, want 200", code)
		}
		if !strings.Contains(tc.Content, "BEGIN CERTIFICATE") {
			t.Errorf("content = %q, want a PEM certificate", tc.Content)
		}
	})

	t.Run("GetTarget on unknown target errors", func(t *testing.T) {
		_, code, err := s.GetTarget(ctx, srv.URL, "does-not-exist")
		if err == nil {
			t.Fatal("expected error for unknown target")
		}
		if code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", code)
		}
	})

	t.Run("GetTarget with cancelled context", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, code, err := s.GetTarget(cancelled, srv.URL, "fulcio.crt.pem")
		if err == nil {
			t.Fatal("expected error for cancelled context")
		}
		if code != 499 {
			t.Errorf("status = %d, want 499", code)
		}
	})

	t.Run("GetCertificatesInfo returns fulcio and tsa certs", func(t *testing.T) {
		certs, code, err := s.GetCertificatesInfo(ctx, srv.URL)
		if err != nil {
			t.Fatalf("GetCertificatesInfo: %v", err)
		}
		if code != http.StatusOK {
			t.Errorf("status = %d, want 200", code)
		}
		if len(certs.Data) != 2 {
			t.Fatalf("got %d certificates, want 2 (fulcio + tsa)", len(certs.Data))
		}
		types := map[string]bool{}
		for _, c := range certs.Data {
			types[strings.ToLower(c.Type)] = true
		}
		if !types["fulcio"] || !types["tsa"] {
			t.Errorf("certificate types = %v, want fulcio and tsa", types)
		}
	})

	t.Run("GetAllTargets returns every target", func(t *testing.T) {
		targets, code, err := s.GetAllTargets(ctx, srv.URL)
		if err != nil {
			t.Fatalf("GetAllTargets: %v", err)
		}
		if code != http.StatusOK {
			t.Errorf("status = %d, want 200", code)
		}
		if len(targets.Data) != 3 {
			t.Errorf("got %d targets, want 3", len(targets.Data))
		}
	})

	t.Run("GetTrustMetadataInfo reports metadata versions", func(t *testing.T) {
		info, code, err := s.GetTrustMetadataInfo(ctx, srv.URL)
		if err != nil {
			t.Fatalf("GetTrustMetadataInfo: %v", err)
		}
		if code != http.StatusOK {
			t.Errorf("status = %d, want 200", code)
		}
		for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
			entries, ok := info.Data[role]
			if !ok || len(entries) == 0 {
				t.Errorf("missing metadata info for role %q", role)
				continue
			}
			if entries[0].Version != "1" {
				t.Errorf("%s version = %q, want \"1\"", role, entries[0].Version)
			}
		}
	})

	t.Run("GetTUFRepoURL returns configured URL", func(t *testing.T) {
		if got := s.GetTUFRepoURL(); got != srv.URL {
			t.Errorf("GetTUFRepoURL() = %q, want %q", got, srv.URL)
		}
	})

	t.Run("Close cancels background context", func(t *testing.T) {
		_, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}

func TestNewTrustService(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := newTestTUFServer(t, defaultTestTargets(t))

	ts := NewTrustService(&TrustServiceFlags{
		TUFRepoURL:      srv.URL,
		RefreshInterval: time.Hour, // large, so the background ticker never fires during the test
	})
	defer func() {
		if err := ts.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	if ts.GetTUFRepoURL() != srv.URL {
		t.Errorf("GetTUFRepoURL() = %q, want %q", ts.GetTUFRepoURL(), srv.URL)
	}

	// Repository is initialized, so a target lookup must succeed.
	tc, code, err := ts.GetTarget(context.Background(), srv.URL, "tsa.crt.pem")
	if err != nil {
		t.Fatalf("GetTarget after NewTrustService: %v", err)
	}
	if code != http.StatusOK || !strings.Contains(tc.Content, "BEGIN CERTIFICATE") {
		t.Errorf("unexpected target result: code=%d content=%q", code, tc.Content)
	}
}
