package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
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
