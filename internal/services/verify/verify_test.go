package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/securesign/rhtas-console/internal/models"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func generateTestCert(t *testing.T, notBefore, notAfter time.Time, subject string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: subject},
		Issuer:                pkix.Name{CommonName: subject},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type certChain struct {
	rootPEM         string
	intermediatePEM string
	leafPEM         string
}

func generateCertChain(t *testing.T) certChain {
	t.Helper()
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)

	// Root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		Issuer:                pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))

	// Intermediate CA
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("intermediate key: %v", err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("intermediate cert: %v", err)
	}
	intCert, _ := x509.ParseCertificate(intDER)
	intPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER}))

	// Leaf
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	return certChain{rootPEM: rootPEM, intermediatePEM: intPEM, leafPEM: leafPEM}
}

func generateTestCertWithSANs(t *testing.T, dnsNames []string, emails []string, ips []net.IP, uris []*url.URL) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "test-san-cert"},
		NotBefore:      now.Add(-1 * time.Hour),
		NotAfter:       now.Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		DNSNames:       dnsNames,
		EmailAddresses: emails,
		IPAddresses:    ips,
		URIs:           uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// ---------------------------------------------------------------------------
// Error classifier tests
// ---------------------------------------------------------------------------

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"generic error", errors.New("something failed"), false},
		{"transport 404", &transport.Error{StatusCode: http.StatusNotFound}, true},
		{"transport 500", &transport.Error{StatusCode: http.StatusInternalServerError}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotFoundError(tt.err); got != tt.want {
				t.Errorf("isNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"contains not found", errors.New("image not found in registry"), true},
		{"contains 404", errors.New("received 404 response"), true},
		{"contains name unknown", errors.New("NAME_UNKNOWN: repository not found"), true},
		{"unrelated error", errors.New("connection timeout"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotFound(tt.err); got != tt.want {
				t.Errorf("isNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"contains unauthorized", errors.New("UNAUTHORIZED: access denied"), true},
		{"contains 401", errors.New("received 401 response"), true},
		{"contains authentication required", errors.New("authentication required for registry"), true},
		{"unrelated error", errors.New("connection timeout"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAuthError(tt.err); got != tt.want {
				t.Errorf("isAuthError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"contains connection refused", errors.New("dial tcp: connection refused"), true},
		{"unrelated error", errors.New("timeout waiting for response"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isConnectionError(tt.err); got != tt.want {
				t.Errorf("isConnectionError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTransparencyLogError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"not enough log entries", errors.New("not enough verified log entries from transparency log"), true},
		{"failed inclusion", errors.New("failed to verify log inclusion"), true},
		{"transparency log verification", errors.New("transparency log verification failed"), true},
		{"unrelated error", errors.New("certificate expired"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransparencyLogError(tt.err); got != tt.want {
				t.Errorf("isTransparencyLogError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Certificate function tests
// ---------------------------------------------------------------------------

func TestParsePEMCertificates(t *testing.T) {
	now := time.Now()
	validPEM := generateTestCert(t, now.Add(-1*time.Hour), now.Add(365*24*time.Hour), "test-cert")

	t.Run("single valid cert", func(t *testing.T) {
		result, err := parsePEMCertificates(validPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 cert, got %d", len(result))
		}
		if result[0].Cert == nil {
			t.Error("Cert should not be nil")
		}
		if result[0].PEM == "" {
			t.Error("PEM should not be empty")
		}
	})

	t.Run("multiple certs", func(t *testing.T) {
		pem2 := generateTestCert(t, now.Add(-1*time.Hour), now.Add(365*24*time.Hour), "cert-two")
		result, err := parsePEMCertificates(validPEM + pem2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Fatalf("expected 2 certs, got %d", len(result))
		}
	})

	t.Run("empty string", func(t *testing.T) {
		result, err := parsePEMCertificates("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected 0 certs, got %d", len(result))
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		result, err := parsePEMCertificates("not a valid PEM block")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected 0 certs for garbage input, got %d", len(result))
		}
	})

	t.Run("corrupt certificate DER", func(t *testing.T) {
		corrupt := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-cert")}))
		_, err := parsePEMCertificates(corrupt)
		if err == nil {
			t.Error("expected error for corrupt DER inside CERTIFICATE block")
		}
	})
}

func TestGetSANFromCert(t *testing.T) {
	uri, _ := url.Parse("https://github.com/login/oauth")

	t.Run("cert with URI SAN", func(t *testing.T) {
		certPEM := generateTestCertWithSANs(t, nil, nil, nil, []*url.URL{uri})
		san, err := getSANFromCert(certPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if san != uri.String() {
			t.Errorf("getSANFromCert() = %q, want %q", san, uri.String())
		}
	})

	t.Run("cert with email SAN", func(t *testing.T) {
		certPEM := generateTestCertWithSANs(t, nil, []string{"user@example.com"}, nil, nil)
		san, err := getSANFromCert(certPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if san != "user@example.com" {
			t.Errorf("getSANFromCert() = %q, want %q", san, "user@example.com")
		}
	})

	t.Run("URI takes priority over email", func(t *testing.T) {
		certPEM := generateTestCertWithSANs(t, nil, []string{"user@example.com"}, nil, []*url.URL{uri})
		san, err := getSANFromCert(certPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if san != uri.String() {
			t.Errorf("getSANFromCert() = %q, want URI %q", san, uri.String())
		}
	})

	t.Run("cert with no supported SAN", func(t *testing.T) {
		certPEM := generateTestCertWithSANs(t, []string{"example.com"}, nil, nil, nil)
		_, err := getSANFromCert(certPEM)
		if err == nil {
			t.Error("expected error for cert with only DNS SAN")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := getSANFromCert("not a valid PEM")
		if err == nil {
			t.Error("expected error for invalid PEM")
		}
	})

	t.Run("non-CERTIFICATE PEM block", func(t *testing.T) {
		block := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")})
		_, err := getSANFromCert(string(block))
		if err == nil {
			t.Error("expected error for non-CERTIFICATE PEM block")
		}
	})
}

func TestIdentifyCertRole(t *testing.T) {
	t.Run("nil cert", func(t *testing.T) {
		got := identifyCertRole(nil)
		if got != models.CertificateRoleUnknown {
			t.Errorf("identifyCertRole(nil) = %q, want %q", got, models.CertificateRoleUnknown)
		}
	})

	chain := generateCertChain(t)

	t.Run("root CA", func(t *testing.T) {
		certs, err := parsePEMCertificates(chain.rootPEM)
		if err != nil {
			t.Fatalf("parse root: %v", err)
		}
		got := identifyCertRole(certs[0].Cert)
		if got != models.CertificateRoleRoot {
			t.Errorf("identifyCertRole(root) = %q, want %q", got, models.CertificateRoleRoot)
		}
	})

	t.Run("intermediate CA", func(t *testing.T) {
		certs, err := parsePEMCertificates(chain.intermediatePEM)
		if err != nil {
			t.Fatalf("parse intermediate: %v", err)
		}
		got := identifyCertRole(certs[0].Cert)
		if got != models.CertificateRoleIntermediate {
			t.Errorf("identifyCertRole(intermediate) = %q, want %q", got, models.CertificateRoleIntermediate)
		}
	})

	t.Run("leaf cert", func(t *testing.T) {
		certs, err := parsePEMCertificates(chain.leafPEM)
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		got := identifyCertRole(certs[0].Cert)
		if got != models.CertificateRoleLeaf {
			t.Errorf("identifyCertRole(leaf) = %q, want %q", got, models.CertificateRoleLeaf)
		}
	})
}

func TestMergeSANs(t *testing.T) {
	uri, _ := url.Parse("https://example.com/path")

	tests := []struct {
		name    string
		dns     []string
		emails  []string
		ips     []net.IP
		uris    []*url.URL
		wantLen int
		wantNil bool
	}{
		{"DNS only", []string{"example.com"}, nil, nil, nil, 1, false},
		{"email only", nil, []string{"a@b.com"}, nil, nil, 1, false},
		{"IP only", nil, nil, []net.IP{net.ParseIP("10.0.0.1")}, nil, 1, false},
		{"URI only", nil, nil, nil, []*url.URL{uri}, 1, false},
		{"mixed", []string{"a.com", "b.com"}, []string{"x@y.com"}, []net.IP{net.ParseIP("1.2.3.4")}, []*url.URL{uri}, 5, false},
		{"no SANs", nil, nil, nil, nil, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				DNSNames:       tt.dns,
				EmailAddresses: tt.emails,
				IPAddresses:    tt.ips,
				URIs:           tt.uris,
			}
			got := mergeSANs(cert)
			if tt.wantNil && got != nil {
				t.Errorf("mergeSANs() = %v, want nil", got)
			}
			if !tt.wantNil && len(got) != tt.wantLen {
				t.Errorf("mergeSANs() returned %d items, want %d", len(got), tt.wantLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Data function tests
// ---------------------------------------------------------------------------

func TestClassifyIdentity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.1", "ip"},
		{"::1", "ip"},
		{"user@example.com", "email"},
		{"https://example.com/path", "uri"},
		{"http://localhost:8080", "uri"},
		{"1.2.3.4.5", "oid"},
		{"CN=test,O=org", "subject"},
		{"example.com", "dns"},
		{"localhost", "other"},
		{"", "other"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.input), func(t *testing.T) {
			if got := classifyIdentity(tt.input); got != tt.want {
				t.Errorf("classifyIdentity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDedupeIdentities(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		got := dedupeIdentities(nil)
		if len(got) != 0 {
			t.Errorf("expected empty, got %d", len(got))
		}
	})

	t.Run("no duplicates", func(t *testing.T) {
		input := []models.ArtifactIdentity{
			{Source: models.San, Type: "uri", Value: "https://a.com"},
			{Source: models.Issuer, Type: "email", Value: "b@c.com"},
		}
		got := dedupeIdentities(input)
		if len(got) != 2 {
			t.Fatalf("expected 2, got %d", len(got))
		}
		if got[0].Id != 0 || got[1].Id != 1 {
			t.Errorf("IDs should be sequential: got %d, %d", got[0].Id, got[1].Id)
		}
	})

	t.Run("all duplicates", func(t *testing.T) {
		input := []models.ArtifactIdentity{
			{Source: models.San, Type: "uri", Value: "https://a.com"},
			{Source: models.San, Type: "uri", Value: "https://a.com"},
			{Source: models.San, Type: "uri", Value: "https://a.com"},
		}
		got := dedupeIdentities(input)
		if len(got) != 1 {
			t.Errorf("expected 1, got %d", len(got))
		}
	})

	t.Run("partial duplicates", func(t *testing.T) {
		input := []models.ArtifactIdentity{
			{Source: models.San, Type: "uri", Value: "https://a.com"},
			{Source: models.Issuer, Type: "email", Value: "b@c.com"},
			{Source: models.San, Type: "uri", Value: "https://a.com"},
			{Source: models.Issuer, Type: "email", Value: "d@e.com"},
		}
		got := dedupeIdentities(input)
		if len(got) != 3 {
			t.Fatalf("expected 3, got %d", len(got))
		}
		for i, id := range got {
			if id.Id != i {
				t.Errorf("got[%d].Id = %d, want %d", i, id.Id, i)
			}
		}
	})
}

func TestComputeTimeCoherenceSummary(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	farPast := now.Add(-48 * time.Hour)
	future := now.Add(1 * time.Hour)

	t.Run("no timestamps", func(t *testing.T) {
		resp := models.VerifyArtifactResponse{}
		got := ComputeTimeCoherenceSummary(resp)
		if got.Status != models.TimeCoherenceSummaryStatusUnknown {
			t.Errorf("status = %q, want %q", got.Status, models.TimeCoherenceSummaryStatusUnknown)
		}
	})

	t.Run("single timestamp", func(t *testing.T) {
		ts := past
		resp := models.VerifyArtifactResponse{
			Signatures: []models.SignatureView{{Timestamp: &ts}},
		}
		got := ComputeTimeCoherenceSummary(resp)
		if got.Status != models.TimeCoherenceSummaryStatusOk {
			t.Errorf("status = %q, want %q", got.Status, models.TimeCoherenceSummaryStatusOk)
		}
	})

	t.Run("two close timestamps", func(t *testing.T) {
		t1 := past
		t2 := past.Add(5 * time.Minute)
		resp := models.VerifyArtifactResponse{
			Signatures:   []models.SignatureView{{Timestamp: &t1}},
			Attestations: []models.AttestationView{{Timestamp: &t2}},
		}
		got := ComputeTimeCoherenceSummary(resp)
		if got.Status != models.TimeCoherenceSummaryStatusOk {
			t.Errorf("status = %q, want %q", got.Status, models.TimeCoherenceSummaryStatusOk)
		}
	})

	t.Run("timestamps more than 24h apart", func(t *testing.T) {
		t1 := farPast
		t2 := past
		resp := models.VerifyArtifactResponse{
			Signatures: []models.SignatureView{
				{Timestamp: &t1},
				{Timestamp: &t2},
			},
		}
		got := ComputeTimeCoherenceSummary(resp)
		if got.Status != models.TimeCoherenceSummaryStatusWarning {
			t.Errorf("status = %q, want %q", got.Status, models.TimeCoherenceSummaryStatusWarning)
		}
	})

	t.Run("future timestamp", func(t *testing.T) {
		ts := future
		resp := models.VerifyArtifactResponse{
			Signatures: []models.SignatureView{{Timestamp: &ts}},
		}
		got := ComputeTimeCoherenceSummary(resp)
		if got.Status != models.TimeCoherenceSummaryStatusError {
			t.Errorf("status = %q, want %q", got.Status, models.TimeCoherenceSummaryStatusError)
		}
	})

	t.Run("nil timestamps skipped", func(t *testing.T) {
		resp := models.VerifyArtifactResponse{
			Signatures: []models.SignatureView{{Timestamp: nil}},
		}
		got := ComputeTimeCoherenceSummary(resp)
		if got.Status != models.TimeCoherenceSummaryStatusUnknown {
			t.Errorf("status = %q, want %q", got.Status, models.TimeCoherenceSummaryStatusUnknown)
		}
	})
}

func TestIsCertChainValid(t *testing.T) {
	t.Run("empty chain", func(t *testing.T) {
		if isCertChainValid(nil) {
			t.Error("expected false for empty chain")
		}
	})

	t.Run("single self-signed cert", func(t *testing.T) {
		now := time.Now()
		certPEM := generateTestCert(t, now.Add(-1*time.Hour), now.Add(365*24*time.Hour), "self-signed")
		chain := []models.ParsedCertificate{{Pem: certPEM, IsCa: true}}
		if !isCertChainValid(chain) {
			t.Error("expected true for valid self-signed cert")
		}
	})

	t.Run("single expired self-signed cert", func(t *testing.T) {
		certPEM := generateTestCert(t, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), "expired")
		chain := []models.ParsedCertificate{{Pem: certPEM, IsCa: true}}
		if isCertChainValid(chain) {
			t.Error("expected false for expired self-signed cert")
		}
	})

	t.Run("valid 3-cert chain", func(t *testing.T) {
		cc := generateCertChain(t)
		chain := []models.ParsedCertificate{
			{Pem: cc.leafPEM},
			{Pem: cc.intermediatePEM, IsCa: true},
			{Pem: cc.rootPEM, IsCa: true},
		}
		if !isCertChainValid(chain) {
			t.Error("expected true for valid 3-cert chain")
		}
	})

	t.Run("invalid PEM in chain", func(t *testing.T) {
		chain := []models.ParsedCertificate{{Pem: "not-a-cert"}}
		if isCertChainValid(chain) {
			t.Error("expected false for invalid PEM")
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
		{"trailing slash difference", "https://example.com/", "https://example.com", true},
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
