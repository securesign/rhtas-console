package prometheus

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const vectorBody = `{"status":"success","data":{"resultType":"vector","result":[
 {"metric":{"code":"200"},"value":[1700000000.1,"12"]},
 {"metric":{"code":"500"},"value":[1700000000.1,"2.6"]}]}}`

func TestQueryVector(t *testing.T) {
	var gotQuery, gotNamespace, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("path = %q, want /api/v1/query", r.URL.Path)
		}
		gotQuery = r.URL.Query().Get("query")
		gotNamespace = r.URL.Query().Get("namespace")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(vectorBody))
	}))
	defer srv.Close()

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{URL: srv.URL + "/", TokenPath: tokenPath, Namespace: "tas"})
	if err != nil {
		t.Fatal(err)
	}
	samples, err := c.Query(context.Background(), `sum by (code) (x)`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotQuery != `sum by (code) (x)` || gotNamespace != "tas" || gotAuth != "Bearer s3cret" {
		t.Errorf("query=%q namespace=%q auth=%q", gotQuery, gotNamespace, gotAuth)
	}
	if len(samples) != 2 || samples[0].Labels["code"] != "200" || samples[0].Value != 12 || samples[1].Value != 2.6 {
		t.Errorf("samples = %+v", samples)
	}
}

func TestQueryScalarAndNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("no Authorization header expected without a token path")
		}
		if r.URL.Query().Has("namespace") {
			t.Error("no namespace parameter expected when Namespace is empty")
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"scalar","result":[1700000000,"7"]}}`))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	samples, err := c.Query(context.Background(), "scalar(1)")
	if err != nil || len(samples) != 1 || samples[0].Value != 7 {
		t.Errorf("samples=%+v err=%v", samples, err)
	}
}

func TestQueryErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		check  func(error) bool
	}{
		{"forbidden plain text", http.StatusForbidden, "Forbidden", func(err error) bool {
			var se *StatusError
			return errors.As(err, &se) && se.Code == http.StatusForbidden
		}},
		{"query rejected", http.StatusBadRequest, `{"status":"error","errorType":"bad_data","error":"parse error"}`, func(err error) bool {
			var qe *QueryError
			return errors.As(err, &qe) && qe.Type == "bad_data"
		}},
		{"invalid json", http.StatusOK, "<html>", func(err error) bool { return errors.Is(err, ErrInvalidResponse) }},
		{"unsupported result", http.StatusOK, `{"status":"success","data":{"resultType":"matrix","result":[]}}`, func(err error) bool {
			return errors.Is(err, ErrInvalidResponse)
		}},
		{"bad value", http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"x"]}]}}`, func(err error) bool {
			return errors.Is(err, ErrInvalidResponse)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			c, err := New(Config{URL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Query(context.Background(), "up"); !tt.check(err) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestQueryTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)

	c, err := New(Config{URL: srv.URL, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query(context.Background(), "up"); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestNewValidation(t *testing.T) {
	for _, u := range []string{"", "thanos:9091", "ftp://x", "http://"} {
		if _, err := New(Config{URL: u}); err == nil {
			t.Errorf("New(%q) should fail", u)
		}
	}
	notPEM := filepath.Join(t.TempDir(), "ca.txt")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{URL: "https://prom", CAPath: notPEM}); err == nil {
		t.Error("a CA bundle without certificates should be rejected")
	}
	if _, err := New(Config{URL: "https://prom", CAPath: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Error("a missing CA bundle should be rejected")
	}
}

// TLS is always verified: a self-signed endpoint fails without its CA and
// works once the CA bundle is configured.
func TestCABundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vectorBody))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query(context.Background(), "up"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("expected a certificate verification error, got %v", err)
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = New(Config{URL: srv.URL, CAPath: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query(context.Background(), "up"); err != nil {
		t.Errorf("query with CA bundle failed: %v", err)
	}
}
