// Package prometheus is a minimal client for the instant-query endpoint of the
// Prometheus HTTP API (/api/v1/query), as served by Prometheus, the OpenShift
// Thanos querier and other compatible backends.
package prometheus

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/securesign/rhtas-console/internal/httpclient"
)

// maxResponseBytes bounds how much of a query response is read.
const maxResponseBytes = 10 << 20

// Config configures a Client.
type Config struct {
	// URL is the base URL of the Prometheus-compatible endpoint (http or https).
	URL string
	// TokenPath is a file holding a bearer token, read on every request so
	// rotated (bound) ServiceAccount tokens are picked up. Empty: no token.
	TokenPath string
	// CAPath is an optional PEM bundle added to the system roots to verify the
	// endpoint's TLS certificate. TLS verification is always enabled.
	CAPath string
	// Namespace is sent as the "namespace" URL parameter, which the
	// namespace-scoped (tenancy) Thanos querier port requires. Standard
	// Prometheus ignores it.
	Namespace string
	// Timeout bounds each request.
	Timeout time.Duration
}

// Client queries a Prometheus-compatible endpoint.
type Client struct {
	baseURL   *url.URL
	tokenPath string
	namespace string
	http      *http.Client
}

// Sample is one element of an instant-vector result.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// StatusError is returned when the endpoint answers with a non-2xx status.
type StatusError struct {
	Code int
}

func (e *StatusError) Error() string { return fmt.Sprintf("prometheus returned HTTP %d", e.Code) }

// QueryError is returned when Prometheus rejects or fails a query.
type QueryError struct {
	Type    string
	Message string
}

func (e *QueryError) Error() string {
	return fmt.Sprintf("prometheus query error (%s): %s", e.Type, e.Message)
}

// ErrInvalidResponse is returned when the response cannot be understood.
var ErrInvalidResponse = errors.New("invalid response from prometheus")

// New validates the configuration and returns a Client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid prometheus URL %q: must be an absolute http or https URL", cfg.URL)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	hc := httpclient.New(timeout, timeout)
	if cfg.CAPath != "" {
		pem, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("read prometheus CA bundle: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("prometheus CA bundle %s contains no PEM certificates", cfg.CAPath)
		}
		transport := hc.Transport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{baseURL: u, tokenPath: cfg.TokenPath, namespace: cfg.Namespace, http: hc}, nil
}

// Query runs an instant query and returns its vector result. Scalar results
// are returned as a single sample without labels.
func (c *Client) Query(ctx context.Context, query string) ([]Sample, error) {
	params := url.Values{"query": {query}}
	if c.namespace != "" {
		params.Set("namespace", c.namespace)
	}
	u := c.baseURL.JoinPath("api", "v1", "query")
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.tokenPath != "" {
		token, err := os.ReadFile(c.tokenPath)
		if err != nil {
			return nil, fmt.Errorf("read prometheus token: %w", err)
		}
		if t := strings.TrimSpace(string(token)); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Status    string `json:"status"`
		ErrorType string `json:"errorType"`
		Error     string `json:"error"`
		Data      struct {
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if jsonErr := json.Unmarshal(body, &parsed); jsonErr != nil {
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, &StatusError{Code: resp.StatusCode}
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, jsonErr)
	}
	if parsed.Status == "error" {
		return nil, &QueryError{Type: parsed.ErrorType, Message: parsed.Error}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &StatusError{Code: resp.StatusCode}
	}
	if parsed.Status != "success" {
		return nil, fmt.Errorf("%w: status %q", ErrInvalidResponse, parsed.Status)
	}

	switch parsed.Data.ResultType {
	case "vector":
		var raw []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		}
		if err := json.Unmarshal(parsed.Data.Result, &raw); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}
		out := make([]Sample, 0, len(raw))
		for _, r := range raw {
			v, err := parseValue(r.Value)
			if err != nil {
				return nil, err
			}
			out = append(out, Sample{Labels: r.Metric, Value: v})
		}
		return out, nil
	case "scalar":
		var raw [2]any
		if err := json.Unmarshal(parsed.Data.Result, &raw); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}
		v, err := parseValue(raw)
		if err != nil {
			return nil, err
		}
		return []Sample{{Labels: map[string]string{}, Value: v}}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported result type %q", ErrInvalidResponse, parsed.Data.ResultType)
	}
}

// parseValue decodes a [timestamp, "value"] pair.
func parseValue(v [2]any) (float64, error) {
	s, ok := v[1].(string)
	if !ok {
		return 0, fmt.Errorf("%w: sample value is not a string", ErrInvalidResponse)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: sample value %q", ErrInvalidResponse, s)
	}
	return f, nil
}
