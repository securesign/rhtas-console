// Package httpclient builds outbound HTTP clients with bounded connection and
// request times.
package httpclient

import (
	"net"
	"net/http"
	"time"
)

const (
	// DefaultDialTimeout bounds connection attempts of the Default client. It is
	// split across the addresses a host resolves to.
	DefaultDialTimeout = 5 * time.Second
	// DefaultTimeout bounds whole requests of the Default client.
	DefaultTimeout = 60 * time.Second
)

// Default is a shared client for general outbound requests (TUF metadata,
// root.json). It is safe for concurrent use.
var Default = New(DefaultDialTimeout, DefaultTimeout)

// New returns an HTTP client whose connection attempts are bounded by
// dialTimeout and whose whole requests are bounded by timeout.
//
// http.Transport dials without the request deadline, so a client without a
// dialer timeout can spend its entire request budget on a single unreachable
// address. With Dialer.Timeout set, Go splits it across all addresses a host
// resolves to (e.g. the per-zone IPs of a cloud load balancer) and falls back
// to the next one when an address does not answer.
func New(dialTimeout, timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext
	return &http.Client{Timeout: timeout, Transport: transport}
}
