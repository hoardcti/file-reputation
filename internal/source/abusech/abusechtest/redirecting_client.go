// Package abusechtest helps tests run the real abusech client against an httptest.Server. Both
// the abusech package's tests and the aggregate command's tests use it, which is why it's a
// package of its own rather than a _test.go file.
package abusechtest

import (
	"net/http"
	"net/http/httptest"
)

// NewRedirectingClient returns an *http.Client that sends every request to server, whatever
// scheme and host the request names, so production code with hard-coded abuse.ch URLs talks to
// the fake upstream instead. server must be a plain HTTP server from httptest.NewServer.
func NewRedirectingClient(server *httptest.Server) *http.Client {
	return &http.Client{
		Transport: redirectingTransport{
			address:   server.Listener.Addr().String(),
			transport: server.Client().Transport,
		},
	}
}

// redirectingTransport rewrites each request's scheme and host to a test server's address.
type redirectingTransport struct {
	// address is the test server's "host:port".
	address string

	// transport sends the rewritten request; it's the test server's own transport.
	transport http.RoundTripper
}

// RoundTrip sends a copy of request to the test server. It implements http.RoundTripper: a Go
// type satisfies an interface just by having the right methods.
func (redirecting redirectingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	redirected := request.Clone(request.Context())
	redirected.URL.Scheme = "http"
	redirected.URL.Host = redirecting.address
	redirected.Host = redirecting.address

	return redirecting.transport.RoundTrip(redirected)
}
