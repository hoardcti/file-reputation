package abusech

import (
	"net/http"
	"net/url"
)

// rewriteTransport redirects every outgoing request to target, regardless of
// the scheme/host baked into the request's URL, so production code that
// hardcodes abuse.ch's hostnames can still be pointed at an httptest.Server.
type rewriteTransport struct {
	target *url.URL
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme = t.target.Scheme
	out.URL.Host = t.target.Host
	out.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(out)
}

// testHTTPClient returns an *http.Client that transparently redirects every
// request to the given test server's address.
func testHTTPClient(serverURL string) *http.Client {
	target, err := url.Parse(serverURL)
	if nil != err {
		panic(err)
	}
	return &http.Client{Transport: rewriteTransport{target: target}}
}
