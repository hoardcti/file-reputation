// Package abusech implements a client for abuse.ch's MalwareBazaar
// file-reputation feed.
package abusech

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hoardcti/file-reputation/internal/network"
)

const (
	// baseURL is abuse.ch's MalwareBazaar API v1 endpoint.
	baseURL = "https://mb-api.abuse.ch/api/v1/"

	// exportURLPrefix precedes "<auth key>/sha256_recent.txt" to form the
	// recent-samples export URL.
	exportURLPrefix = "https://mb-api.abuse.ch/v2/files/exports/"

	// userAgent identifies this client to abuse.ch. Some feeds sit behind a
	// CDN/WAF that blocks or 502s requests carrying Go's default
	// "Go-http-client" user agent, especially from CI/cloud IP ranges.
	userAgent = "hoardcti-file-reputation/1.0 (+https://github.com/hoardcti/file-reputation)"

	// defaultWorkers is how many get_info lookups run concurrently during Aggregate.
	defaultWorkers = 5

	// defaultRateLimit is the max number of get_info requests issued per
	// second, shared across all workers, to stay under abuse.ch's API rate limit.
	defaultRateLimit = 2.0

	// defaultMaxRetries is how many times a rate-limited (429) or transient
	// gateway error (502/503/504) request is retried.
	defaultMaxRetries = 5

	// defaultOutputDir is where Aggregate writes sample JSON files.
	defaultOutputDir = "./out"
)

// Client talks to abuse.ch's MalwareBazaar API.
type Client struct {
	authKey    string
	httpClient *http.Client

	workers    int
	maxRetries int
	outputDir  string

	limiter *tokenBucket
}

// Option configures a Client constructed by NewClient.
type Option func(*Client)

// WithHTTPClient overrides the *http.Client used for requests. It defaults
// to the shared network.Client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) { c.httpClient = httpClient }
}

// WithWorkers sets how many get_info lookups Aggregate runs concurrently.
func WithWorkers(n int) Option {
	return func(c *Client) { c.workers = n }
}

// WithRateLimit sets the max get_info requests issued per second, shared
// across all workers.
func WithRateLimit(perSecond float64) Option {
	return func(c *Client) { c.limiter = newTokenBucket(perSecond) }
}

// WithMaxRetries sets how many times a rate-limited (429) request is retried.
func WithMaxRetries(n int) Option {
	return func(c *Client) { c.maxRetries = n }
}

// WithOutputDir sets where Aggregate writes sample JSON files.
func WithOutputDir(dir string) Option {
	return func(c *Client) { c.outputDir = dir }
}

// NewClient builds a Client authenticated with authKey. Callers should call
// Close when finished with it to release the rate limiter's background goroutine.
func NewClient(authKey string, opts ...Option) (*Client, error) {
	if "" == authKey {
		return nil, fmt.Errorf("abusech: auth key is required")
	}

	c := &Client{
		authKey:    authKey,
		httpClient: network.Client,
		workers:    defaultWorkers,
		maxRetries: defaultMaxRetries,
		outputDir:  defaultOutputDir,
	}

	for _, opt := range opts {
		opt(c)
	}

	if nil == c.limiter {
		c.limiter = newTokenBucket(defaultRateLimit)
	}

	return c, nil
}

// Close releases resources held by the Client.
func (c *Client) Close() {
	c.limiter.Close()
}

// retryableStatus reports whether resp's status code is worth retrying:
// rate limiting (429) or a transient upstream/gateway failure (502/503/504),
// the latter being common from CDNs/WAFs in front of abuse.ch under load or
// when fronting requests from CI/cloud IP ranges.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// retryAfter reports how long to wait before retrying a rate-limited
// response, honoring the Retry-After header (seconds or HTTP-date) when present.
func retryAfter(resp *http.Response, fallback time.Duration) time.Duration {
	if ra := resp.Header.Get("Retry-After"); "" != ra {
		if secs, err := strconv.Atoi(ra); nil == err {
			return time.Duration(secs) * time.Second
		}
		if t, err := http.ParseTime(ra); nil == err {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	return fallback
}

// doWithRetry issues a request built by newReq, throttled by the Client's
// shared rate limiter. It retries on rate limiting or a transient gateway
// error (see retryableStatus) with backoff honoring the Retry-After header
// when present. newReq must build a fresh *http.Request on every call since
// a POST body reader can't be replayed after a failed attempt. The caller
// gets back either a response with a non-retryable status (including a
// successful one) or an error once retries are exhausted; either way it owns
// closing resp.Body.
func (c *Client) doWithRetry(ctx context.Context, label string, newReq func() (*http.Request, error)) (*http.Response, error) {
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		if err := c.limiter.Take(ctx); nil != err {
			return nil, err
		}

		req, err := newReq()
		if nil != err {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := c.httpClient.Do(req)
		if nil != err {
			return nil, fmt.Errorf("abusech: %s: request failed: %w", label, err)
		}

		if !retryableStatus(resp.StatusCode) {
			return resp, nil
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()

		if attempt >= c.maxRetries {
			return nil, fmt.Errorf("abusech: %s: giving up after %d retries, last status %d: %s", label, attempt, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		wait := retryAfter(resp, backoff)
		log.Printf("abusech: %s: status %d, retrying in %s (attempt %d/%d)", label, resp.StatusCode, wait, attempt+1, c.maxRetries)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		backoff *= 2
	}
}

// GetInfo queries the abuse.ch MalwareBazaar API for details about a single
// hash. Requests are throttled by the Client's shared rate limiter, and
// rate-limited or gateway-error responses are retried with backoff.
func (c *Client) GetInfo(ctx context.Context, hash string) (*GetInfoResponse, error) {
	form := url.Values{}
	form.Set("query", "get_info")
	form.Set("hash", hash)
	encodedForm := form.Encode()

	resp, err := c.doWithRetry(ctx, fmt.Sprintf("get_info %s", hash), func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, strings.NewReader(encodedForm))
		if nil != err {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Auth-Key", c.authKey)
		return req, nil
	})
	if nil != err {
		return nil, err
	}
	defer resp.Body.Close()

	if 200 != resp.StatusCode {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("abusech: get_info for %s returned status %d: %s", hash, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	respBody, err := io.ReadAll(resp.Body)
	if nil != err {
		return nil, fmt.Errorf("abusech: reading get_info response for %s: %w", hash, err)
	}

	var info GetInfoResponse
	if err := json.Unmarshal(respBody, &info); nil != err {
		return nil, fmt.Errorf("abusech: parsing get_info response for %s: %w", hash, err)
	}

	return &info, nil
}
