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

	// defaultWorkers is how many get_info lookups run concurrently during Aggregate.
	defaultWorkers = 5

	// defaultRateLimit is the max number of get_info requests issued per
	// second, shared across all workers, to stay under abuse.ch's API rate limit.
	defaultRateLimit = 2.0

	// defaultMaxRetries is how many times a rate-limited (429) get_info
	// request is retried.
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

// get performs an HTTP GET request to the specified URL.
func (c *Client) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if nil != err {
		return nil, err
	}
	return c.httpClient.Do(req)
}

// post performs an HTTP POST request to the specified URL with a
// form-encoded body. Entries in headers override the default Content-Type
// when keys collide.
func (c *Client) post(ctx context.Context, u string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if nil != err {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return c.httpClient.Do(req)
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

// GetInfo queries the abuse.ch MalwareBazaar API for details about a single
// hash. Requests are throttled by the Client's shared rate limiter, and 429
// responses are retried with backoff honoring the Retry-After header.
func (c *Client) GetInfo(ctx context.Context, hash string) (*GetInfoResponse, error) {
	form := url.Values{}
	form.Set("query", "get_info")
	form.Set("hash", hash)

	headers := map[string]string{"Auth-Key": c.authKey}

	backoff := time.Second
	for attempt := 0; ; attempt++ {
		if err := c.limiter.Take(ctx); nil != err {
			return nil, err
		}

		resp, err := c.post(ctx, baseURL, strings.NewReader(form.Encode()), headers)
		if nil != err {
			return nil, fmt.Errorf("abusech: get_info request for %s failed: %w", hash, err)
		}

		// Retry rate-limited requests instead of failing the whole batch.
		if 429 == resp.StatusCode {
			resp.Body.Close()
			if attempt >= c.maxRetries {
				return nil, fmt.Errorf("abusech: rate limit exceeded after %d retries for hash %s", attempt, hash)
			}
			wait := retryAfter(resp, backoff)
			log.Printf("abusech: %s: rate limited (429), retrying in %s (attempt %d/%d)", hash, wait, attempt+1, c.maxRetries)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			backoff *= 2
			continue
		}

		if 200 != resp.StatusCode {
			resp.Body.Close()
			return nil, fmt.Errorf("abusech: get_info for %s returned status code %d", hash, resp.StatusCode)
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if nil != err {
			return nil, fmt.Errorf("abusech: reading get_info response for %s: %w", hash, err)
		}

		var info GetInfoResponse
		if err := json.Unmarshal(respBody, &info); nil != err {
			return nil, fmt.Errorf("abusech: parsing get_info response for %s: %w", hash, err)
		}

		return &info, nil
	}
}
