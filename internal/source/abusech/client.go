// Package abusech downloads malware sample metadata from abuse.ch's MalwareBazaar API and writes
// each sample to disk in hoardCTI's feed.Sample format.
//
// Names starting with a capital letter are exported (visible to other packages). This package
// lives under internal/, so only this module can import it and exporting a name, including every
// SCREAMING_SNAKE_CASE constant, doesn't make it a public API.
package abusech

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Upstream endpoints and how this client identifies itself to them.
const (
	// ABUSECH_API_HOST is the host serving both the MalwareBazaar API and its exports.
	ABUSECH_API_HOST = "mb-api.abuse.ch"

	// API_BASE_URL is the MalwareBazaar API v1 endpoint, which answers get_info queries.
	API_BASE_URL = "https://" + ABUSECH_API_HOST + "/api/v1/"

	// EXPORT_PATH is the path the recent-samples export URL starts with. The API key and
	// EXPORT_FILE_NAME follow it as path segments.
	EXPORT_PATH = "/v2/files/exports"

	// EXPORT_FILE_NAME is the export listing the SHA-256 hashes of recently added samples.
	EXPORT_FILE_NAME = "sha256_recent.txt"

	// USER_AGENT identifies this client to abuse.ch. Its CDN rejects or answers 502 to Go's
	// default "Go-http-client" user agent, especially from CI and cloud IP ranges.
	USER_AGENT = "hoardcti-file-reputation/1.0 (+https://github.com/hoardcti/file-reputation)"

	// REDACTED replaces the API key wherever it would otherwise appear in logs or errors.
	REDACTED = "[REDACTED]"
)

// Defaults for the settings a caller can change with an Option.
const (
	// DEFAULT_HTTP_TIMEOUT bounds each request when the caller doesn't supply an HTTP client.
	DEFAULT_HTTP_TIMEOUT = 30 * time.Second

	// DEFAULT_WORKER_COUNT is how many get_info lookups Aggregate runs at once.
	DEFAULT_WORKER_COUNT = 5

	// DEFAULT_REQUESTS_PER_SECOND is the average request rate shared by all workers, which keeps
	// the client under abuse.ch's API rate limit.
	DEFAULT_REQUESTS_PER_SECOND = 2.0

	// DEFAULT_MAX_RETRIES is how many times a rate-limited (429) or gateway-error (502, 503,
	// 504) response is retried.
	DEFAULT_MAX_RETRIES = 5

	// DEFAULT_INITIAL_BACKOFF is the wait before the first retry. It doubles after each attempt,
	// up to MAX_BACKOFF.
	DEFAULT_INITIAL_BACKOFF = time.Second

	// DEFAULT_OUTPUT_DIRECTORY is where Aggregate writes sample files.
	DEFAULT_OUTPUT_DIRECTORY = "./out"
)

// Fixed limits and file settings.
const (
	// MAX_BACKOFF caps the exponential backoff between retries.
	MAX_BACKOFF = 30 * time.Second

	// MAX_RETRY_AFTER caps the delay an upstream Retry-After header can ask for, so a hostile or
	// broken upstream can't stall a run for hours.
	MAX_RETRY_AFTER = 5 * time.Minute

	// MAX_EXPORT_BYTES bounds the recent-samples export, which normally lists a few thousand
	// 64-character hashes.
	MAX_EXPORT_BYTES = 16 << 20

	// MAX_GET_INFO_RESPONSE_BYTES bounds one get_info response, which is normally a few
	// kilobytes but can carry large vendor reports.
	MAX_GET_INFO_RESPONSE_BYTES = 16 << 20

	// MAX_ERROR_SNIPPET_BYTES bounds how much of an unexpected response body is quoted in an
	// error.
	MAX_ERROR_SNIPPET_BYTES = 512

	// PROGRESS_INTERVAL is how often Aggregate logs how far through the export it is.
	PROGRESS_INTERVAL = 5 * time.Second

	// OUTPUT_DIRECTORY_PERMISSIONS lets anyone read the published output directory.
	OUTPUT_DIRECTORY_PERMISSIONS = 0o755

	// OUTPUT_FILE_PERMISSIONS lets anyone read published sample files.
	OUTPUT_FILE_PERMISSIONS = 0o644

	// SAMPLE_JSON_INDENT is the indentation of published sample files. Changing it rewrites
	// every file in the published data set.
	SAMPLE_JSON_INDENT = "  "
)

// sha256Pattern matches a 64-character hexadecimal SHA-256 digest in either case.
var sha256Pattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// APIKey is an abuse.ch Auth-Key. It redacts itself when logged or printed, so it can't leak into
// logs or error messages by accident; convert it with string(key) only where it's sent.
type APIKey string

// LogValue implements slog.LogValuer so the key never appears in logs.
func (key APIKey) LogValue() slog.Value {
	return slog.StringValue(REDACTED)
}

// String implements fmt.Stringer so the key never appears in formatted output either.
func (key APIKey) String() string {
	return REDACTED
}

// Client talks to abuse.ch's MalwareBazaar API. Build one with New. A Client is safe for
// concurrent use by multiple goroutines.
type Client struct {
	// apiKey authenticates get_info requests and is a path segment of exportURL.
	apiKey APIKey

	// exportURL is the recent-samples export URL. It contains apiKey, so it must never appear in
	// logs or errors.
	exportURL string

	// httpClient sends every request.
	httpClient *http.Client

	// logger receives retries, skipped entries and progress.
	logger *slog.Logger

	// limiter spaces out requests from every worker to stay under abuse.ch's rate limit.
	limiter *rate.Limiter

	// workerCount is how many get_info lookups Aggregate runs at once; at least 1.
	workerCount int

	// requestsPerSecond is the average request rate limiter allows; greater than zero.
	requestsPerSecond float64

	// maxRetries is how many times a retryable response is retried; zero disables retries.
	maxRetries int

	// initialBackoff is the wait before the first retry; greater than zero.
	initialBackoff time.Duration

	// outputDirectory is where Aggregate writes sample files.
	outputDirectory string
}

// Option configures a Client built by New. Options only store values; New validates them after
// applying every option.
type Option func(*Client)

// WithHTTPClient sets the HTTP client used for every request. It defaults to a client with a
// DEFAULT_HTTP_TIMEOUT timeout.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(client *Client) { client.httpClient = httpClient }
}

// WithLogger sets the logger the client reports retries, skipped entries and progress to. It
// defaults to a logger that discards everything.
func WithLogger(logger *slog.Logger) Option {
	return func(client *Client) { client.logger = logger }
}

// WithWorkerCount sets how many get_info lookups Aggregate runs at once. It must be at least 1.
func WithWorkerCount(workerCount int) Option {
	return func(client *Client) { client.workerCount = workerCount }
}

// WithRequestsPerSecond sets the average number of requests sent each second, shared by all
// workers. It must be greater than zero.
func WithRequestsPerSecond(requestsPerSecond float64) Option {
	return func(client *Client) { client.requestsPerSecond = requestsPerSecond }
}

// WithMaxRetries sets how many times a rate-limited (429) or gateway-error (502, 503, 504)
// response is retried. It must not be negative; zero disables retries.
func WithMaxRetries(maxRetries int) Option {
	return func(client *Client) { client.maxRetries = maxRetries }
}

// WithInitialBackoff sets the wait before the first retry, which doubles after each attempt up
// to MAX_BACKOFF. It must be greater than zero.
func WithInitialBackoff(initialBackoff time.Duration) Option {
	return func(client *Client) { client.initialBackoff = initialBackoff }
}

// WithOutputDirectory sets the directory Aggregate writes sample files to. It must not be empty.
func WithOutputDirectory(outputDirectory string) Option {
	return func(client *Client) { client.outputDirectory = outputDirectory }
}

// New builds a Client authenticated with apiKey. It returns an error listing every invalid
// setting. The Client holds no resources of its own, so there's nothing to close.
//
// New accepts zero or more options; inside, options is a []Option.
func New(apiKey APIKey, options ...Option) (*Client, error) {
	// Start from the defaults, then apply each option in order, so a later option wins. The API
	// key is escaped so it stays a single path segment of the export URL.
	exportBaseURL := &url.URL{Scheme: "https", Host: ABUSECH_API_HOST, Path: EXPORT_PATH}
	exportURL := exportBaseURL.JoinPath(url.PathEscape(string(apiKey)), EXPORT_FILE_NAME)
	client := &Client{
		apiKey:            apiKey,
		exportURL:         exportURL.String(),
		httpClient:        &http.Client{Timeout: DEFAULT_HTTP_TIMEOUT},
		logger:            slog.New(slog.DiscardHandler),
		workerCount:       DEFAULT_WORKER_COUNT,
		requestsPerSecond: DEFAULT_REQUESTS_PER_SECOND,
		maxRetries:        DEFAULT_MAX_RETRIES,
		initialBackoff:    DEFAULT_INITIAL_BACKOFF,
		outputDirectory:   DEFAULT_OUTPUT_DIRECTORY,
	}
	for _, option := range options {
		option(client)
	}

	// Check every setting now, so a bad value fails here rather than hanging or crashing a run.
	var problems []error
	if "" == apiKey {
		problems = append(problems, errors.New("API key is required"))
	}
	if nil == client.httpClient {
		problems = append(problems, errors.New("HTTP client must not be nil"))
	}
	if nil == client.logger {
		problems = append(problems, errors.New("logger must not be nil"))
	}
	if client.workerCount < 1 {
		problems = append(problems, fmt.Errorf("worker count must be at least 1, got %d", client.workerCount))
	}
	if client.requestsPerSecond <= 0 {
		problems = append(problems, fmt.Errorf("requests per second must be positive, got %v", client.requestsPerSecond))
	}
	if client.maxRetries < 0 {
		problems = append(problems, fmt.Errorf("max retries must not be negative, got %d", client.maxRetries))
	}
	if client.initialBackoff <= 0 {
		problems = append(problems, fmt.Errorf("initial backoff must be positive, got %v", client.initialBackoff))
	}
	if "" == client.outputDirectory {
		problems = append(problems, errors.New("output directory must not be empty"))
	}
	if err := errors.Join(problems...); nil != err {
		return nil, fmt.Errorf("invalid abuse.ch client settings: %w", err)
	}

	// The limiter allows requestsPerSecond requests per second on average, in bursts of one. It
	// works out waits when asked, so it needs no background goroutine and nothing to close.
	client.limiter = rate.NewLimiter(rate.Limit(client.requestsPerSecond), 1)

	return client, nil
}

// Aggregate downloads abuse.ch's list of recently added SHA-256 hashes, looks up each one with
// GetInfo and writes every sample not already on disk to <output directory>/<sha256>.json. It
// creates the output directory if needed, even when the export lists nothing.
//
// Lookups run concurrently on the client's workers, throttled by its shared rate limiter. A
// failure on one hash doesn't stop the others: every failure is returned, joined together.
// Cancelling ctx stops queueing new hashes and makes in-flight lookups fail.
func (client *Client) Aggregate(ctx context.Context) error {
	// Download the list of hashes first; without it there's nothing to do.
	hashes, err := client.fetchRecentHashes(ctx)
	if nil != err {
		return fmt.Errorf("fetching recent hashes: %w", err)
	}
	client.logger.InfoContext(ctx, "aggregating samples", "sample_count", len(hashes))

	// Every file is written through root, which refuses any name that would escape the output
	// directory, even if a hash were somehow crafted as "../x".
	if err := os.MkdirAll(client.outputDirectory, OUTPUT_DIRECTORY_PERMISSIONS); nil != err {
		return fmt.Errorf("creating output directory: %w", err)
	}
	root, err := os.OpenRoot(client.outputDirectory)
	if nil != err {
		return fmt.Errorf("opening output directory: %w", err)
	}
	// defer runs root.Close when Aggregate returns, on every return path. Nothing is written
	// through the directory handle itself, so its Close error carries no information.
	defer root.Close()

	// Look up and save every hash, then report every failure together so one bad hash doesn't
	// hide the others.
	failures := client.saveAll(ctx, root, hashes)
	client.logger.InfoContext(
		ctx,
		"aggregation finished",
		"sample_count", len(hashes),
		"failure_count", len(failures),
	)

	return errors.Join(failures...)
}

// GetInfo looks up one hash with MalwareBazaar's get_info query. Requests share the client's rate
// limiter, and rate-limited or gateway-error responses are retried with backoff.
//
// A hash MalwareBazaar doesn't know isn't an error; the response's QueryStatus says so. GetInfo
// returns an error for any other HTTP status once retries are used up, and for a body that's too
// large or isn't valid JSON.
func (client *Client) GetInfo(ctx context.Context, hash string) (GetInfoResponse, error) {
	// url.Values encodes the form body, so the hash can't add or change form fields.
	form := url.Values{}
	form.Set("query", "get_info")
	form.Set("hash", hash)
	encodedForm := form.Encode()
	header := http.Header{
		"Auth-Key":     {string(client.apiKey)},
		"Content-Type": {"application/x-www-form-urlencoded"},
	}

	// A request body can only be read once, so every attempt gets a fresh reader over the form.
	requestLogger := client.logger.With("operation", "get_info", "sha256", hash)
	newRequest := func() (*http.Request, error) {
		body := strings.NewReader(encodedForm)
		return http.NewRequestWithContext(ctx, http.MethodPost, API_BASE_URL, body)
	}
	response, err := client.doWithRetry(ctx, requestLogger, header, newRequest)
	if nil != err {
		return GetInfoResponse{}, fmt.Errorf("requesting get_info: %w", err)
	}
	defer response.Body.Close()

	// Anything but 200 is a failure, including a 429 or 5xx that outlasted every retry.
	if http.StatusOK != response.StatusCode {
		return GetInfoResponse{}, unexpectedStatusError(response)
	}

	// Decode the bounded body. Unknown upstream fields are ignored, so new ones can't break runs.
	body, err := readLimited(response.Body, MAX_GET_INFO_RESPONSE_BYTES)
	if nil != err {
		return GetInfoResponse{}, fmt.Errorf("reading get_info response: %w", err)
	}
	var info GetInfoResponse
	if err := json.Unmarshal(body, &info); nil != err {
		return GetInfoResponse{}, fmt.Errorf("decoding get_info response: %w", err)
	}

	return info, nil
}

// fetchRecentHashes downloads the recent-samples export and returns the well-formed SHA-256
// hashes it lists, logging a warning for every malformed line it skips.
func (client *Client) fetchRecentHashes(ctx context.Context) ([]string, error) {
	// Download the export. Its URL contains the API key, which send redacts from errors.
	requestLogger := client.logger.With("operation", "fetch_export")
	newRequest := func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, client.exportURL, nil)
	}
	response, err := client.doWithRetry(ctx, requestLogger, nil, newRequest)
	if nil != err {
		return nil, fmt.Errorf("requesting export: %w", err)
	}
	defer response.Body.Close()

	// Read the bounded body and keep only the lines that are valid hashes.
	if http.StatusOK != response.StatusCode {
		return nil, unexpectedStatusError(response)
	}
	body, err := readLimited(response.Body, MAX_EXPORT_BYTES)
	if nil != err {
		return nil, fmt.Errorf("reading export: %w", err)
	}

	return parseHashList(ctx, client.logger, body), nil
}

// saveAll runs fetchAndSave for every hash on client.workerCount worker goroutines and returns
// every failure. It logs progress every PROGRESS_INTERVAL while the workers run, and returns
// only once every goroutine it started has finished.
func (client *Client) saveAll(ctx context.Context, root *os.Root, hashes []string) []error {
	// A channel passes values between goroutines. jobs is unbuffered, so each send waits until a
	// worker takes the hash, and queueing never gets ahead of the workers.
	jobs := make(chan string)

	var (
		// workersWaitGroup waits for a set of goroutines (the workers) to finish.
		workersWaitGroup sync.WaitGroup

		// failuresMutex lets only one worker at a time append to failures.
		failuresMutex sync.Mutex
		failures      []error

		// completedCount is updated by every worker at once; atomic.Int64 makes each Add safe
		// without a lock.
		completedCount atomic.Int64
	)

	// Report progress from its own goroutine until stopProgress is called below, after the
	// workers finish; progressWaitGroup.Wait then waits for it to return.
	progressContext, stopProgress := context.WithCancel(ctx)
	defer stopProgress()
	var progressWaitGroup sync.WaitGroup
	progressWaitGroup.Go(func() {
		client.reportProgress(progressContext, &completedCount, len(hashes))
	})

	// waitGroup.Go runs each worker in a new goroutine (a lightweight thread managed by Go) and
	// continues without waiting. A worker's range loop ends once jobs is closed and empty. The
	// worker closure shares failures and completedCount with saveAll rather than copying them.
	for range client.workerCount {
		workersWaitGroup.Go(func() {
			for hash := range jobs {
				if err := client.fetchAndSave(ctx, root, hash); nil != err {
					failuresMutex.Lock()
					failures = append(failures, fmt.Errorf("saving sample %q: %w", hash, err))
					failuresMutex.Unlock()
				}
				completedCount.Add(1)
			}
		})
	}

	// Queue every hash, stopping early if ctx is cancelled. Closing jobs tells the workers no
	// more hashes are coming, and each Wait blocks until its goroutines have returned.
	queueErr := queueAll(ctx, jobs, hashes)
	close(jobs)
	workersWaitGroup.Wait()
	stopProgress()
	progressWaitGroup.Wait()

	if nil != queueErr {
		failures = append(failures, fmt.Errorf("queueing hashes: %w", queueErr))
	}

	return failures
}

// reportProgress logs how many of totalCount samples have been processed every
// PROGRESS_INTERVAL, until ctx is cancelled. completedCount is read, never changed.
func (client *Client) reportProgress(
	ctx context.Context,
	completedCount *atomic.Int64,
	totalCount int,
) {
	ticker := time.NewTicker(PROGRESS_INTERVAL)
	defer ticker.Stop()

	// The loop runs until ctx is cancelled. ctx.Done() is a channel that closes when the caller
	// gives up, and select waits for whichever happens first: that, or the next tick.
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			client.logger.InfoContext(
				ctx,
				"aggregation progress",
				"completed_count", completedCount.Load(),
				"total_count", totalCount,
			)
		}
	}
}

// fetchAndSave looks up one hash with GetInfo and writes the translated sample to <hash>.json
// inside root. It does nothing when that file already exists, and logs a warning and skips the
// hash when MalwareBazaar has no details for it. hash must already be a validated SHA-256 hash.
func (client *Client) fetchAndSave(ctx context.Context, root *os.Root, hash string) error {
	// Samples saved by an earlier run are never looked up or overwritten again.
	fileName := hash + ".json"
	_, err := root.Stat(fileName)
	switch {
	case nil == err:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		// Not saved yet; continue below.
	default:
		return fmt.Errorf("checking for an existing sample file: %w", err)
	}

	// Look the hash up. An unknown hash is expected now and then and isn't a failure.
	info, err := client.GetInfo(ctx, hash)
	if nil != err {
		return err
	}
	hasDetails := "ok" == info.QueryStatus && 0 != len(info.Data)
	if !hasDetails {
		client.logger.WarnContext(
			ctx,
			"skipping sample without details",
			"sha256", hash,
			"query_status", info.QueryStatus,
		)
		return nil
	}

	// Encode in the published layout and write it without ever exposing a partial file.
	encoded, err := json.MarshalIndent(info.Data[0].ToSample(), "", SAMPLE_JSON_INDENT)
	if nil != err { // coverage-ignore -- raw JSON fields were validated when decoded, and abuse.ch's four-digit-year timestamps stay within the years JSON can encode.
		return fmt.Errorf("encoding sample: %w", err)
	}

	return writeFileAtomically(root, fileName, encoded)
}

// doWithRetry sends the request built by newRequest, retrying rate-limited and gateway-error
// responses with capped exponential backoff and jitter, and honouring any Retry-After header.
// newRequest is called for every attempt because a request body can only be sent once, and
// header is added to each attempt.
//
// Once the retries are used up it returns the last response like any other, so the caller checks
// its status. The caller must close the returned response's body. Cancelling ctx stops the
// retries.
func (client *Client) doWithRetry(
	ctx context.Context,
	requestLogger *slog.Logger,
	header http.Header,
	newRequest func() (*http.Request, error),
) (*http.Response, error) {
	backoff := client.initialBackoff
	for attempt := range client.maxRetries {
		// Hand back errors and non-retryable responses (including successes) straight away.
		response, err := client.send(ctx, header, newRequest)
		if nil != err {
			return nil, err
		}
		if !isRetryableStatus(response.StatusCode) {
			return response, nil
		}
		// This response is being discarded unread, so its Close error carries no information.
		response.Body.Close()

		// Wait for the delay the upstream asked for, or for the backoff plus random jitter so
		// parallel workers don't retry in lockstep.
		wait := retryDelay(response, backoff+rand.N(backoff))
		requestLogger.WarnContext(
			ctx,
			"retrying request",
			"status_code", response.StatusCode,
			"retry_after", wait,
			"attempt", attempt+1,
			"max_retries", client.maxRetries,
		)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting to retry: %w", ctx.Err())
		}
		backoff = min(2*backoff, MAX_BACKOFF)
	}

	// Every retry is used up: make the last attempt and return whatever it gives back.
	return client.send(ctx, header, newRequest)
}

// send makes one attempt at a request: it waits for the shared rate limiter, builds a fresh
// request with newRequest, adds header and the User-Agent, and sends it. The caller must close
// the returned response's body.
func (client *Client) send(
	ctx context.Context,
	header http.Header,
	newRequest func() (*http.Request, error),
) (*http.Response, error) {
	// Every attempt, retries included, waits its turn with the limiter shared by all workers.
	if err := client.limiter.Wait(ctx); nil != err {
		return nil, fmt.Errorf("waiting for rate limiter: %w", err)
	}

	// Build the request. abuse.ch's CDN rejects Go's default user agent, so always set ours.
	request, err := newRequest()
	if nil != err {
		return nil, fmt.Errorf("building request: %w", err)
	}
	maps.Copy(request.Header, header)
	request.Header.Set("User-Agent", USER_AGENT)

	// Send it. *url.Error embeds the full request URL, and the export URL contains the API key,
	// so blank the key out before the error is wrapped: wrapping copies the error's text. The
	// type assertion's second result, ok, is false instead of a crash when err isn't a
	// *url.Error.
	response, err := client.httpClient.Do(request)
	if nil != err {
		if urlErr, ok := errors.AsType[*url.Error](err); ok {
			escapedAPIKey := url.PathEscape(string(client.apiKey))
			urlErr.URL = strings.ReplaceAll(urlErr.URL, escapedAPIKey, REDACTED)
		}
		return nil, fmt.Errorf("sending request: %w", err)
	}

	return response, nil
}

// queueAll sends each hash on jobs until they're all sent or ctx is cancelled, and returns ctx's
// error in that case.
func queueAll(ctx context.Context, jobs chan<- string, hashes []string) error {
	for _, hash := range hashes {
		// Check first: once ctx is cancelled, a waiting worker and the cancellation would both be
		// ready in the select below, and select picks between ready cases at random.
		if err := ctx.Err(); nil != err {
			return err
		}
		select {
		case jobs <- hash:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// parseHashList returns the well-formed SHA-256 hashes listed in a sha256_recent.txt export
// body, in order. The export uses CRLF line endings and may quote values, so each line is
// trimmed of both. Blank lines and # comments are skipped silently; every other line that
// isn't a hash is skipped with a warning.
func parseHashList(ctx context.Context, logger *slog.Logger, body []byte) []string {
	// strings.Lines is an iterator: the range loop receives the body one line at a time instead
	// of first building a slice of every line.
	var hashes []string
	for line := range strings.Lines(string(body)) {
		hash := strings.Trim(strings.TrimSpace(line), `"`)
		if "" == hash || strings.HasPrefix(hash, "#") {
			continue
		}
		if !isSHA256(hash) {
			logger.WarnContext(ctx, "skipping malformed export line", "line", hash)
			continue
		}
		hashes = append(hashes, hash)
	}

	return hashes
}

// isSHA256 reports whether value is a 64-character hexadecimal SHA-256 digest, in either case.
func isSHA256(value string) bool {
	return sha256Pattern.MatchString(value)
}

// writeFileAtomically writes content to name inside root so readers never see a partial file: it
// writes a temporary file next to name, then renames it over name. The temporary file is
// removed if any step fails.
func writeFileAtomically(root *os.Root, name string, content []byte) (err error) {
	temporaryName := name + ".tmp"
	openFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	file, err := root.OpenFile(temporaryName, openFlags, OUTPUT_FILE_PERMISSIONS)
	if nil != err {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	// This deferred function runs when writeFileAtomically returns, on every return path. err is
	// the named result, so it sees the error being returned and can add the clean-up's error.
	defer func() {
		if nil != err {
			err = errors.Join(err, root.Remove(temporaryName))
		}
	}()

	// Close is where buffered data is flushed and a full disk is reported, so check it too.
	_, writeErr := file.Write(content)
	if err := errors.Join(writeErr, file.Close()); nil != err { // coverage-ignore -- the operating system can't be made to fail a write to, or close of, a regular file on demand.
		return fmt.Errorf("writing temporary file: %w", err)
	}

	if err := root.Rename(temporaryName, name); nil != err {
		return fmt.Errorf("replacing %q: %w", name, err)
	}

	return nil
}

// readLimited reads all of reader, which must hold at most limitBytes bytes. It returns an error
// rather than silently truncating a larger body.
func readLimited(reader io.Reader, limitBytes int64) ([]byte, error) {
	// Read one byte past the limit so an over-long body can be told apart from one exactly at it.
	body, err := io.ReadAll(io.LimitReader(reader, limitBytes+1))
	if nil != err {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if int64(len(body)) > limitBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", limitBytes)
	}

	return body, nil
}

// unexpectedStatusError describes a response whose status the caller can't handle, quoting the
// start of its body because upstreams usually explain a rejection there.
func unexpectedStatusError(response *http.Response) error {
	// The snippet only adds detail to the error, so a failure to read it is ignored (_) on
	// purpose.
	snippet, _ := io.ReadAll(io.LimitReader(response.Body, MAX_ERROR_SNIPPET_BYTES))
	return fmt.Errorf("unexpected HTTP status %d: %q", response.StatusCode, bytes.TrimSpace(snippet))
}

// isRetryableStatus reports whether an HTTP status is worth retrying: rate limiting (429) or a
// transient gateway failure (502, 503, 504), which the CDN in front of abuse.ch returns under
// load and to CI and cloud IP ranges.
func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// retryDelay returns how long to wait before retrying response: the delay its Retry-After header
// asks for, in seconds or as an HTTP date, capped at MAX_RETRY_AFTER; or fallback when the header
// is missing, malformed, negative or in the past.
func retryDelay(response *http.Response, fallback time.Duration) time.Duration {
	retryAfter := response.Header.Get("Retry-After")

	// Cap the seconds before converting, so a huge value can't overflow the duration.
	if seconds, err := strconv.Atoi(retryAfter); nil == err && seconds >= 0 {
		maxSeconds := int(MAX_RETRY_AFTER / time.Second)
		return time.Duration(min(seconds, maxSeconds)) * time.Second
	}
	if date, err := http.ParseTime(retryAfter); nil == err && date.After(time.Now()) {
		return min(time.Until(date), MAX_RETRY_AFTER)
	}

	return fallback
}
