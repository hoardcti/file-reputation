package abusech

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/time/rate"

	"github.com/hoardcti/file-reputation/internal/source/abusech/abusechtest"
)

// Values shared by the tests in this file.
const (
	// TEST_API_KEY is the API key every test client uses; the fake upstream checks for it.
	TEST_API_KEY = "test-api-key"

	// KNOWN_HASH is the sample described by testdata/get_info_full.json.
	KNOWN_HASH = "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"

	// SPARSE_HASH is the sample described by testdata/get_info_sparse.json.
	SPARSE_HASH = "3f191c8e0d0f8e5a2d5c515c7868aea3b2e3529222e90a82cc90ed1ba6bcfdb0"

	// UNKNOWN_HASH is a well-formed hash the fake upstream answers with hash_not_found.
	UNKNOWN_HASH = "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff"
)

// updateGoldenFiles rewrites the golden files in testdata instead of comparing against them.
var updateGoldenFiles = flag.Bool("update", false, "rewrite golden files in testdata")

// TestAPIKeyRedactsItself checks that an APIKey never shows its value in logs or formatted
// output, which is what keeps it out of CI logs and error reports.
func TestAPIKeyRedactsItself(test *testing.T) {
	test.Parallel()

	key := APIKey("secret-key")

	var logOutput bytes.Buffer
	slog.New(slog.NewJSONHandler(&logOutput, nil)).Info("request", "api_key", key)
	if strings.Contains(logOutput.String(), "secret-key") {
		test.Errorf("logged APIKey = %s, want the value redacted", logOutput.String())
	}
	if !strings.Contains(logOutput.String(), REDACTED) {
		test.Errorf("logged APIKey = %s, want it to contain %q", logOutput.String(), REDACTED)
	}
	if got := fmt.Sprint(key); REDACTED != got {
		test.Errorf("fmt.Sprint(APIKey) = %q, want %q", got, REDACTED)
	}
}

// TestNew checks the defaults, that options override them, and that every invalid setting is
// rejected up front instead of failing later in a run.
func TestNew(test *testing.T) {
	test.Parallel()

	test.Run("defaults", func(subtest *testing.T) {
		subtest.Parallel()

		client, err := New(TEST_API_KEY)
		if nil != err {
			subtest.Fatalf("New() error = %v, want nil", err)
		}

		want := "https://mb-api.abuse.ch/v2/files/exports/" + TEST_API_KEY + "/sha256_recent.txt"
		if want != client.exportURL {
			subtest.Errorf("New().exportURL = %q, want %q", client.exportURL, want)
		}
		if DEFAULT_HTTP_TIMEOUT != client.httpClient.Timeout {
			subtest.Errorf("New().httpClient.Timeout = %v, want %v", client.httpClient.Timeout, DEFAULT_HTTP_TIMEOUT)
		}
		if DEFAULT_WORKER_COUNT != client.workerCount {
			subtest.Errorf("New().workerCount = %d, want %d", client.workerCount, DEFAULT_WORKER_COUNT)
		}
		if rate.Limit(DEFAULT_REQUESTS_PER_SECOND) != client.limiter.Limit() {
			subtest.Errorf("New().limiter.Limit() = %v, want %v", client.limiter.Limit(), DEFAULT_REQUESTS_PER_SECOND)
		}
		if DEFAULT_MAX_RETRIES != client.maxRetries {
			subtest.Errorf("New().maxRetries = %d, want %d", client.maxRetries, DEFAULT_MAX_RETRIES)
		}
		if DEFAULT_INITIAL_BACKOFF != client.initialBackoff {
			subtest.Errorf("New().initialBackoff = %v, want %v", client.initialBackoff, DEFAULT_INITIAL_BACKOFF)
		}
		if DEFAULT_OUTPUT_DIRECTORY != client.outputDirectory {
			subtest.Errorf("New().outputDirectory = %q, want %q", client.outputDirectory, DEFAULT_OUTPUT_DIRECTORY)
		}
	})

	test.Run("options override defaults", func(subtest *testing.T) {
		subtest.Parallel()

		httpClient := &http.Client{}
		logger := slog.New(slog.DiscardHandler)
		client, err := New(
			TEST_API_KEY,
			WithHTTPClient(httpClient),
			WithLogger(logger),
			WithWorkerCount(9),
			WithRequestsPerSecond(7),
			WithMaxRetries(0),
			WithInitialBackoff(time.Minute),
			WithOutputDirectory("samples"),
		)
		if nil != err {
			subtest.Fatalf("New() error = %v, want nil", err)
		}

		if httpClient != client.httpClient {
			subtest.Error("New().httpClient isn't the client passed to WithHTTPClient")
		}
		if logger != client.logger {
			subtest.Error("New().logger isn't the logger passed to WithLogger")
		}
		if 9 != client.workerCount {
			subtest.Errorf("New().workerCount = %d, want 9", client.workerCount)
		}
		if 7 != client.limiter.Limit() {
			subtest.Errorf("New().limiter.Limit() = %v, want 7", client.limiter.Limit())
		}
		if 0 != client.maxRetries {
			subtest.Errorf("New().maxRetries = %d, want 0", client.maxRetries)
		}
		if time.Minute != client.initialBackoff {
			subtest.Errorf("New().initialBackoff = %v, want 1m", client.initialBackoff)
		}
		if "samples" != client.outputDirectory {
			subtest.Errorf("New().outputDirectory = %q, want %q", client.outputDirectory, "samples")
		}
	})

	// A key containing "/" must stay one path segment rather than change the export path.
	test.Run("api key is escaped in the export url", func(subtest *testing.T) {
		subtest.Parallel()

		client, err := New("key/with/slashes")
		if nil != err {
			subtest.Fatalf("New() error = %v, want nil", err)
		}

		want := "https://mb-api.abuse.ch/v2/files/exports/key%2Fwith%2Fslashes/sha256_recent.txt"
		if want != client.exportURL {
			subtest.Errorf("New().exportURL = %q, want %q", client.exportURL, want)
		}
	})

	testCases := []struct {
		name    string
		apiKey  APIKey
		option  Option
		wantErr string
	}{
		{name: "empty api key", apiKey: "", option: WithWorkerCount(1), wantErr: "API key is required"},
		{name: "nil http client", apiKey: TEST_API_KEY, option: WithHTTPClient(nil), wantErr: "HTTP client"},
		{name: "nil logger", apiKey: TEST_API_KEY, option: WithLogger(nil), wantErr: "logger"},
		{name: "zero workers", apiKey: TEST_API_KEY, option: WithWorkerCount(0), wantErr: "worker count"},
		{name: "zero request rate", apiKey: TEST_API_KEY, option: WithRequestsPerSecond(0), wantErr: "requests per second"},
		{name: "negative retries", apiKey: TEST_API_KEY, option: WithMaxRetries(-1), wantErr: "max retries"},
		{name: "zero backoff", apiKey: TEST_API_KEY, option: WithInitialBackoff(0), wantErr: "initial backoff"},
		{name: "empty output directory", apiKey: TEST_API_KEY, option: WithOutputDirectory(""), wantErr: "output directory"},
	}
	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			client, err := New(testCase.apiKey, testCase.option)
			if nil == err {
				subtest.Fatalf("New() = %v, nil, want an error containing %q", client, testCase.wantErr)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("New() error = %q, want it to contain %q", err, testCase.wantErr)
			}
		})
	}
}

// TestClientAggregate checks the whole run against a fake upstream: known samples are written
// byte for byte in the published format, and unknown or malformed entries are skipped.
func TestClientAggregate(test *testing.T) {
	test.Parallel()

	exportBody := "# abuse.ch MalwareBazaar sha256 hash list\r\n" +
		"\r\n" +
		KNOWN_HASH + "\r\n" +
		`"` + SPARSE_HASH + `"` + "\r\n" +
		UNKNOWN_HASH + "\r\n" +
		"not-a-valid-hash\r\n"
	server := newFakeUpstream(test, exportBody, map[string]string{
		KNOWN_HASH:  "get_info_full.json",
		SPARSE_HASH: "get_info_sparse.json",
	})
	logger, logOutput := newCapturingLogger()
	client := newTestClient(test, server, WithLogger(logger), WithWorkerCount(2))

	if err := client.Aggregate(test.Context()); nil != err {
		test.Fatalf("Aggregate() error = %v, want nil", err)
	}

	// The written files must match what earlier versions of this module published.
	for hash, fixture := range map[string]string{KNOWN_HASH: "get_info_full", SPARSE_HASH: "get_info_sparse"} {
		written, err := os.ReadFile(filepath.Join(client.outputDirectory, hash+".json"))
		if nil != err {
			test.Errorf("reading the sample written for %s: %v", hash, err)
			continue
		}
		if diff := cmp.Diff(readGoldenFile(test, fixture+".golden.json", written), string(written)); "" != diff {
			test.Errorf("Aggregate() wrote %s.json mismatch (-want +got):\n%s", hash, diff)
		}
	}

	// Nothing else is left in the output directory: no unknown sample and no temporary files.
	entries, err := os.ReadDir(client.outputDirectory)
	if nil != err {
		test.Fatalf("reading the output directory: %v", err)
	}
	if 2 != len(entries) {
		test.Errorf("Aggregate() wrote %d files, want 2: %v", len(entries), entries)
	}

	// The malformed line and the unknown hash are reported as warnings.
	if !hasLogRecord(test, logOutput, "skipping malformed export line", "line", "not-a-valid-hash") {
		test.Errorf("Aggregate() logs = %s, want a warning for the malformed line", logOutput)
	}
	if !hasLogRecord(test, logOutput, "skipping sample without details", "sha256", UNKNOWN_HASH) {
		test.Errorf("Aggregate() logs = %s, want a warning for the unknown hash", logOutput)
	}
}

// TestClientAggregateSkipsExistingFile checks that a sample saved by an earlier run is neither
// looked up nor overwritten.
func TestClientAggregateSkipsExistingFile(test *testing.T) {
	test.Parallel()

	var getInfoRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if http.MethodPost == r.Method {
			getInfoRequests.Add(1)
		}
		io.WriteString(w, KNOWN_HASH+"\n")
	}))
	test.Cleanup(server.Close)
	client := newTestClient(test, server)

	existingPath := filepath.Join(client.outputDirectory, KNOWN_HASH+".json")
	if err := os.WriteFile(existingPath, []byte(`{"pre":"existing"}`), 0o600); nil != err {
		test.Fatalf("seeding the existing sample file: %v", err)
	}

	if err := client.Aggregate(test.Context()); nil != err {
		test.Fatalf("Aggregate() error = %v, want nil", err)
	}

	if 0 != getInfoRequests.Load() {
		test.Errorf("Aggregate() sent %d get_info requests, want 0", getInfoRequests.Load())
	}
	contents, err := os.ReadFile(existingPath)
	if nil != err {
		test.Fatalf("reading the existing sample file: %v", err)
	}
	if `{"pre":"existing"}` != string(contents) {
		test.Errorf("Aggregate() overwrote the existing sample file with %s", contents)
	}
}

// TestClientAggregateRetriesExportOnBadGateway guards against the regression fixed in
// https://github.com/hoardcti/file-reputation/commit/57e8f471: the CDN in front of abuse.ch
// answers CI runners with transient 502s, which must be retried rather than abort the run.
func TestClientAggregateRetriesExportOnBadGateway(test *testing.T) {
	test.Parallel()

	getInfoResponse := readFixture(test, "get_info_full.json")
	var exportRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if http.MethodPost == r.Method {
			w.Write(getInfoResponse)
			return
		}
		if 1 == exportRequests.Add(1) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		io.WriteString(w, KNOWN_HASH+"\n")
	}))
	test.Cleanup(server.Close)
	client := newTestClient(test, server, WithMaxRetries(2))

	if err := client.Aggregate(test.Context()); nil != err {
		test.Fatalf("Aggregate() error = %v, want nil", err)
	}

	if 2 != exportRequests.Load() {
		test.Errorf("Aggregate() sent %d export requests, want 2 (one 502, then one 200)", exportRequests.Load())
	}
	if _, err := os.Stat(filepath.Join(client.outputDirectory, KNOWN_HASH+".json")); nil != err {
		test.Errorf("Aggregate() didn't write the sample after recovering from the 502: %v", err)
	}
}

// TestClientAggregateReportsEveryFailure checks that a failed lookup doesn't stop the others and
// that every failure is returned.
func TestClientAggregateReportsEveryFailure(test *testing.T) {
	test.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if http.MethodPost == r.Method {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		io.WriteString(w, KNOWN_HASH+"\n"+SPARSE_HASH+"\n")
	}))
	test.Cleanup(server.Close)
	client := newTestClient(test, server, WithWorkerCount(1))

	err := client.Aggregate(test.Context())
	if nil == err {
		test.Fatal("Aggregate() error = nil, want the failure of both lookups")
	}
	for _, hash := range []string{KNOWN_HASH, SPARSE_HASH} {
		if !strings.Contains(err.Error(), hash) {
			test.Errorf("Aggregate() error = %q, want it to mention %s", err, hash)
		}
	}
}

// TestClientAggregateWithEmptyExport checks that an empty export still creates the output
// directory, which the publishing workflow expects to exist.
func TestClientAggregateWithEmptyExport(test *testing.T) {
	test.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "# no samples in the last hour\r\n")
	}))
	test.Cleanup(server.Close)
	outputDirectory := filepath.Join(test.TempDir(), "nested", "out")
	client := newTestClient(test, server, WithOutputDirectory(outputDirectory))

	if err := client.Aggregate(test.Context()); nil != err {
		test.Fatalf("Aggregate() error = %v, want nil", err)
	}
	if info, err := os.Stat(outputDirectory); nil != err || !info.IsDir() {
		test.Errorf("Aggregate() didn't create the output directory %q: %v", outputDirectory, err)
	}
}

// TestClientAggregateExportFailures checks each way fetching the export can fail, and that none
// of the errors reveals the API key, which is part of the export URL.
func TestClientAggregateExportFailures(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "status other than 200",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, "  invalid auth key  ")
			},
			wantErr: `unexpected HTTP status 403: "invalid auth key"`,
		},
		{
			// Declaring more bytes than are sent makes the client's read fail part-way through.
			name: "body cut short",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "1000")
				io.WriteString(w, KNOWN_HASH)
			},
			wantErr: "reading export",
		},
	}
	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			server := httptest.NewServer(testCase.handler)
			subtest.Cleanup(server.Close)
			client := newTestClient(subtest, server)

			err := client.Aggregate(subtest.Context())
			if nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("Aggregate() error = %v, want it to contain %q", err, testCase.wantErr)
			}
		})
	}

	// A connection failure produces a *url.Error, whose text embeds the request URL.
	test.Run("connection refused", func(subtest *testing.T) {
		subtest.Parallel()

		server := httptest.NewServer(http.NotFoundHandler())
		client := newTestClient(subtest, server)
		server.Close()

		err := client.Aggregate(subtest.Context())
		if nil == err {
			subtest.Fatal("Aggregate() error = nil, want a connection error")
		}
		if strings.Contains(err.Error(), TEST_API_KEY) {
			subtest.Errorf("Aggregate() error = %q, want the API key redacted", err)
		}
		if !strings.Contains(err.Error(), REDACTED) {
			subtest.Errorf("Aggregate() error = %q, want it to contain %q", err, REDACTED)
		}
	})
}

// TestClientAggregateOutputDirectoryFailures checks that an unusable output directory stops the
// run with a clear error before any lookups.
func TestClientAggregateOutputDirectoryFailures(test *testing.T) {
	test.Parallel()

	// The output path is a regular file, so the directory can't be created.
	test.Run("path is a file", func(subtest *testing.T) {
		subtest.Parallel()

		outputPath := filepath.Join(subtest.TempDir(), "out")
		if err := os.WriteFile(outputPath, nil, 0o600); nil != err {
			subtest.Fatalf("creating the blocking file: %v", err)
		}

		err := newEmptyExportClient(subtest, outputPath).Aggregate(subtest.Context())
		if nil == err || !strings.Contains(err.Error(), "creating output directory") {
			subtest.Errorf("Aggregate() error = %v, want a directory creation error", err)
		}
	})

	// The directory exists but can't be listed, so it can't be opened as a root.
	test.Run("directory is not readable", func(subtest *testing.T) {
		subtest.Parallel()

		outputPath := newRestrictedDirectory(subtest, 0o300)

		err := newEmptyExportClient(subtest, outputPath).Aggregate(subtest.Context())
		if nil == err || !strings.Contains(err.Error(), "opening output directory") {
			subtest.Errorf("Aggregate() error = %v, want a directory opening error", err)
		}
	})
}

// TestClientSaveAllStopsWhenCancelled checks that no hash is queued once ctx is cancelled, and
// that the cancellation is reported.
func TestClientSaveAllStopsWhenCancelled(test *testing.T) {
	test.Parallel()

	client := newTestClient(test, httptest.NewServer(http.NotFoundHandler()))
	root := openTestRoot(test, client.outputDirectory)
	ctx, cancel := context.WithCancel(test.Context())
	cancel()

	failures := client.saveAll(ctx, root, []string{KNOWN_HASH})

	if 1 != len(failures) || !errors.Is(failures[0], context.Canceled) {
		test.Errorf("saveAll() = %v, want one failure wrapping context.Canceled", failures)
	}
}

// TestClientReportProgress checks that progress is logged every PROGRESS_INTERVAL until ctx is
// cancelled. synctest simulates time, so the test doesn't wait for real.
func TestClientReportProgress(test *testing.T) {
	test.Parallel()

	synctest.Test(test, func(bubble *testing.T) {
		logger, logOutput := newCapturingLogger()
		client := &Client{logger: logger}
		var completedCount atomic.Int64
		completedCount.Store(3)

		// go runs reportProgress in a goroutine that stops when cancel is called below; closing
		// done tells the test it has returned. The sleep only advances the bubble's fake clock.
		ctx, cancel := context.WithCancel(bubble.Context())
		done := make(chan struct{})
		go func() {
			client.reportProgress(ctx, &completedCount, 10)
			close(done)
		}()
		time.Sleep(PROGRESS_INTERVAL + time.Second)
		cancel()
		<-done

		records := decodeLogRecords(bubble, logOutput)
		if 1 != len(records) {
			bubble.Fatalf("reportProgress() logged %d records, want 1: %s", len(records), logOutput)
		}
		want := map[string]any{"msg": "aggregation progress", "completed_count": 3.0, "total_count": 10.0}
		for key, wantValue := range want {
			if wantValue != records[0][key] {
				bubble.Errorf("reportProgress() record[%q] = %v, want %v", key, records[0][key], wantValue)
			}
		}
	})
}

// TestClientFetchAndSaveStatFailure checks that a failure to check for an existing file is
// reported, not mistaken for "already saved" or "not saved yet".
func TestClientFetchAndSaveStatFailure(test *testing.T) {
	test.Parallel()

	client := newTestClient(test, httptest.NewServer(http.NotFoundHandler()))
	outputPath := newRestrictedDirectory(test, 0o700)
	root := openTestRoot(test, outputPath)
	// Without search (execute) permission, nothing inside the directory can be looked up.
	if err := os.Chmod(outputPath, 0o600); nil != err {
		test.Fatalf("restricting the output directory: %v", err)
	}

	err := client.fetchAndSave(test.Context(), root, KNOWN_HASH)
	if nil == err || !strings.Contains(err.Error(), "checking for an existing sample file") {
		test.Errorf("fetchAndSave() error = %v, want a file check error", err)
	}
}

// TestClientGetInfo checks that a get_info request carries the query, hash and credentials, and
// that the response is decoded.
func TestClientGetInfo(test *testing.T) {
	test.Parallel()

	server := newFakeUpstream(test, "", map[string]string{KNOWN_HASH: "get_info_full.json"})
	client := newTestClient(test, server)

	info, err := client.GetInfo(test.Context(), KNOWN_HASH)
	if nil != err {
		test.Fatalf("GetInfo(%q) error = %v, want nil", KNOWN_HASH, err)
	}
	if "ok" != info.QueryStatus {
		test.Errorf("GetInfo(%q).QueryStatus = %q, want ok", KNOWN_HASH, info.QueryStatus)
	}
	if 1 != len(info.Data) || KNOWN_HASH != info.Data[0].SHA256 {
		test.Errorf("GetInfo(%q).Data = %+v, want one entry for the hash", KNOWN_HASH, info.Data)
	}
}

// TestClientGetInfoRetries checks which statuses are retried and how many requests are sent.
func TestClientGetInfoRetries(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name         string
		statuses     []int
		maxRetries   int
		wantRequests int64
		wantErr      string
	}{
		{name: "retries rate limiting", statuses: []int{http.StatusTooManyRequests}, maxRetries: 2, wantRequests: 2},
		{name: "retries bad gateway", statuses: []int{http.StatusBadGateway}, maxRetries: 2, wantRequests: 2},
		{
			name:         "gives up after max retries",
			statuses:     []int{http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable},
			maxRetries:   1,
			wantRequests: 2,
			wantErr:      "unexpected HTTP status 503",
		},
		// A 500 isn't a transient gateway failure, so retrying it wouldn't help.
		{
			name:         "doesn't retry server errors",
			statuses:     []int{http.StatusInternalServerError},
			maxRetries:   3,
			wantRequests: 1,
			wantErr:      "unexpected HTTP status 500",
		},
	}
	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			// The server answers with each status in turn, then with the known sample.
			getInfoResponse := readFixture(subtest, "get_info_full.json")
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := int(requests.Add(1))
				if request <= len(testCase.statuses) {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(testCase.statuses[request-1])
					return
				}
				w.Write(getInfoResponse)
			}))
			subtest.Cleanup(server.Close)
			client := newTestClient(subtest, server, WithMaxRetries(testCase.maxRetries))

			_, err := client.GetInfo(subtest.Context(), KNOWN_HASH)

			if testCase.wantRequests != requests.Load() {
				subtest.Errorf("GetInfo() sent %d requests, want %d", requests.Load(), testCase.wantRequests)
			}
			if "" == testCase.wantErr && nil != err {
				subtest.Errorf("GetInfo() error = %v, want nil", err)
			}
			if "" != testCase.wantErr && (nil == err || !strings.Contains(err.Error(), testCase.wantErr)) {
				subtest.Errorf("GetInfo() error = %v, want it to contain %q", err, testCase.wantErr)
			}
		})
	}
}

// TestClientGetInfoRejectsBadBodies checks that a truncated or malformed response body is an
// error rather than an empty result.
func TestClientGetInfoRejectsBadBodies(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "body cut short",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "1000")
				io.WriteString(w, `{"query_status":`)
			},
			wantErr: "reading get_info response",
		},
		{
			name: "invalid json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"query_status":`)
			},
			wantErr: "decoding get_info response",
		},
	}
	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			server := httptest.NewServer(testCase.handler)
			subtest.Cleanup(server.Close)
			client := newTestClient(subtest, server)

			_, err := client.GetInfo(subtest.Context(), KNOWN_HASH)
			if nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("GetInfo() error = %v, want it to contain %q", err, testCase.wantErr)
			}
		})
	}

	// The error from a failed request says which request failed.
	test.Run("connection refused", func(subtest *testing.T) {
		subtest.Parallel()

		server := httptest.NewServer(http.NotFoundHandler())
		client := newTestClient(subtest, server)
		server.Close()

		_, err := client.GetInfo(subtest.Context(), KNOWN_HASH)
		if nil == err || !strings.Contains(err.Error(), "requesting get_info") {
			subtest.Errorf("GetInfo() error = %v, want a request error", err)
		}
	})
}

// TestClientDoWithRetryStops checks each way the retry loop gives up without a response.
func TestClientDoWithRetryStops(test *testing.T) {
	test.Parallel()

	// A request that can't be built is reported, not sent.
	test.Run("request can't be built", func(subtest *testing.T) {
		subtest.Parallel()

		client := newTestClient(subtest, httptest.NewServer(http.NotFoundHandler()))
		newRequest := func() (*http.Request, error) { return nil, errors.New("bad request") }

		_, err := client.doWithRetry(subtest.Context(), client.logger, nil, newRequest)
		if nil == err || !strings.Contains(err.Error(), "building request: bad request") {
			subtest.Errorf("doWithRetry() error = %v, want the build error", err)
		}
	})

	// A cancelled context stops the request before it takes a rate limiter token.
	test.Run("cancelled before sending", func(subtest *testing.T) {
		subtest.Parallel()

		client := newTestClient(subtest, httptest.NewServer(http.NotFoundHandler()))
		ctx, cancel := context.WithCancel(subtest.Context())
		cancel()

		_, err := client.doWithRetry(ctx, client.logger, nil, newExampleRequest(ctx))
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "waiting for rate limiter") {
			subtest.Errorf("doWithRetry() error = %v, want a cancelled rate limiter wait", err)
		}
	})

	// The transport answers 429 asking for a long wait, and cancels ctx as it does, so the
	// cancellation arrives while the client waits to retry.
	test.Run("cancelled while waiting to retry", func(subtest *testing.T) {
		subtest.Parallel()

		ctx, cancel := context.WithCancel(subtest.Context())
		transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			cancel()
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": {"60"}},
				Body:       http.NoBody,
				Request:    request,
			}, nil
		})
		client, err := New(TEST_API_KEY, WithHTTPClient(&http.Client{Transport: transport}), WithRequestsPerSecond(1000))
		if nil != err {
			subtest.Fatalf("New() error = %v, want nil", err)
		}

		_, err = client.doWithRetry(ctx, client.logger, nil, newExampleRequest(ctx))
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "waiting to retry") {
			subtest.Errorf("doWithRetry() error = %v, want a cancelled retry wait", err)
		}
	})
}

// TestQueueAllStopsWhenCancelled checks that queueAll stops waiting for a free worker once ctx is
// cancelled. Nothing ever receives from jobs, so only the cancellation can end the wait; synctest
// runs the one-second delay instantly.
func TestQueueAllStopsWhenCancelled(test *testing.T) {
	test.Parallel()

	synctest.Test(test, func(bubble *testing.T) {
		ctx, cancel := context.WithCancel(bubble.Context())
		time.AfterFunc(time.Second, cancel)

		err := queueAll(ctx, make(chan string), []string{KNOWN_HASH})
		if !errors.Is(err, context.Canceled) {
			bubble.Errorf("queueAll() error = %v, want context.Canceled", err)
		}
	})
}

// TestParseHashList checks that comments, blank lines, quotes and CRLF line endings are handled
// and that malformed lines are skipped with a warning.
func TestParseHashList(test *testing.T) {
	test.Parallel()

	body := "# abuse.ch MalwareBazaar sha256 hash list\r\n" +
		"# Last updated: 2026-09-18\r\n" +
		"\r\n" +
		KNOWN_HASH + "\r\n" +
		`"` + SPARSE_HASH + `"` + "\r\n" +
		"not-a-valid-hash\r\n" +
		"\r\n"
	logger, logOutput := newCapturingLogger()

	got := parseHashList(test.Context(), logger, []byte(body))

	if diff := cmp.Diff([]string{KNOWN_HASH, SPARSE_HASH}, got); "" != diff {
		test.Errorf("parseHashList() mismatch (-want +got):\n%s", diff)
	}
	if !hasLogRecord(test, logOutput, "skipping malformed export line", "line", "not-a-valid-hash") {
		test.Errorf("parseHashList() logs = %s, want a warning for the malformed line", logOutput)
	}
}

// FuzzParseHashList checks that parseHashList never panics and only returns well-formed hashes,
// whatever the export contains.
func FuzzParseHashList(fuzzer *testing.F) {
	fuzzer.Add("# comment\r\n" + KNOWN_HASH + "\r\n")
	fuzzer.Add(`"` + SPARSE_HASH + `"`)
	fuzzer.Add("not-a-valid-hash\n\n")
	fuzzer.Add("")

	fuzzer.Fuzz(func(test *testing.T, body string) {
		for _, hash := range parseHashList(test.Context(), slog.New(slog.DiscardHandler), []byte(body)) {
			if !isSHA256(hash) {
				test.Errorf("parseHashList(%q) returned malformed hash %q", body, hash)
			}
		}
	})
}

// TestIsSHA256 checks hash validation, which guards every file name the client writes.
func TestIsSHA256(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "valid lower case", input: KNOWN_HASH, want: true},
		// abuse.ch sometimes returns upper-case hex, which is still valid.
		{name: "valid upper case", input: strings.ToUpper(KNOWN_HASH), want: true},
		{name: "one character short", input: KNOWN_HASH[1:]},
		{name: "one character long", input: KNOWN_HASH + "a"},
		{name: "non-hex characters", input: "zz" + KNOWN_HASH[2:]},
		{name: "path traversal", input: "../" + KNOWN_HASH[3:]},
		{name: "trailing newline", input: KNOWN_HASH[1:] + "\n"},
		{name: "empty"},
	}
	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if got := isSHA256(testCase.input); testCase.want != got {
				subtest.Errorf("isSHA256(%q) = %v, want %v", testCase.input, got, testCase.want)
			}
		})
	}
}

// TestWriteFileAtomically checks that content replaces the target in one step and that a failure
// leaves neither a partial target nor a temporary file behind.
func TestWriteFileAtomically(test *testing.T) {
	test.Parallel()

	test.Run("writes the file", func(subtest *testing.T) {
		subtest.Parallel()

		directory := subtest.TempDir()
		root := openTestRoot(subtest, directory)

		if err := writeFileAtomically(root, "sample.json", []byte(`{"new":true}`)); nil != err {
			subtest.Fatalf("writeFileAtomically() error = %v, want nil", err)
		}

		entries, err := os.ReadDir(directory)
		if nil != err {
			subtest.Fatalf("reading the directory: %v", err)
		}
		if 1 != len(entries) || "sample.json" != entries[0].Name() {
			subtest.Errorf("writeFileAtomically() left %v, want only sample.json", entries)
		}
		contents, err := os.ReadFile(filepath.Join(directory, "sample.json"))
		if nil != err {
			subtest.Fatalf("reading the written file: %v", err)
		}
		if `{"new":true}` != string(contents) {
			subtest.Errorf("writeFileAtomically() wrote %q, want %q", contents, `{"new":true}`)
		}
	})

	// A directory where the temporary file should go stops it being created.
	test.Run("temporary file can't be created", func(subtest *testing.T) {
		subtest.Parallel()

		directory := subtest.TempDir()
		root := openTestRoot(subtest, directory)
		if err := os.Mkdir(filepath.Join(directory, "sample.json.tmp"), 0o700); nil != err {
			subtest.Fatalf("creating the blocking directory: %v", err)
		}

		err := writeFileAtomically(root, "sample.json", []byte("{}"))
		if nil == err || !strings.Contains(err.Error(), "creating temporary file") {
			subtest.Errorf("writeFileAtomically() error = %v, want a creation error", err)
		}
	})

	// A file can't be renamed over a directory that isn't empty.
	test.Run("target can't be replaced", func(subtest *testing.T) {
		subtest.Parallel()

		directory := subtest.TempDir()
		root := openTestRoot(subtest, directory)
		if err := os.MkdirAll(filepath.Join(directory, "sample.json", "inside"), 0o700); nil != err {
			subtest.Fatalf("creating the blocking directory: %v", err)
		}

		err := writeFileAtomically(root, "sample.json", []byte("{}"))
		if nil == err || !strings.Contains(err.Error(), `replacing "sample.json"`) {
			subtest.Errorf("writeFileAtomically() error = %v, want a rename error", err)
		}
		if _, statErr := os.Stat(filepath.Join(directory, "sample.json.tmp")); !errors.Is(statErr, os.ErrNotExist) {
			subtest.Errorf("writeFileAtomically() left the temporary file behind: %v", statErr)
		}
	})
}

// TestReadLimited checks that a body at the limit is read in full and a longer one is rejected
// rather than silently truncated.
func TestReadLimited(test *testing.T) {
	test.Parallel()

	body, err := readLimited(strings.NewReader("12345"), 5)
	if nil != err || "12345" != string(body) {
		test.Errorf(`readLimited("12345", 5) = %q, %v, want "12345", nil`, body, err)
	}

	body, err = readLimited(strings.NewReader("123456"), 5)
	if nil == err {
		test.Errorf(`readLimited("123456", 5) = %q, nil, want an error`, body)
	}
}

// TestIsRetryableStatus checks that only rate limiting and transient gateway failures are
// retried.
func TestIsRetryableStatus(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{name: "too many requests", statusCode: http.StatusTooManyRequests, want: true},
		{name: "bad gateway", statusCode: http.StatusBadGateway, want: true},
		{name: "service unavailable", statusCode: http.StatusServiceUnavailable, want: true},
		{name: "gateway timeout", statusCode: http.StatusGatewayTimeout, want: true},
		{name: "ok", statusCode: http.StatusOK},
		{name: "forbidden", statusCode: http.StatusForbidden},
		{name: "internal server error", statusCode: http.StatusInternalServerError},
	}
	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if got := isRetryableStatus(testCase.statusCode); testCase.want != got {
				subtest.Errorf("isRetryableStatus(%d) = %v, want %v", testCase.statusCode, got, testCase.want)
			}
		})
	}
}

// TestRetryDelay checks how the Retry-After header is honoured, capped and ignored. It runs in a
// synctest bubble, where the clock is fixed, so HTTP dates give exact delays.
func TestRetryDelay(test *testing.T) {
	test.Parallel()

	synctest.Test(test, func(bubble *testing.T) {
		const fallback = 3 * time.Second
		now := time.Now()

		testCases := []struct {
			name       string
			retryAfter string
			want       time.Duration
		}{
			{name: "seconds", retryAfter: "5", want: 5 * time.Second},
			{name: "zero seconds", retryAfter: "0", want: 0},
			{name: "seconds over the cap", retryAfter: "99999999999", want: MAX_RETRY_AFTER},
			{name: "negative seconds", retryAfter: "-5", want: fallback},
			{name: "missing", want: fallback},
			{name: "malformed", retryAfter: "soon", want: fallback},
			{name: "date in the future", retryAfter: now.Add(10 * time.Second).Format(http.TimeFormat), want: 10 * time.Second},
			{name: "date past the cap", retryAfter: now.Add(time.Hour).Format(http.TimeFormat), want: MAX_RETRY_AFTER},
			{name: "date in the past", retryAfter: now.Add(-time.Minute).Format(http.TimeFormat), want: fallback},
		}
		for _, testCase := range testCases {
			response := &http.Response{Header: http.Header{}}
			if "" != testCase.retryAfter {
				response.Header.Set("Retry-After", testCase.retryAfter)
			}

			if got := retryDelay(response, fallback); testCase.want != got {
				bubble.Errorf("%s: retryDelay(%q) = %v, want %v", testCase.name, testCase.retryAfter, got, testCase.want)
			}
		}
	})
}

// roundTripperFunc lets a plain function act as an HTTP transport in tests.
type roundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls the function itself.
func (roundTrip roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

// newTestClient builds a Client that sends every request to server, with a fresh temporary output
// directory, no real waiting between requests or retries, and any extra options applied last.
func newTestClient(testingContext testing.TB, server *httptest.Server, options ...Option) *Client {
	testingContext.Helper()

	testingContext.Cleanup(server.Close)
	defaults := []Option{
		WithHTTPClient(abusechtest.NewRedirectingClient(server)),
		WithRequestsPerSecond(1000),
		WithInitialBackoff(time.Millisecond),
		WithOutputDirectory(testingContext.TempDir()),
	}
	client, err := New(TEST_API_KEY, append(defaults, options...)...)
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return client
}

// newEmptyExportClient builds a test Client that writes to outputDirectory and whose upstream
// serves an empty export.
func newEmptyExportClient(testingContext testing.TB, outputDirectory string) *Client {
	testingContext.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	return newTestClient(testingContext, server, WithOutputDirectory(outputDirectory))
}

// newFakeUpstream starts an httptest.Server that plays abuse.ch. It serves exportBody for the
// recent-samples export, and answers a get_info query with the testdata fixture named in
// fixturesByHash for the posted hash, or with hash_not_found. It reports any request the real
// client shouldn't send. The server is closed when the test ends.
func newFakeUpstream(test *testing.T, exportBody string, fixturesByHash map[string]string) *httptest.Server {
	test.Helper()

	responsesByHash := make(map[string][]byte, len(fixturesByHash))
	for hash, fixture := range fixturesByHash {
		responsesByHash[hash] = readFixture(test, fixture)
	}
	exportPath := EXPORT_PATH + "/" + TEST_API_KEY + "/" + EXPORT_FILE_NAME

	// The handler runs on the server's goroutines, so it reports problems with Errorf, never
	// Fatalf.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if USER_AGENT != r.Header.Get("User-Agent") {
			test.Errorf("fake upstream: User-Agent = %q, want %q", r.Header.Get("User-Agent"), USER_AGENT)
		}
		switch {
		case http.MethodGet == r.Method && exportPath == r.URL.Path:
			io.WriteString(w, exportBody)
		case http.MethodPost == r.Method && "/api/v1/" == r.URL.Path:
			serveGetInfo(test, w, r, responsesByHash)
		default:
			test.Errorf("fake upstream: unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	test.Cleanup(server.Close)

	return server
}

// serveGetInfo answers one get_info request for newFakeUpstream, checking that it's well formed.
func serveGetInfo(test *testing.T, w http.ResponseWriter, r *http.Request, responsesByHash map[string][]byte) {
	if TEST_API_KEY != r.Header.Get("Auth-Key") {
		test.Errorf("fake upstream: Auth-Key = %q, want %q", r.Header.Get("Auth-Key"), TEST_API_KEY)
	}
	if err := r.ParseForm(); nil != err {
		test.Errorf("fake upstream: parsing form: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if "get_info" != r.PostForm.Get("query") {
		test.Errorf("fake upstream: query = %q, want get_info", r.PostForm.Get("query"))
	}

	response, ok := responsesByHash[r.PostForm.Get("hash")]
	if !ok {
		response = []byte(`{"query_status":"hash_not_found"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// newRestrictedDirectory creates a directory with the given permissions and restores full
// permissions at the end of the test so it can be deleted.
func newRestrictedDirectory(testingContext testing.TB, permissions os.FileMode) string {
	testingContext.Helper()

	directory := filepath.Join(testingContext.TempDir(), "restricted")
	if err := os.Mkdir(directory, permissions); nil != err {
		testingContext.Fatalf("creating the restricted directory: %v", err)
	}
	testingContext.Cleanup(func() {
		if err := os.Chmod(directory, 0o700); nil != err {
			testingContext.Errorf("restoring permissions on %q: %v", directory, err)
		}
	})

	return directory
}

// openTestRoot opens directory as an os.Root that's closed at the end of the test.
func openTestRoot(testingContext testing.TB, directory string) *os.Root {
	testingContext.Helper()

	root, err := os.OpenRoot(directory)
	if nil != err {
		testingContext.Fatalf("opening %q as a root: %v", directory, err)
	}
	testingContext.Cleanup(func() { root.Close() })

	return root
}

// readFixture returns the contents of the named file in testdata.
func readFixture(testingContext testing.TB, name string) []byte {
	testingContext.Helper()

	contents, err := os.ReadFile(filepath.Join("testdata", name))
	if nil != err {
		testingContext.Fatalf("reading fixture %q: %v", name, err)
	}

	return contents
}

// readGoldenFile returns the golden file's contents. With -update, it first rewrites the golden
// file with got.
func readGoldenFile(testingContext testing.TB, name string, got []byte) string {
	testingContext.Helper()

	path := filepath.Join("testdata", name)
	if *updateGoldenFiles {
		if err := os.WriteFile(path, got, 0o600); nil != err {
			testingContext.Fatalf("updating golden file %q: %v", name, err)
		}
	}

	return string(readFixture(testingContext, name))
}

// newCapturingLogger returns a logger that writes JSON records to the returned buffer. slog's
// handlers serialise their writes, so workers can log to it at the same time.
func newCapturingLogger() (*slog.Logger, *bytes.Buffer) {
	var output bytes.Buffer
	return slog.New(slog.NewJSONHandler(&output, nil)), &output
}

// decodeLogRecords decodes every JSON log record in output.
func decodeLogRecords(testingContext testing.TB, output *bytes.Buffer) []map[string]any {
	testingContext.Helper()

	var records []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for decoder.More() {
		var record map[string]any
		if err := decoder.Decode(&record); nil != err {
			testingContext.Fatalf("decoding log output %q: %v", output, err)
		}
		records = append(records, record)
	}

	return records
}

// hasLogRecord reports whether output holds a record with the given message whose attribute key
// has the given value.
func hasLogRecord(testingContext testing.TB, output *bytes.Buffer, message, key, value string) bool {
	testingContext.Helper()

	for _, record := range decodeLogRecords(testingContext, output) {
		if message == record["msg"] && value == record[key] {
			return true
		}
	}

	return false
}

// newExampleRequest returns a request builder for a GET that tests never let reach the network.
func newExampleRequest(ctx context.Context) func() (*http.Request, error) {
	return func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, API_BASE_URL, nil)
	}
}
