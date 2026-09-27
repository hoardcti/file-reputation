package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hoardcti/file-reputation/internal/source/abusech/abusechtest"
)

// Values shared by the tests in this file.
const (
	// TEST_API_KEY is the API key the tests put in the environment.
	TEST_API_KEY = "test-api-key"

	// KNOWN_HASH is the one sample the fake upstream in TestRunWithHTTPClientSavesSamples knows.
	KNOWN_HASH = "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"
)

// TestRunUsageErrors checks that bad flags and settings are reported as usage errors before any
// work starts. None of these cases reaches the environment, so they run in parallel.
func TestRunUsageErrors(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name       string
		arguments  []string
		wantStderr string
	}{
		{name: "unknown flag", arguments: []string{"-nope"}, wantStderr: "flag provided but not defined: -nope"},
		{name: "positional argument", arguments: []string{"extra"}, wantStderr: `unexpected arguments ["extra"]`},
		{name: "unknown log format", arguments: []string{"-log", "xml"}, wantStderr: `-log must be "json" or "text", got "xml"`},
		{name: "unknown log level", arguments: []string{"-level", "loud"}, wantStderr: "parsing -level"},
		// A directory can be opened but not read as a .env file.
		{name: "unreadable env file", arguments: []string{"-env", "."}, wantStderr: `loading "."`},
	}
	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			arguments := append([]string{"-env", missingFile(subtest)}, testCase.arguments...)
			var stdout, stderr bytes.Buffer
			exitCode := run(subtest.Context(), arguments, &stdout, &stderr)

			if EXIT_USAGE != exitCode {
				subtest.Errorf("run(%q) = %d, want %d", arguments, exitCode, EXIT_USAGE)
			}
			if !strings.Contains(stderr.String(), testCase.wantStderr) {
				subtest.Errorf("run(%q) stderr = %q, want it to contain %q", arguments, stderr.String(), testCase.wantStderr)
			}
			if 0 != stdout.Len() {
				subtest.Errorf("run(%q) stdout = %q, want nothing", arguments, stdout.String())
			}
		})
	}
}

// TestRunHelp checks that -h prints the usage text and succeeds.
func TestRunHelp(test *testing.T) {
	test.Parallel()

	var stdout, stderr bytes.Buffer
	exitCode := run(test.Context(), []string{"-h"}, &stdout, &stderr)

	if EXIT_SUCCESS != exitCode {
		test.Errorf("run(-h) = %d, want %d", exitCode, EXIT_SUCCESS)
	}
	if !strings.Contains(stderr.String(), "-workers") {
		test.Errorf("run(-h) stderr = %q, want the usage text", stderr.String())
	}
}

// TestRunRequiresAPIKey checks that a missing API key is a usage error. It doesn't run in
// parallel because it changes the process environment.
func TestRunRequiresAPIKey(test *testing.T) {
	unsetEnvironmentVariable(test, API_KEY_VARIABLE)

	var stdout, stderr bytes.Buffer
	exitCode := run(test.Context(), []string{"-env", missingFile(test)}, &stdout, &stderr)

	if EXIT_USAGE != exitCode {
		test.Errorf("run() = %d, want %d", exitCode, EXIT_USAGE)
	}
	if !strings.Contains(stderr.String(), "ABUSECH_API_KEY environment variable is required") {
		test.Errorf("run() stderr = %q, want the missing key error", stderr.String())
	}
}

// TestRunRejectsInvalidWorkerCount checks that settings abusech.New rejects are usage errors. It
// doesn't run in parallel because it changes the process environment.
func TestRunRejectsInvalidWorkerCount(test *testing.T) {
	test.Setenv(API_KEY_VARIABLE, TEST_API_KEY)

	var stdout, stderr bytes.Buffer
	exitCode := run(test.Context(), []string{"-env", missingFile(test), "-workers", "0"}, &stdout, &stderr)

	if EXIT_USAGE != exitCode {
		test.Errorf("run(-workers 0) = %d, want %d", exitCode, EXIT_USAGE)
	}
	if !strings.Contains(stderr.String(), "worker count must be at least 1") {
		test.Errorf("run(-workers 0) stderr = %q, want the worker count error", stderr.String())
	}
}

// TestRunLoadsAPIKeyFromEnvFile checks that the API key can come from the .env file. The context
// is cancelled up front, so the run gets past configuration and then fails before sending any
// request, as a runtime failure logged in JSON. It doesn't run in parallel because it changes the
// process environment.
func TestRunLoadsAPIKeyFromEnvFile(test *testing.T) {
	unsetEnvironmentVariable(test, API_KEY_VARIABLE)
	environmentFile := filepath.Join(test.TempDir(), ".env")
	if err := os.WriteFile(environmentFile, []byte(API_KEY_VARIABLE+"="+TEST_API_KEY+"\n"), 0o600); nil != err {
		test.Fatalf("writing the .env file: %v", err)
	}
	ctx, cancel := context.WithCancel(test.Context())
	cancel()

	var stdout, stderr bytes.Buffer
	exitCode := run(ctx, []string{"-env", environmentFile, "-out", test.TempDir()}, &stdout, &stderr)

	if EXIT_FAILURE != exitCode {
		test.Errorf("run() = %d, want %d; stderr = %q", exitCode, EXIT_FAILURE, stderr.String())
	}
	if !strings.Contains(stderr.String(), `"msg":"aggregation failed"`) {
		test.Errorf("run() stderr = %q, want a JSON aggregation failure record", stderr.String())
	}
	if strings.Contains(stderr.String(), TEST_API_KEY) {
		test.Errorf("run() stderr = %q, want the API key kept out of the logs", stderr.String())
	}
}

// TestRunWithHTTPClientSavesSamples checks a complete successful run against a fake upstream,
// with text logs. It doesn't run in parallel because it changes the process environment.
func TestRunWithHTTPClientSavesSamples(test *testing.T) {
	test.Setenv(API_KEY_VARIABLE, TEST_API_KEY)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if http.MethodGet == r.Method {
			io.WriteString(w, KNOWN_HASH+"\n")
			return
		}
		io.WriteString(w, `{"query_status":"ok","data":[{"sha256_hash":"`+KNOWN_HASH+`","file_name":"sample.exe"}]}`)
	}))
	test.Cleanup(server.Close)
	outputDirectory := test.TempDir()
	arguments := []string{"-env", missingFile(test), "-out", outputDirectory, "-log", "text"}

	var stderr bytes.Buffer
	exitCode := runWithHTTPClient(test.Context(), arguments, &stderr, abusechtest.NewRedirectingClient(server))

	if EXIT_SUCCESS != exitCode {
		test.Fatalf("runWithHTTPClient(%q) = %d, want %d; stderr = %q", arguments, exitCode, EXIT_SUCCESS, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outputDirectory, KNOWN_HASH+".json")); nil != err {
		test.Errorf("runWithHTTPClient(%q) didn't write the sample: %v", arguments, err)
	}
	if !strings.Contains(stderr.String(), `msg="aggregation finished"`) {
		test.Errorf("runWithHTTPClient(%q) stderr = %q, want a text log record", arguments, stderr.String())
	}
}

// TestNewHTTPClient checks that the shared client has a timeout, since Go's default client has
// none and a stalled upstream would hang the run.
func TestNewHTTPClient(test *testing.T) {
	test.Parallel()

	if httpClient := newHTTPClient(); HTTP_TIMEOUT != httpClient.Timeout {
		test.Errorf("newHTTPClient().Timeout = %v, want %v", httpClient.Timeout, HTTP_TIMEOUT)
	}
}

// missingFile returns a path in a fresh temporary directory where no file exists, for -env.
func missingFile(testingContext testing.TB) string {
	testingContext.Helper()

	return filepath.Join(testingContext.TempDir(), "missing.env")
}

// unsetEnvironmentVariable removes name from the environment for the rest of the test and
// restores it afterwards. godotenv never overrides a variable that's set, even to "", so the
// variable has to be removed rather than emptied.
func unsetEnvironmentVariable(testingContext testing.TB, name string) {
	testingContext.Helper()

	// Setenv records the current value and restores it when the test ends.
	testingContext.Setenv(name, "")
	if err := os.Unsetenv(name); nil != err {
		testingContext.Fatalf("unsetting %s: %v", name, err)
	}
}
