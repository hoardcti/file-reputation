package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/hoardcti/file-reputation/internal/source/abusech"
)

// Exit codes returned by run.
const (
	// EXIT_SUCCESS means the command completed normally.
	EXIT_SUCCESS = 0

	// EXIT_FAILURE means a runtime failure, such as an upstream or disk error.
	EXIT_FAILURE = 1

	// EXIT_USAGE means invalid flags, arguments or configuration.
	EXIT_USAGE = 2
)

// Configuration names and defaults.
const (
	// API_KEY_VARIABLE is the environment variable holding the abuse.ch Auth-Key.
	API_KEY_VARIABLE = "ABUSECH_API_KEY"

	// DEFAULT_ENV_FILE is the .env file loaded when -env isn't given. It's optional.
	DEFAULT_ENV_FILE = ".env"

	// LOG_FORMAT_JSON selects machine-readable JSON logs, for CI and production.
	LOG_FORMAT_JSON = "json"

	// LOG_FORMAT_TEXT selects human-readable text logs, for local development.
	LOG_FORMAT_TEXT = "text"

	// DEFAULT_LOG_FORMAT is JSON because the command normally runs in CI.
	DEFAULT_LOG_FORMAT = LOG_FORMAT_JSON

	// DEFAULT_LOG_LEVEL is the minimum level logged when -level isn't given.
	DEFAULT_LOG_LEVEL = "info"
)

// Settings of the HTTP client shared by every upstream request.
const (
	// HTTP_TIMEOUT bounds each whole request, including reading the response body.
	HTTP_TIMEOUT = 30 * time.Second

	// MAX_IDLE_CONNECTIONS bounds the idle connections kept open across all hosts.
	MAX_IDLE_CONNECTIONS = 100

	// MAX_IDLE_CONNECTIONS_PER_HOST raises Go's default of 2, which would make the lookup
	// workers keep reconnecting to the one abuse.ch host.
	MAX_IDLE_CONNECTIONS_PER_HOST = 100

	// IDLE_CONNECTION_TIMEOUT is how long an unused connection is kept open for reuse.
	IDLE_CONNECTION_TIMEOUT = 90 * time.Second
)

// configuration holds every setting the command needs, resolved from flags, the environment and
// defaults.
type configuration struct {
	// apiKey authenticates requests to abuse.ch; required.
	apiKey abusech.APIKey

	// outputDirectory is where sample files are written.
	outputDirectory string

	// workerCount is how many lookups run at once; abusech.New checks it's at least 1.
	workerCount int

	// logFormat is LOG_FORMAT_JSON or LOG_FORMAT_TEXT.
	logFormat string

	// logLevel is the minimum level logged.
	logLevel slog.Level
}

// main runs the command and exits with its result. os.Exit skips deferred calls, so nothing else
// happens here.
func main() { // coverage-ignore -- only calls run, which is fully tested.
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command with the given arguments and returns its exit code. The command writes
// nothing to stdout; its output is the sample files, and its logs go to stderr.
func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	// Stop cleanly on Ctrl+C or SIGTERM: ctx is cancelled and in-flight work winds down instead of
	// leaving partial output behind. defer runs stop when run returns, on every return path.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runWithHTTPClient(ctx, arguments, stderr, newHTTPClient())
}

// runWithHTTPClient does everything run does apart from handling signals, sending every upstream
// request through httpClient. It exists so tests can point the whole command at a fake upstream.
func runWithHTTPClient(
	ctx context.Context,
	arguments []string,
	stderr io.Writer,
	httpClient *http.Client,
) int {
	// Resolve and validate every setting before starting any work. -h prints the usage text and
	// counts as success.
	configuration, err := loadConfiguration(arguments, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return EXIT_SUCCESS
	}
	if nil != err {
		fmt.Fprintf(stderr, "aggregate: %v\n", err)
		return EXIT_USAGE
	}

	// Build dependencies once and pass them down.
	logger := newLogger(configuration.logFormat, configuration.logLevel, stderr)
	client, err := abusech.New(
		configuration.apiKey,
		abusech.WithHTTPClient(httpClient),
		abusech.WithLogger(logger),
		abusech.WithWorkerCount(configuration.workerCount),
		abusech.WithOutputDirectory(configuration.outputDirectory),
	)
	if nil != err {
		fmt.Fprintf(stderr, "aggregate: %v\n", err)
		return EXIT_USAGE
	}

	// Do the work and report the outcome once.
	if err := client.Aggregate(ctx); nil != err {
		logger.ErrorContext(ctx, "aggregation failed", "error", err)
		return EXIT_FAILURE
	}

	return EXIT_SUCCESS
}

// loadConfiguration parses arguments as flags, loads the optional .env file and reads the
// environment, returning the validated settings. The flag package reports flag problems and the
// usage text to stderr itself; for -h the returned error wraps flag.ErrHelp.
func loadConfiguration(arguments []string, stderr io.Writer) (configuration, error) {
	// A flag set local to this call, rather than the global one, can be parsed once per test.
	flags := flag.NewFlagSet("aggregate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputDirectory := flags.String("out", abusech.DEFAULT_OUTPUT_DIRECTORY, "directory samples are written to")
	workerCount := flags.Int("workers", abusech.DEFAULT_WORKER_COUNT, "number of concurrent sample lookups")
	logFormat := flags.String("log", DEFAULT_LOG_FORMAT, `log format, "json" or "text"`)
	logLevelName := flags.String("level", DEFAULT_LOG_LEVEL, `minimum log level: "debug", "info", "warn" or "error"`)
	environmentFile := flags.String("env", DEFAULT_ENV_FILE, "optional .env file to load")
	if err := flags.Parse(arguments); nil != err {
		return configuration{}, fmt.Errorf("parsing flags: %w", err)
	}
	if 0 != flags.NArg() {
		return configuration{}, fmt.Errorf("unexpected arguments %q", flags.Args())
	}

	// Load .env when it exists. godotenv.Load never overrides a variable that's already set, so
	// the real environment wins, and in CI the file simply doesn't exist.
	if err := godotenv.Load(*environmentFile); nil != err && !errors.Is(err, fs.ErrNotExist) {
		return configuration{}, fmt.Errorf("loading %q: %w", *environmentFile, err)
	}

	// Validate every setting that nothing later checks.
	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(*logLevelName)); nil != err {
		return configuration{}, fmt.Errorf("parsing -level: %w", err)
	}
	isKnownLogFormat := LOG_FORMAT_JSON == *logFormat || LOG_FORMAT_TEXT == *logFormat
	if !isKnownLogFormat {
		return configuration{}, fmt.Errorf("-log must be %q or %q, got %q", LOG_FORMAT_JSON, LOG_FORMAT_TEXT, *logFormat)
	}
	apiKey := abusech.APIKey(os.Getenv(API_KEY_VARIABLE))
	if "" == apiKey {
		return configuration{}, fmt.Errorf("%s environment variable is required", API_KEY_VARIABLE)
	}

	return configuration{
		apiKey:          apiKey,
		outputDirectory: *outputDirectory,
		workerCount:     *workerCount,
		logFormat:       *logFormat,
		logLevel:        logLevel,
	}, nil
}

// newLogger builds the program's logger, writing to stderr in format (LOG_FORMAT_JSON or
// LOG_FORMAT_TEXT, already validated) at level and above.
func newLogger(format string, level slog.Level, stderr io.Writer) *slog.Logger {
	options := &slog.HandlerOptions{Level: level}
	if LOG_FORMAT_TEXT == format {
		return slog.New(slog.NewTextHandler(stderr, options))
	}

	return slog.New(slog.NewJSONHandler(stderr, options))
}

// newHTTPClient builds the client shared by every upstream request in this run.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: HTTP_TIMEOUT,
		Transport: &http.Transport{
			MaxIdleConns:        MAX_IDLE_CONNECTIONS,
			MaxIdleConnsPerHost: MAX_IDLE_CONNECTIONS_PER_HOST,
			IdleConnTimeout:     IDLE_CONNECTION_TIMEOUT,
			ForceAttemptHTTP2:   true,
		},
	}
}
