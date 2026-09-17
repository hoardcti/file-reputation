package abusech

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClient_Aggregate(t *testing.T) {
	const (
		knownHash   = "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"
		unknownHash = "3f191c8e0d0f8e5a2d5c515c7868aea3b2e3529222e90a82cc90ed1ba6bcfdb0"
	)

	exportBody := "# abuse.ch MalwareBazaar sha256 hash list\r\n" +
		"\r\n" +
		knownHash + "\r\n" +
		unknownHash + "\r\n" +
		"not-a-valid-hash\r\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case http.MethodGet == r.Method && strings.HasSuffix(r.URL.Path, "/sha256_recent.txt"):
			w.Write([]byte(exportBody))

		case http.MethodPost == r.Method && "/api/v1/" == r.URL.Path:
			if err := r.ParseForm(); nil != err {
				t.Fatalf("server: parsing form: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			switch r.FormValue("hash") {
			case knownHash:
				w.Write([]byte(`{"query_status":"ok","data":[{"sha256_hash":"` + knownHash + `","file_name":"sample.exe"}]}`))
			case unknownHash:
				w.Write([]byte(`{"query_status":"hash_not_found"}`))
			default:
				t.Errorf("server: unexpected hash %q", r.FormValue("hash"))
			}

		default:
			t.Errorf("server: unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	outputDir := t.TempDir()

	c, err := NewClient(
		"test-key",
		WithHTTPClient(testHTTPClient(server.URL)),
		WithOutputDir(outputDir),
		WithWorkers(2),
		WithRateLimit(1000),
	)
	if nil != err {
		t.Fatalf("NewClient: unexpected error: %v", err)
	}
	defer c.Close()

	if err := c.Aggregate(context.Background()); nil != err {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	knownPath := filepath.Join(outputDir, knownHash+".json")
	if _, err := os.Stat(knownPath); nil != err {
		t.Errorf("expected %s to exist: %v", knownPath, err)
	}

	unknownPath := filepath.Join(outputDir, unknownHash+".json")
	if _, err := os.Stat(unknownPath); !os.IsNotExist(err) {
		t.Errorf("expected %s to not exist (hash_not_found should be skipped), stat err: %v", unknownPath, err)
	}
}

func TestClient_Aggregate_SkipsExistingFile(t *testing.T) {
	const knownHash = "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"

	exportBody := knownHash + "\n"

	var getInfoCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case http.MethodGet == r.Method && strings.HasSuffix(r.URL.Path, "/sha256_recent.txt"):
			w.Write([]byte(exportBody))
		case http.MethodPost == r.Method && "/api/v1/" == r.URL.Path:
			getInfoCalls++
			w.Write([]byte(`{"query_status":"ok","data":[{"sha256_hash":"` + knownHash + `"}]}`))
		}
	}))
	defer server.Close()

	outputDir := t.TempDir()
	existingPath := filepath.Join(outputDir, knownHash+".json")
	if err := os.WriteFile(existingPath, []byte(`{"pre":"existing"}`), 0644); nil != err {
		t.Fatalf("seeding existing file: %v", err)
	}

	c, err := NewClient(
		"test-key",
		WithHTTPClient(testHTTPClient(server.URL)),
		WithOutputDir(outputDir),
		WithWorkers(1),
		WithRateLimit(1000),
	)
	if nil != err {
		t.Fatalf("NewClient: unexpected error: %v", err)
	}
	defer c.Close()

	if err := c.Aggregate(context.Background()); nil != err {
		t.Fatalf("Aggregate: unexpected error: %v", err)
	}

	if 0 != getInfoCalls {
		t.Errorf("get_info called %d times, want 0 since the file already exists", getInfoCalls)
	}

	contents, err := os.ReadFile(existingPath)
	if nil != err {
		t.Fatalf("reading existing file: %v", err)
	}
	if `{"pre":"existing"}` != string(contents) {
		t.Errorf("existing file was overwritten: %s", contents)
	}
}
