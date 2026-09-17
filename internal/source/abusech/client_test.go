package abusech

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Run("empty auth key", func(t *testing.T) {
		if _, err := NewClient(""); nil == err {
			t.Fatal("NewClient(\"\"): expected error, got nil")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		c, err := NewClient("key")
		if nil != err {
			t.Fatalf("NewClient: unexpected error: %v", err)
		}
		defer c.Close()

		if defaultWorkers != c.workers {
			t.Errorf("workers = %d, want %d", c.workers, defaultWorkers)
		}
		if defaultMaxRetries != c.maxRetries {
			t.Errorf("maxRetries = %d, want %d", c.maxRetries, defaultMaxRetries)
		}
		if defaultOutputDir != c.outputDir {
			t.Errorf("outputDir = %q, want %q", c.outputDir, defaultOutputDir)
		}
		if nil == c.limiter {
			t.Error("limiter = nil, want a default rate limiter")
		}
	})

	t.Run("options applied", func(t *testing.T) {
		c, err := NewClient("key", WithWorkers(9), WithMaxRetries(2), WithOutputDir("/tmp/x"))
		if nil != err {
			t.Fatalf("NewClient: unexpected error: %v", err)
		}
		defer c.Close()

		if 9 != c.workers {
			t.Errorf("workers = %d, want 9", c.workers)
		}
		if 2 != c.maxRetries {
			t.Errorf("maxRetries = %d, want 2", c.maxRetries)
		}
		if "/tmp/x" != c.outputDir {
			t.Errorf("outputDir = %q, want /tmp/x", c.outputDir)
		}
	})
}

func TestRetryAfter(t *testing.T) {
	fallback := 3 * time.Second

	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{name: "seconds", header: "5", want: 5 * time.Second},
		{name: "missing", header: "", want: fallback},
		{name: "unparseable", header: "not-a-value", want: fallback},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if "" != tc.header {
				resp.Header.Set("Retry-After", tc.header)
			}
			if got := retryAfter(resp, fallback); got != tc.want {
				t.Fatalf("retryAfter() = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("http-date in the future", func(t *testing.T) {
		future := time.Now().Add(10 * time.Second).UTC()
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Retry-After", future.Format(http.TimeFormat))

		got := retryAfter(resp, fallback)
		if got <= 0 || got > 10*time.Second {
			t.Fatalf("retryAfter() = %v, want roughly <= 10s and > 0", got)
		}
	})
}

func TestClient_GetInfo_OK(t *testing.T) {
	const hash = "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); nil != err {
			t.Fatalf("server: parsing form: %v", err)
		}
		if "get_info" != r.FormValue("query") {
			t.Errorf("server: query = %q, want get_info", r.FormValue("query"))
		}
		if hash != r.FormValue("hash") {
			t.Errorf("server: hash = %q, want %q", r.FormValue("hash"), hash)
		}
		if "test-key" != r.Header.Get("Auth-Key") {
			t.Errorf("server: Auth-Key = %q, want test-key", r.Header.Get("Auth-Key"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"query_status":"ok","data":[{"sha256_hash":"` + hash + `","file_name":"sample.exe"}]}`))
	}))
	defer server.Close()

	c, err := NewClient("test-key", WithHTTPClient(testHTTPClient(server.URL)))
	if nil != err {
		t.Fatalf("NewClient: unexpected error: %v", err)
	}
	defer c.Close()

	info, err := c.GetInfo(context.Background(), hash)
	if nil != err {
		t.Fatalf("GetInfo: unexpected error: %v", err)
	}
	if "ok" != info.QueryStatus {
		t.Errorf("QueryStatus = %q, want ok", info.QueryStatus)
	}
	if 1 != len(info.Data) || hash != info.Data[0].SHA256 {
		t.Errorf("Data = %+v, want one entry for %s", info.Data, hash)
	}
}

func TestClient_GetInfo_RetriesOn429(t *testing.T) {
	const hash = "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"

	var requests int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if 1 == atomic.AddInt64(&requests, 1) {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"query_status":"ok","data":[{"sha256_hash":"` + hash + `"}]}`))
	}))
	defer server.Close()

	c, err := NewClient("test-key", WithHTTPClient(testHTTPClient(server.URL)), WithMaxRetries(2))
	if nil != err {
		t.Fatalf("NewClient: unexpected error: %v", err)
	}
	defer c.Close()

	info, err := c.GetInfo(context.Background(), hash)
	if nil != err {
		t.Fatalf("GetInfo: unexpected error: %v", err)
	}
	if "ok" != info.QueryStatus {
		t.Errorf("QueryStatus = %q, want ok", info.QueryStatus)
	}
	if 2 != atomic.LoadInt64(&requests) {
		t.Errorf("server received %d requests, want 2 (one 429 then one 200)", requests)
	}
}

func TestClient_GetInfo_GivesUpAfterMaxRetries(t *testing.T) {
	const hash = "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"

	var requests int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	c, err := NewClient("test-key", WithHTTPClient(testHTTPClient(server.URL)), WithMaxRetries(1))
	if nil != err {
		t.Fatalf("NewClient: unexpected error: %v", err)
	}
	defer c.Close()

	if _, err := c.GetInfo(context.Background(), hash); nil == err {
		t.Fatal("GetInfo: expected error after exhausting retries, got nil")
	}
	if 2 != atomic.LoadInt64(&requests) {
		t.Errorf("server received %d requests, want 2 (1 initial + 1 retry)", requests)
	}
}

func TestClient_GetInfo_UnexpectedStatus(t *testing.T) {
	const hash = "1e934f76b891d4be57a5ef60fdf52235d10ccada12b061645238cf4f68b02b48"

	var requests int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c, err := NewClient("test-key", WithHTTPClient(testHTTPClient(server.URL)))
	if nil != err {
		t.Fatalf("NewClient: unexpected error: %v", err)
	}
	defer c.Close()

	if _, err := c.GetInfo(context.Background(), hash); nil == err {
		t.Fatal("GetInfo: expected error for 500 response, got nil")
	}
	if 1 != atomic.LoadInt64(&requests) {
		t.Errorf("server received %d requests, want 1 (no retry on non-429 errors)", requests)
	}
}
