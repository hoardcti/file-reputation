package abusech

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// progressInterval is how often Aggregate logs its progress through the batch.
const progressInterval = 5 * time.Second

// Aggregate fetches abuse.ch's recent SHA256 hash export, looks up each
// hash's details via GetInfo, and writes any not already on disk to
// <output dir>/<hash>.json. Lookups run concurrently across a worker pool
// throttled by the Client's shared rate limiter; a failure on one hash does
// not abort the rest of the batch.
func (c *Client) Aggregate(ctx context.Context) error {
	resp, err := c.get(ctx, exportURLPrefix+c.authKey+"/sha256_recent.txt")
	if nil != err {
		return fmt.Errorf("abusech: fetching recent sample export: %w", err)
	}
	defer resp.Body.Close()

	if 200 != resp.StatusCode {
		return fmt.Errorf("abusech: recent sample export returned status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if nil != err {
		return fmt.Errorf("abusech: reading recent sample export: %w", err)
	}

	queue := parseHashList(body)
	total := len(queue)
	log.Printf("abusech: aggregating %d samples", total)

	if err := os.MkdirAll(c.outputDir, 0755); nil != err {
		return fmt.Errorf("abusech: creating output directory: %w", err)
	}

	// Fan the hashes out to a small pool of workers; the Client's shared rate
	// limiter keeps them collectively within abuse.ch's API rate limit.
	jobs := make(chan string)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allErrs []error
	var completed int64

	for i := 0; i < c.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sha256 := range jobs {
				if err := c.fetchAndSave(ctx, sha256); nil != err {
					log.Printf("abusech: %s: %v", sha256, err)
					mu.Lock()
					allErrs = append(allErrs, err)
					mu.Unlock()
				}
				atomic.AddInt64(&completed, 1)
			}
		}()
	}

	// Periodically log how far through the batch the workers are.
	progressDone := make(chan struct{})
	if total > 0 {
		go func() {
			ticker := time.NewTicker(progressInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					done := atomic.LoadInt64(&completed)
					log.Printf("abusech: progress %d/%d (%.1f%%)", done, total, 100*float64(done)/float64(total))
				case <-progressDone:
					return
				}
			}
		}()
	}

	for _, sha256 := range queue {
		jobs <- sha256
	}
	close(jobs)

	wg.Wait()
	close(progressDone)

	log.Printf("abusech: finished %d/%d samples (%d errors)", atomic.LoadInt64(&completed), total, len(allErrs))

	// Return a combined error if any sample failed, without letting one
	// failure abort the rest of the batch.
	return errors.Join(allErrs...)
}

// parseHashList extracts well-formed SHA256 hashes from a sha256_recent.txt
// export body, skipping comments, blank lines, and malformed entries. Each
// line is sanitized since the export uses CRLF line endings and may quote values.
func parseHashList(body []byte) []string {
	lines := strings.Split(string(body), "\n")
	hashes := make([]string, 0, len(lines))
	for _, line := range lines {
		sha256 := strings.Trim(strings.TrimSpace(line), `"`)
		if "" == sha256 || strings.HasPrefix(sha256, "#") {
			continue
		}
		if !isSHA256(sha256) {
			log.Printf("abusech: skipping malformed line in feed: %q", sha256)
			continue
		}
		hashes = append(hashes, sha256)
	}
	return hashes
}

// isSHA256 reports whether s is a well-formed 64-character hex SHA256 hash.
func isSHA256(s string) bool {
	if 64 != len(s) {
		return false
	}
	for _, r := range s {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'f' || 'A' <= r && r <= 'F') {
			return false
		}
	}
	return true
}

// fetchAndSave looks up a single hash via GetInfo and writes its details to
// <output dir>/<hash>.json, skipping hashes that already have a file on disk.
func (c *Client) fetchAndSave(ctx context.Context, sha256 string) error {
	filePath := c.outputDir + "/" + sha256 + ".json"

	// Check if the file already exists to avoid overwriting existing samples.
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		return nil
	}

	info, err := c.GetInfo(ctx, sha256)
	if nil != err {
		return err
	}

	if "ok" != info.QueryStatus || 0 == len(info.Data) {
		log.Printf("abusech: %s: skipped, query_status=%q", sha256, info.QueryStatus)
		return nil
	}

	sampleJSON, err := json.Marshal(info.Data[0].ToSample())
	if nil != err {
		return fmt.Errorf("abusech: marshaling sample %s: %w", sha256, err)
	}

	return os.WriteFile(filePath, sampleJSON, 0644)
}
