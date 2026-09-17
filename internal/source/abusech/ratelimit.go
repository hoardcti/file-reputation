package abusech

import (
	"context"
	"time"
)

// tokenBucket throttles callers to roughly ratePerSecond Take()s per second.
type tokenBucket struct {
	tokens chan struct{}
	done   chan struct{}
}

// newTokenBucket starts a bucket that refills at ratePerSecond. Call Close
// when done with it to stop the background refill goroutine.
func newTokenBucket(ratePerSecond float64) *tokenBucket {
	tb := &tokenBucket{
		tokens: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	tb.tokens <- struct{}{} // let the first request through immediately

	go func() {
		ticker := time.NewTicker(time.Duration(float64(time.Second) / ratePerSecond))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				select {
				case tb.tokens <- struct{}{}:
				default:
				}
			case <-tb.done:
				return
			}
		}
	}()

	return tb
}

// Take blocks until a token is available or ctx is done.
func (tb *tokenBucket) Take(ctx context.Context) error {
	select {
	case <-tb.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops the bucket's background refill goroutine.
func (tb *tokenBucket) Close() {
	close(tb.done)
}
