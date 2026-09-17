package abusech

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTokenBucket_Take_ImmediateFirst(t *testing.T) {
	tb := newTokenBucket(1) // 1/sec, slow enough that only the seeded token matters here
	defer tb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := tb.Take(ctx); nil != err {
		t.Fatalf("Take: unexpected error on first call: %v", err)
	}
}

func TestTokenBucket_Take_BlocksUntilContextDone(t *testing.T) {
	tb := newTokenBucket(0.01) // effectively won't refill within the test window
	defer tb.Close()

	// Drain the seeded token.
	if err := tb.Take(context.Background()); nil != err {
		t.Fatalf("Take: unexpected error draining seed token: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	err := tb.Take(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Take: got err %v, want context.DeadlineExceeded", err)
	}
}

func TestTokenBucket_Take_Refills(t *testing.T) {
	tb := newTokenBucket(100) // 10ms interval
	defer tb.Close()

	if err := tb.Take(context.Background()); nil != err {
		t.Fatalf("Take: unexpected error draining seed token: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := tb.Take(ctx); nil != err {
		t.Fatalf("Take: expected the bucket to refill in time, got: %v", err)
	}
}
