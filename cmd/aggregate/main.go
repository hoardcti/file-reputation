package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hoardcti/file-reputation/internal/devenv"
	"github.com/hoardcti/file-reputation/internal/source/abusech"
)

func main() {
	// Load environment variables from the .env file in development mode.
	if err := devenv.Load(".env"); nil != err {
		log.Fatalf("load .env: %v", err)
	}

	authKey := os.Getenv("ABUSECH_API_KEY")
	if "" == authKey {
		log.Fatalf("ABUSECH_API_KEY environment variable is not set")
	}

	client, err := abusech.NewClient(authKey)
	if nil != err {
		log.Fatalf("abusech: %v", err)
	}
	defer client.Close()

	// Stop cleanly on Ctrl+C / SIGTERM instead of leaving partial work behind mid-request.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Aggregate data from abuse.ch's MalwareBazaar feed.
	if err := client.Aggregate(ctx); nil != err {
		log.Fatalf("aggregate: %v", err)
	}
}
