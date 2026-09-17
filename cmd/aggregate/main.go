package main

import (
	"github.com/hoardcti/file-reputation/internal/devenv"
	"github.com/hoardcti/file-reputation/internal/source/abusech"
	"log"
	"os"
)

func main() {
	// Load environment variables from the .env file in development mode.
	if err := devenv.Load(".env"); nil != err {
		log.Fatalf("load .env: %v", err)
	}

	// Check if the "out" directory exists, and create it if it doesn't.
	_, err := os.Stat("./out")
	if os.IsNotExist(err) {
		err := os.Mkdir("./out", 0755)
		if nil != err {
			log.Fatalf("failed to create 'out' directory: %v", err)
		}
	}

	// Aggregate data from abuse.ch's MalwareBazaar feed.
	if err := abusech.Aggregate(); nil != err {
		log.Fatalf("aggregate: %v", err)
	}

}
