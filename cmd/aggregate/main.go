package main

import (
	"github.com/hoardcti/file-reputation/internal/db"
	"github.com/hoardcti/file-reputation/internal/devenv"
	"log"
)

func main() {
	if err := devenv.Load(".env"); err != nil {
		log.Fatalf("load .env: %v", err)
	}

	if _, err := db.Init(); err != nil {
		log.Fatalf("init db: %v", err)
	}
}
