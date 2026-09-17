//go:build dev

package devenv

import (
	"log"

	"github.com/joho/godotenv"
)

func Load(path string) error {
	err := godotenv.Load()
	if err != nil {
		log.Printf("load .env: %v", err)
	}

	return err
}
