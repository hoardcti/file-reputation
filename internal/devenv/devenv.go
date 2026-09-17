//go:build dev

package devenv

import (
	"log"

	"github.com/joho/godotenv"
)

func Load(path string) error {
	err := godotenv.Load()
	if nil != err {
		log.Printf("load .env: %v", err)
	}

	return err
}
