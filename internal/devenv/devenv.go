//go:build dev

package devenv

import (
	"github.com/joho/godotenv"
	"log"
)

// Load reads the environment variables from the specified .env file and sets them in the process's environment.
func Load(path string) error {
	err := godotenv.Load()
	if nil != err {
		log.Printf("load .env: %v", err)
	}

	return err
}
