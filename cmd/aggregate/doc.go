// Command aggregate downloads the SHA-256 hashes that abuse.ch's MalwareBazaar added recently,
// looks up each sample's details and writes one JSON file per sample, named <sha256>.json.
// Samples that already have a file are skipped, so repeated runs only add new ones.
//
// Usage:
//
//	aggregate [-out DIR] [-workers N] [-log FORMAT] [-level LEVEL] [-env FILE]
//
// Flags:
//
//	-out      directory samples are written to (default "./out")
//	-workers  number of concurrent sample lookups (default 5)
//	-log      log format, "json" or "text" (default "json")
//	-level    minimum log level: "debug", "info", "warn" or "error" (default "info")
//	-env      optional .env file to load (default ".env")
//
// Environment:
//
//	ABUSECH_API_KEY  required; the abuse.ch Auth-Key
//
// A variable already set in the environment wins over the same name in the .env file. Logs go to
// stderr; the command writes nothing to stdout.
//
// Exit codes: 0 on success, 1 on a runtime failure, 2 on a usage error.
//
// Example:
//
//	ABUSECH_API_KEY=... aggregate -out ./out -log text
package main
