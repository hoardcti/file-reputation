//go:build !dev

package devenv

// Load is a no-op in production builds, as environment variables are expected to be set externally.
func Load(string) error { return nil }
