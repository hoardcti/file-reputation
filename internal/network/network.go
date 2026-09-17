package network

import (
	"net/http"
	"time"
)

// Client is a shared HTTP client with a timeout and connection pooling settings.
var Client = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100, // default is 2, which throttles same-host polling
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	},
}
