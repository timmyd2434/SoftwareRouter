package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request should be allowed based on rate limits
func (rl *RateLimiter) Allow(ip string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	// Get existing requests for this IP
	requests := rl.requests[ip]

	// Filter out old requests
	validRequests := []time.Time{}
	for _, t := range requests {
		if t.After(cutoff) {
			validRequests = append(validRequests, t)
		}
	}

	// Check if limit exceeded
	if len(validRequests) >= limit {
		rl.requests[ip] = validRequests
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	rl.requests[ip] = validRequests

	return true
}

// GetRemaining returns how many requests are remaining for an IP
func (rl *RateLimiter) GetRemaining(ip string, limit int, window time.Duration) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	requests := rl.requests[ip]
	validRequests := []time.Time{}

	for _, t := range requests {
		if t.After(cutoff) {
			validRequests = append(validRequests, t)
		}
	}

	remaining := limit - len(validRequests)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// cleanup periodically removes old entries
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()

		for ip, requests := range rl.requests {
			// Remove IPs with no requests in the last hour
			if len(requests) == 0 {
				delete(rl.requests, ip)
				continue
			}

			lastRequest := requests[len(requests)-1]
			if now.Sub(lastRequest) > time.Hour {
				delete(rl.requests, ip)
			}
		}

		rl.mu.Unlock()
	}
}

// rateLimitMiddleware creates a rate limiting middleware
func rateLimitMiddleware(limiter *RateLimiter, limit int, window time.Duration) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)

			if !limiter.Allow(ip, limit, window) {
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(window).Unix()))
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))

				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}

			remaining := limiter.GetRemaining(ip, limit, window)
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

			next.ServeHTTP(w, r)
		}
	}
}
