package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type ipLimiter struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter implements a constant-space token bucket rate limiter
type RateLimiter struct {
	limiters map[string]*ipLimiter
	mu       sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*ipLimiter),
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
	lim, exists := rl.limiters[ip]
	if !exists {
		// Initialize bucket fully populated
		lim = &ipLimiter{
			tokens:     float64(limit),
			lastRefill: now,
		}
		rl.limiters[ip] = lim
	}

	// Calculate refill based on elapsed time since last refill
	elapsed := now.Sub(lim.lastRefill)
	refill := float64(elapsed) * (float64(limit) / float64(window))
	
	newTokens := lim.tokens + refill
	if newTokens > float64(limit) {
		newTokens = float64(limit)
	}

	lim.lastRefill = now

	if newTokens >= 1.0 {
		lim.tokens = newTokens - 1.0
		return true
	}

	lim.tokens = newTokens
	return false
}

// GetRemaining returns how many requests are remaining for an IP
func (rl *RateLimiter) GetRemaining(ip string, limit int, window time.Duration) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	lim, exists := rl.limiters[ip]
	if !exists {
		return limit
	}

	elapsed := now.Sub(lim.lastRefill)
	refill := float64(elapsed) * (float64(limit) / float64(window))
	newTokens := lim.tokens + refill
	if newTokens > float64(limit) {
		newTokens = float64(limit)
	}

	remaining := int(newTokens)
	if remaining < 0 {
		return 0
	}
	if remaining > limit {
		return limit
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

		for ip, lim := range rl.limiters {
			// Remove IPs with no activity in the last hour
			if now.Sub(lim.lastRefill) > time.Hour {
				delete(rl.limiters, ip)
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
