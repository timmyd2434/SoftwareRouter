package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// --- Token Management ---

func generateSecureToken(username string) string {
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%s:%d", username, timestamp)

	// HMAC-SHA256: standard construction, immune to length extension attacks
	mac := hmac.New(sha256.New, tokenSecret)
	mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))

	// Format: Bearer sr-<username>-<timestamp>-<signature>
	return fmt.Sprintf("sr-%s-%d-%s", username, timestamp, signature)
}

func verifySecureToken(token string) bool {
	if !strings.HasPrefix(token, "Bearer sr-") {
		return false
	}

	parts := strings.Split(strings.TrimPrefix(token, "Bearer sr-"), "-")
	if len(parts) != 3 {
		return false
	}

	username := parts[0]
	timestampStr := parts[1]
	providedSignature := parts[2]

	// Re-generate signature to verify using HMAC-SHA256
	payload := fmt.Sprintf("%s:%s", username, timestampStr)
	mac := hmac.New(sha256.New, tokenSecret)
	mac.Write([]byte(payload))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// Parse and validate timestamp for expiration
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		log.Printf("SECURITY: Invalid token timestamp format: %v", err)
		return false
	}

	// Check token expiration - 7 days for home router use
	// (compromise between security and convenience for always-on home device)
	tokenAge := time.Now().Unix() - timestamp
	maxAge := int64(7 * 24 * 60 * 60) // 7 days in seconds

	if tokenAge > maxAge {
		log.Printf("SECURITY: Token expired (age: %d seconds, max: %d)", tokenAge, maxAge)
		return false
	}

	if tokenAge < 0 {
		log.Printf("SECURITY: Token timestamp in future - possible clock skew or attack")
		return false
	}

	// Constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(providedSignature), []byte(expectedSignature))
}

// getUsernameFromToken extracts username from the Bearer token
func getUsernameFromToken(r *http.Request) string {
	token := r.Header.Get("Authorization")

	// Extract username from token (token format: "Bearer sr-username-timestamp-signature")
	if !strings.HasPrefix(token, "Bearer ") {
		return "unknown"
	}

	tokenValue := strings.TrimPrefix(token, "Bearer ")
	// Remove "sr-" prefix
	if !strings.HasPrefix(tokenValue, "sr-") {
		return "unknown"
	}

	tokenValue = strings.TrimPrefix(tokenValue, "sr-")
	// Split by "-" to get username-timestamp-signature
	parts := strings.Split(tokenValue, "-")
	if len(parts) >= 3 {
		// Username is the first part
		return parts[0]
	}

	return "unknown"
}

// --- Password Management ---

// Legacy SHA256 hash (for migration only)
func hashPasswordSHA256(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// New bcrypt hash (secure)
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

// Verify password - supports both bcrypt and legacy SHA256
func verifyPassword(password, hash string) bool {
	// Try bcrypt first (starts with $2a$, $2b$, or $2y$)
	if strings.HasPrefix(hash, "$2") {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		return err == nil
	}

	// Fallback to legacy SHA256 (64 hex characters)
	if len(hash) == 64 {
		return hashPasswordSHA256(password) == hash
	}

	return false
}

// --- Credential Storage ---

func loadCredentials() UserCredentials {
	// Root of the system - if nothing exists, we define a highly temporary fallback
	// but warning the user that it should be changed or set on deployment.
	defaultCreds := UserCredentials{
		Username: "admin",
		Password: "", // Empty means NO access by default if file is missing
	}

	// Create directory if not exists
	os.MkdirAll("/etc/softrouter", 0750)

	data, err := os.ReadFile(credentialsFilePath)
	if err != nil {
		fmt.Println("CRITICAL: Credentials file not found. System is locked.")
		return defaultCreds
	}

	var creds UserCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		fmt.Println("CRITICAL: Failed to parse credentials.")
		return defaultCreds
	}
	return creds
}

func saveCredentials(creds UserCredentials) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	// Use 0600 permissions for security (owner read/write only)
	return os.WriteFile(credentialsFilePath, data, 0600)
}

// --- CSRF Protection ---

func generateCSRFToken() string {
	token := uuid.New().String()
	csrfTokens.Store(token, time.Now().Add(csrfExpiryDur))
	return token
}

func validateCSRFToken(token string) bool {
	if token == "" {
		return false
	}

	val, ok := csrfTokens.Load(token)
	if !ok {
		return false
	}

	expiry, ok := val.(time.Time)
	if !ok || time.Now().After(expiry) {
		csrfTokens.Delete(token)
		return false
	}

	return true
}

// Clean up expired CSRF tokens periodically
func cleanupCSRFTokens() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			csrfTokens.Range(func(key, value interface{}) bool {
				if expiry, ok := value.(time.Time); ok && time.Now().After(expiry) {
					csrfTokens.Delete(key)
				}
				return true
			})
		}
	}()
}

// csrfMiddleware validates CSRF tokens for state-changing operations
func csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only check CSRF for state-changing methods
		if r.Method != "GET" && r.Method != "OPTIONS" && r.Method != "HEAD" {
			token := r.Header.Get("X-CSRF-Token")
			if !validateCSRFToken(token) {
				log.Printf("SECURITY: CSRF validation failed from %s for %s %s", r.RemoteAddr, r.Method, r.URL.Path)
				http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

// --- Auth Middleware ---

// Simple token based auth middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")

		if token == "" || !verifySecureToken(token) {
			http.Error(w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
			return
		}

		tokenValue := strings.TrimPrefix(token, "Bearer ")
		if !sessionStore.ValidateSession(tokenValue) {
			http.Error(w, "Unauthorized: Session expired or logged out", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// --- HTTP Handlers ---

func login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	storedCreds := loadCredentials()

	// Check Rate Limit
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	loginMu.Lock()
	if banTime, banned := loginBanUntil[ip]; banned {
		if time.Now().Before(banTime) {
			loginMu.Unlock()
			time.Sleep(2 * time.Second) // Tarpit
			http.Error(w, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
			return
		}
		delete(loginBanUntil, ip) // Expired ban
		delete(loginAttempts, ip)
	}
	loginMu.Unlock()

	if req.Username == storedCreds.Username && verifyPassword(req.Password, storedCreds.Password) {
		// Success
		loginMu.Lock()
		delete(loginAttempts, ip)
		loginMu.Unlock()

		// Auto-migrate from SHA256 to bcrypt if needed
		if len(storedCreds.Password) == 64 { // SHA256 hash detected
			log.Printf("Auto-migrating password for user %s to bcrypt", req.Username)
			newHash, err := hashPassword(req.Password)
			if err == nil {
				storedCreds.Password = newHash
				if err := saveCredentials(storedCreds); err != nil {
					log.Printf("WARNING: Failed to migrate password: %v", err)
				} else {
					log.Printf("Password successfully migrated to bcrypt for user %s", req.Username)
				}
			}
		}

		token := generateSecureToken(req.Username)
		// Return just the part after "Bearer " for client storage
		tokenValue := strings.TrimPrefix(token, "Bearer ")

		// Track session
		userAgent := r.Header.Get("User-Agent")
		sessionStore.AddSession(tokenValue, req.Username, ip, userAgent)
		log.Printf("Session created for user %s (IP: %s, token: %s...)", req.Username, ip, tokenValue[:20])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token":   tokenValue,
			"message": "Login successful",
			"user":    req.Username,
		})
		// Log successful login
		logAuditEvent(req.Username, "login", "success",
			fmt.Sprintf("{\"ip\":\"%s\"}", ip), ip, true)
		return
	}

	// Failure
	loginMu.Lock()
	loginAttempts[ip]++
	if loginAttempts[ip] >= 5 {
		loginBanUntil[ip] = time.Now().Add(15 * time.Minute)
		log.Printf("Banned IP %s due to excessive login failures", ip)

		// Notify on brute force detection
		SendNotification(NotificationEvent{
			Type:     "brute_force_detected",
			Severity: "critical",
			Title:    fmt.Sprintf("IP %s banned — excessive login failures", ip),
			Details:  fmt.Sprintf("IP address %s has been banned for 15 minutes after %d failed login attempts. Target username: %s", ip, loginAttempts[ip], req.Username),
		})
	}
	loginMu.Unlock()

	time.Sleep(2 * time.Second)
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	logAuditEvent(req.Username, "login", "failure",
		fmt.Sprintf("{\"ip\":\"%s\"}", ip), ip, false)
}

// logout handler for session management (Tier 4 improvement)
// Client-side logout - server remains stateless
func logout(w http.ResponseWriter, r *http.Request) {
	// Extract IP for audit logging
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Extract username from token for logging
	username := getUsernameFromToken(r)

	token := r.Header.Get("Authorization")
	if token != "" {
		tokenValue := strings.TrimPrefix(token, "Bearer ")
		sessionStore.DeleteSession(tokenValue)
	}

	logAuditEvent(username, "logout", "success",
		fmt.Sprintf("{\"ip\":\"%s\"}", ip), ip, true)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	}); err != nil {
		log.Printf("ERROR: Failed to encode logout response: %v", err)
	}
}

func updateCredentials(w http.ResponseWriter, r *http.Request) {
	var req UpdateCredsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	storedCreds := loadCredentials()
	if !verifyPassword(req.CurrentPassword, storedCreds.Password) {
		logAuditEvent(getUsernameFromToken(r), "credentials.update", "password",
			"{\"error\":\"incorrect current password\"}", getClientIP(r), false)
		http.Error(w, "Incorrect current password", http.StatusUnauthorized)
		return
	}

	// Hash password with bcrypt
	newHash, err := hashPassword(req.NewPassword)
	if err != nil {
		logAuditEvent(getUsernameFromToken(r), "credentials.update", "password",
			fmt.Sprintf("{\"error\":\"%s\"}", err.Error()), getClientIP(r), false)
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	newCreds := UserCredentials{
		Username: req.NewUsername,
		Password: newHash,
	}

	if err := saveCredentials(newCreds); err != nil {
		logAuditEvent(getUsernameFromToken(r), "credentials.update", "password",
			fmt.Sprintf("{\"error\":\"%s\"}", err.Error()), getClientIP(r), false)
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	// Log successful credential update
	logAuditEvent(getUsernameFromToken(r), "credentials.update", "password",
		fmt.Sprintf("{\"new_username\":\"%s\"}", req.NewUsername), getClientIP(r), true)

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
