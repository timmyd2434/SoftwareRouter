package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// Session represents an active user session
type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionStore manages active sessions
type SessionStore struct {
	sessions map[string]*Session // map[token]Session
	mu       sync.RWMutex
}

var (
	sessionStore   = &SessionStore{sessions: make(map[string]*Session)}
	sessionTimeout = 24 * time.Hour // Default 24 hour timeout
)

// AddSession adds a new session to the store
func (ss *SessionStore) AddSession(token, username, ipAddress, userAgent string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	now := time.Now()
	session := &Session{
		Token:     token,
		Username:  username,
		CreatedAt: now,
		LastUsed:  now,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresAt: now.Add(sessionTimeout),
	}

	ss.sessions[token] = session
}

// GetSession retrieves a session by token
func (ss *SessionStore) GetSession(token string) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	session, exists := ss.sessions[token]
	return session, exists
}

// UpdateLastUsed updates the last used time for a session
func (ss *SessionStore) UpdateLastUsed(token string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if session, exists := ss.sessions[token]; exists {
		session.LastUsed = time.Now()
		// Extend expiration on activity
		session.ExpiresAt = time.Now().Add(sessionTimeout)
	}
}

// DeleteSession removes a session from the store
func (ss *SessionStore) DeleteSession(token string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if _, exists := ss.sessions[token]; exists {
		delete(ss.sessions, token)
		return true
	}
	return false
}

// ListSessions returns all active sessions for a username
func (ss *SessionStore) ListSessions(username string) []Session {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	sessions := []Session{}
	for _, session := range ss.sessions {
		if session.Username == username {
			sessions = append(sessions, *session)
		}
	}

	return sessions
}

// ListAllSessions returns all active sessions (admin only)
func (ss *SessionStore) ListAllSessions() []Session {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	sessions := []Session{}
	for _, session := range ss.sessions {
		sessions = append(sessions, *session)
	}

	return sessions
}

// CleanupExpiredSessions removes expired sessions
func (ss *SessionStore) CleanupExpiredSessions() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	now := time.Now()
	for token, session := range ss.sessions {
		if now.After(session.ExpiresAt) {
			delete(ss.sessions, token)
		}
	}
}

// ValidateSession checks if a session is valid
func (ss *SessionStore) ValidateSession(token string) bool {
	session, exists := ss.GetSession(token)
	if !exists {
		return false
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		ss.DeleteSession(token)
		return false
	}

	// Update last used time
	ss.UpdateLastUsed(token)
	return true
}

// startSessionCleanup starts a goroutine to periodically clean up expired sessions
func startSessionCleanup() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			sessionStore.CleanupExpiredSessions()
			log.Printf("Session cleanup: removed expired sessions")
		}
	}()
}

// RevokeAllUserSessions revokes all sessions for a specific user
func (ss *SessionStore) RevokeAllUserSessions(username string) int {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	count := 0
	for token, session := range ss.sessions {
		if session.Username == username {
			delete(ss.sessions, token)
			count++
		}
	}

	return count
}

// GetSessionCount returns the total number of active sessions
func (ss *SessionStore) GetSessionCount() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	return len(ss.sessions)
}

// ExportSessions exports all sessions as JSON (for backup)
func (ss *SessionStore) ExportSessions() ([]byte, error) {
	ss.mu.RLock()
	sessions := make([]Session, 0, len(ss.sessions))
	for _, session := range ss.sessions {
		sessions = append(sessions, *session)
	}
	ss.mu.RUnlock()

	return json.MarshalIndent(sessions, "", "  ")
}

// SessionInfo returns safe session info (without token)
type SessionInfo struct {
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
	IsCurrent bool      `json:"is_current"`
}

// GetSafeSessionInfo returns session info without sensitive token
func (s *Session) ToSafeInfo(currentToken string) SessionInfo {
	return SessionInfo{
		Username:  s.Username,
		CreatedAt: s.CreatedAt,
		LastUsed:  s.LastUsed,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		ExpiresAt: s.ExpiresAt,
		IsCurrent: s.Token == currentToken,
	}
}
