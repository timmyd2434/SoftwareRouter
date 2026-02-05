package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AuditLogEntry represents a single audit log entry
type AuditLogEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Action    string    `json:"action"`   // e.g., "firewall.add", "interface.update"
	Resource  string    `json:"resource"` // Specific resource affected
	Details   string    `json:"details"`  // JSON string of change details
	IPAddress string    `json:"ip_address"`
	Success   bool      `json:"success"`
}

const (
	auditLogDir  = "/var/log/softrouter"
	auditLogFile = "audit.log"
)

var auditLogMu sync.Mutex

// initAuditLog creates the audit log directory if it doesn't exist
func initAuditLog() error {
	if err := os.MkdirAll(auditLogDir, 0755); err != nil {
		return fmt.Errorf("failed to create audit log directory: %w", err)
	}
	return nil
}

// logAuditEvent writes an audit log entry
func logAuditEvent(user, action, resource, details, ipAddress string, success bool) {
	entry := AuditLogEntry{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		User:      user,
		Action:    action,
		Resource:  resource,
		Details:   details,
		IPAddress: ipAddress,
		Success:   success,
	}

	auditLogMu.Lock()
	defer auditLogMu.Unlock()

	logPath := filepath.Join(auditLogDir, auditLogFile)
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Fallback to stderr if audit log fails
		fmt.Fprintf(os.Stderr, "AUDIT LOG ERROR: Failed to open log file: %v\n", err)
		return
	}
	defer file.Close() //nolint:errcheck

	jsonData, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "AUDIT LOG ERROR: Failed to marshal entry: %v\n", err)
		return
	}

	// Write as JSON line
	if _, err := file.Write(append(jsonData, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "AUDIT LOG ERROR: Failed to write entry: %v\n", err)
	}
}

// getAuditLogs retrieves audit logs with optional filtering
func getAuditLogs(startTime, endTime time.Time, actionFilter, userFilter string, limit int) ([]AuditLogEntry, error) {
	auditLogMu.Lock()
	defer auditLogMu.Unlock()

	logPath := filepath.Join(auditLogDir, auditLogFile)

	// Check if file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return []AuditLogEntry{}, nil // Return empty array if no logs yet
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}

	// Parse JSON lines
	lines := splitLines(string(data))
	entries := []AuditLogEntry{}

	for _, line := range lines {
		if line == "" {
			continue
		}

		var entry AuditLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip malformed entries
			continue
		}

		// Apply filters
		if !startTime.IsZero() && entry.Timestamp.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && entry.Timestamp.After(endTime) {
			continue
		}
		if actionFilter != "" && entry.Action != actionFilter {
			continue
		}
		if userFilter != "" && entry.User != userFilter {
			continue
		}

		entries = append(entries, entry)
	}

	// Return most recent first
	reverseSlice(entries)

	// Apply limit
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	return entries, nil
}

// Helper function to split lines
func splitLines(s string) []string {
	lines := []string{}
	current := ""

	for _, c := range s {
		if c == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(c)
		}
	}

	if current != "" {
		lines = append(lines, current)
	}

	return lines
}

// Helper function to reverse slice
func reverseSlice(entries []AuditLogEntry) {
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
}

// rotateAuditLog rotates the audit log file (called daily)
func rotateAuditLog() {
	auditLogMu.Lock()
	defer auditLogMu.Unlock()

	logPath := filepath.Join(auditLogDir, auditLogFile)

	// Check if file exists and has data
	info, err := os.Stat(logPath)
	if os.IsNotExist(err) || info.Size() == 0 {
		return
	}

	// Rotate to dated filename
	rotatedPath := fmt.Sprintf("%s.%s", logPath, time.Now().Format("2006-01-02"))

	if err := os.Rename(logPath, rotatedPath); err != nil {
		fmt.Fprintf(os.Stderr, "AUDIT LOG ERROR: Failed to rotate log: %v\n", err)
		return
	}

	// Note: In production, you'd want to compress old logs here
	// e.g., gzip rotatedPath
}

// startAuditLogRotation starts a goroutine to rotate logs daily
func startAuditLogRotation() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			rotateAuditLog()
		}
	}()
}
