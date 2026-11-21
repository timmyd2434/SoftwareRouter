package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	if err := os.MkdirAll(auditLogDir, 0750); err != nil {
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
	// #nosec G304 G703: path is validated or constructed from safe internal sources
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
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

// auditReadChunk is how much of the log is read per step when scanning backwards.
// It is a variable so tests can force entries to straddle chunk boundaries.
var auditReadChunk = 64 << 10

// auditMaxLine bounds how much of a single (malformed) line is kept in memory.
const auditMaxLine = 1 << 20

// auditMaxPage is the most entries a single query returns.
const auditMaxPage = 1000

// scanLinesReverse calls fn for every line in f[:size], last line first, until fn
// returns false. Only one chunk plus a partial line is held in memory at a time.
func scanLinesReverse(f *os.File, size int64, fn func(line []byte) bool) error {
	var carry []byte
	pos := size
	for pos > 0 {
		n := int64(auditReadChunk)
		if n > pos {
			n = pos
		}
		pos -= n
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, pos); err != nil && err != io.EOF {
			return err
		}
		data := append(buf, carry...)
		carry = nil
		for {
			i := bytes.LastIndexByte(data, '\n')
			if i < 0 {
				carry = data // start of this chunk continues in the previous one
				break
			}
			if line := data[i+1:]; len(line) > 0 && !fn(line) {
				return nil
			}
			data = data[:i]
		}
		if len(carry) > auditMaxLine {
			carry = nil // ignore an absurdly long malformed line
		}
	}
	if len(carry) > 0 {
		fn(carry)
	}
	return nil
}

// readAuditLogPage returns matching entries newest first, skipping the first `offset`
// matches and returning at most `limit`. It streams the file from the end, so the cost
// is proportional to offset+limit, not to the size of the log.
func readAuditLogPage(f *os.File, size int64, startTime, endTime time.Time, actionFilter, userFilter string, offset, limit int) ([]AuditLogEntry, error) {
	if limit <= 0 || limit > auditMaxPage {
		limit = auditMaxPage
	}
	if offset < 0 {
		offset = 0
	}
	entries := make([]AuditLogEntry, 0, limit)
	skipped := 0
	err := scanLinesReverse(f, size, func(line []byte) bool {
		var entry AuditLogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return true // skip malformed entries
		}
		// The log is written in time order, so once we are older than the window
		// everything further back is older too.
		if !startTime.IsZero() && entry.Timestamp.Before(startTime) {
			return false
		}
		if !endTime.IsZero() && entry.Timestamp.After(endTime) {
			return true
		}
		if actionFilter != "" && entry.Action != actionFilter {
			return true
		}
		if userFilter != "" && entry.User != userFilter {
			return true
		}
		if skipped < offset {
			skipped++
			return true
		}
		entries = append(entries, entry)
		return len(entries) < limit
	})
	return entries, err
}

// getAuditLogsPage retrieves audit logs, newest first, with optional filtering and paging.
func getAuditLogsPage(startTime, endTime time.Time, actionFilter, userFilter string, offset, limit int) ([]AuditLogEntry, error) {
	logPath := filepath.Join(auditLogDir, auditLogFile)

	// Hold the lock only long enough to open the file and note its size. Entries are
	// appended whole under this lock, so the size is always on a line boundary, and
	// writers are never blocked while we read. An open handle also survives rotation.
	auditLogMu.Lock()
	f, err := os.Open(logPath) // #nosec G304: constant internal path
	var size int64
	if err == nil {
		var info os.FileInfo
		if info, err = f.Stat(); err == nil {
			size = info.Size()
		}
	}
	auditLogMu.Unlock()

	if os.IsNotExist(err) {
		return []AuditLogEntry{}, nil // no logs yet
	}
	if err != nil {
		if f != nil {
			f.Close() //nolint:errcheck
		}
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}
	defer f.Close() //nolint:errcheck

	entries, err := readAuditLogPage(f, size, startTime, endTime, actionFilter, userFilter, offset, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}
	return entries, nil
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
