package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// writeTestAuditLog writes n entries (oldest first, one per minute) plus some junk lines.
func writeTestAuditLog(t *testing.T, n int, trailingNewline bool) (string, []AuditLogEntry) {
	t.Helper()
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var b strings.Builder
	var all []AuditLogEntry
	for i := 0; i < n; i++ {
		e := AuditLogEntry{
			ID:        fmt.Sprintf("id-%04d", i),
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			User:      []string{"alice", "bob"}[i%2],
			Action:    []string{"firewall.add", "guest_access.add", "login"}[i%3],
			Details:   `{"note":"` + strings.Repeat("x", i%40) + `"}`,
			Success:   true,
		}
		all = append(all, e)
		line, _ := json.Marshal(e)
		b.Write(line)
		if i < n-1 || trailingNewline {
			b.WriteByte('\n')
		}
		switch i {
		case 10:
			b.WriteString("{not json\n")
		case 20:
			b.WriteString("\n")
		case 30:
			b.WriteString(strings.Repeat("z", 300) + "\n") // long malformed line
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(b.String())
	f.Close()
	return f.Name(), all
}

// referencePage is the behaviour of the old implementation: filter everything,
// newest first, then slice.
func referencePage(all []AuditLogEntry, start, end time.Time, action, user string, offset, limit int) []string {
	var matched []string
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		if !start.IsZero() && e.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && e.Timestamp.After(end) {
			continue
		}
		if action != "" && e.Action != action {
			continue
		}
		if user != "" && e.User != user {
			continue
		}
		matched = append(matched, e.ID)
	}
	if offset >= len(matched) {
		return []string{}
	}
	matched = matched[offset:]
	if len(matched) > limit {
		matched = matched[:limit]
	}
	return matched
}

func TestAuditStreamingMatchesFullScan(t *testing.T) {
	old := auditReadChunk
	defer func() { auditReadChunk = old }()

	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, trailing := range []bool{true, false} {
		path, all := writeTestAuditLog(t, 400, trailing)
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := f.Stat()

		for _, chunk := range []int{7, 64, 1000, 1 << 16} {
			auditReadChunk = chunk
			for _, offset := range []int{0, 3, 50, 399, 10000} {
				for _, limit := range []int{1, 10, 1000} {
					for _, c := range []struct {
						name         string
						start, end   time.Time
						action, user string
					}{
						{"none", time.Time{}, time.Time{}, "", ""},
						{"user", time.Time{}, time.Time{}, "", "alice"},
						{"action", time.Time{}, time.Time{}, "guest_access.add", ""},
						{"both", time.Time{}, time.Time{}, "login", "bob"},
						{"window", base.Add(100 * time.Minute), base.Add(250 * time.Minute), "", ""},
						{"window+user", base.Add(100 * time.Minute), time.Time{}, "", "alice"},
					} {
						got, err := readAuditLogPage(f, info.Size(), c.start, c.end, c.action, c.user, offset, limit)
						if err != nil {
							t.Fatal(err)
						}
						var ids []string
						for _, e := range got {
							ids = append(ids, e.ID)
						}
						want := referencePage(all, c.start, c.end, c.action, c.user, offset, limit)
						if strings.Join(ids, ",") != strings.Join(want, ",") {
							t.Fatalf("trailing=%v chunk=%d offset=%d limit=%d filter=%s:\n got  %v\n want %v",
								trailing, chunk, offset, limit, c.name, ids, want)
						}
					}
				}
			}
		}
		f.Close()
	}
}

func TestAuditStreamingStopsEarly(t *testing.T) {
	path, _ := writeTestAuditLog(t, 2000, true)
	f, _ := os.Open(path)
	defer f.Close()
	info, _ := f.Stat()

	lines := 0
	err := scanLinesReverse(f, info.Size(), func(line []byte) bool {
		lines++
		return lines < 5
	})
	if err != nil || lines != 5 {
		t.Fatalf("scan should stop after the callback says so: lines=%d err=%v", lines, err)
	}
}

func TestAuditStreamingEmptyAndSnapshot(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "empty-*.log")
	defer f.Close()
	got, err := readAuditLogPage(f, 0, time.Time{}, time.Time{}, "", "", 0, 10)
	if err != nil || len(got) != 0 {
		t.Errorf("empty log should give no entries: %v %v", got, err)
	}

	// Lines appended after the snapshot size must not be returned or break parsing.
	path, all := writeTestAuditLog(t, 20, true)
	g, _ := os.Open(path)
	defer g.Close()
	info, _ := g.Stat()
	w, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	w.WriteString(`{"id":"late","timestamp":"2027-01-01T00:00:00Z","user":"alice","action":"login"}` + "\n")
	w.Close()
	got, _ = readAuditLogPage(g, info.Size(), time.Time{}, time.Time{}, "", "", 0, 5)
	if len(got) != 5 || got[0].ID != all[len(all)-1].ID {
		t.Errorf("snapshot should end at the original size, got first=%v", got[0].ID)
	}
}
