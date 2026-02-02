package main

import (
	"testing"
)

func TestHostRegex(t *testing.T) {
	valid := []string{"google.com", "8.8.8.8", "localhost", "my-router.local", "192.168.1.1"}
	invalid := []string{"google.com; rm -rf /", "test|ls", "`whoami`", "invalid space"}

	for _, v := range valid {
		if !hostRegex.MatchString(v) {
			t.Errorf("Expected %s to be valid", v)
		}
	}

	for _, v := range invalid {
		if hostRegex.MatchString(v) {
			t.Errorf("Expected %s to be invalid", v)
		}
	}
}

// NOTE: We cannot easily test command execution without mocking exec.Command.
// But we can verify the validation logic which is the most critical security part.
// The actual execution is simple exec.Command calls.
