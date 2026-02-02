package main

import (
	"strings"
	"testing"
)

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name      string
		cmd       string
		args      []string
		wantError bool
	}{
		{
			name:      "allowed command nft",
			cmd:       "nft",
			args:      []string{"list", "ruleset"},
			wantError: false,
		},
		{
			name:      "allowed command ip",
			cmd:       "ip",
			args:      []string{"addr", "show"},
			wantError: false,
		},
		{
			name:      "disallowed command",
			cmd:       "rm",
			args:      []string{"-rf", "/"},
			wantError: true,
		},
		{
			name:      "command not in allow-list",
			cmd:       "cat",
			args:      []string{"/etc/passwd"},
			wantError: true,
		},
		{
			name:      "shell with -c flag",
			cmd:       "bash",
			args:      []string{"-c", "echo test"},
			wantError: false,
		},
		{
			name:      "shell without -c flag",
			cmd:       "bash",
			args:      []string{"echo", "test"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommand(tt.cmd, tt.args)
			if (err != nil) != tt.wantError {
				t.Errorf("validateCommand() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestRunPrivileged(t *testing.T) {
	// Test with a safe command that should succeed
	err := runPrivileged("ip", "addr", "show", "lo")
	if err != nil {
		t.Errorf("runPrivileged() with valid command failed: %v", err)
	}

	// Test with disallowed command
	err = runPrivileged("cat", "/etc/passwd")
	if err == nil {
		t.Error("runPrivileged() should have rejected disallowed command")
	}
	if !strings.Contains(err.Error(), "not in the allowed command list") {
		t.Errorf("runPrivileged() error message incorrect: %v", err)
	}
}

func TestRunPrivilegedOutput(t *testing.T) {
	// Test with command that produces output
	output, err := runPrivilegedOutput("ip", "addr", "show", "lo")
	if err != nil {
		t.Errorf("runPrivilegedOutput() failed: %v", err)
	}
	if len(output) == 0 {
		t.Error("runPrivilegedOutput() returned empty output")
	}

	// Verify output contains expected content
	outputStr := string(output)
	if !strings.Contains(outputStr, "lo") {
		t.Errorf("runPrivilegedOutput() output doesn't contain expected interface: %s", outputStr)
	}
}

func TestCommandExecutionLogging(t *testing.T) {
	// Clear previous logs
	recentCommands = []commandExecutionLog{}

	// Execute a command
	runPrivileged("ip", "addr", "show", "lo")

	// Check that it was logged
	logs := GetRecentCommandExecutions()
	if len(logs) == 0 {
		t.Error("Command execution was not logged")
	}

	lastLog := logs[len(logs)-1]
	if lastLog.Command != "ip" {
		t.Errorf("Logged command incorrect: got %s, want ip", lastLog.Command)
	}
	if !lastLog.Success {
		t.Error("Command should have succeeded")
	}
}

func TestArgumentSanitization(t *testing.T) {
	// Test that suspicious arguments trigger warnings (but may still execute if command is valid)
	// This test just ensures validation doesn't panic on edge cases

	suspiciousArgs := []string{
		"normal-arg",
		"--flag=value",
		"192.168.1.1/24",
		"/path/to/file",
	}

	err := validateCommand("ip", suspiciousArgs)
	if err != nil {
		t.Errorf("validateCommand should not reject valid-looking arguments: %v", err)
	}
}
