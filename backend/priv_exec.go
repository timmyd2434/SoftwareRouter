package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// PrivilegedExecutor manages safe execution of system commands
// This is the ONLY way privileged commands should be executed in this application.
// It provides:
// - Command allow-listing (only approved binaries can run)
// - Argument validation (basic pattern matching)
// - Comprehensive audit logging
// - Error wrapping for debugging

// allowedCommands defines the whitelist of commands that can be executed
// This is the security boundary - ONLY these commands are permitted
var allowedCommands = map[string]bool{
	"nft":         true, // NFTables firewall
	"sysctl":      true, // Kernel parameters
	"ip":          true, // Network configuration
	"tc":          true, // Traffic control (QoS)
	"systemctl":   true, // Service management
	"wg":          true, // WireGuard VPN
	"modprobe":    true, // Kernel modules (bonding)
	"cloudflared": true, // Cloudflare tunnel
	"ping":        true, // Diagnostics
	"traceroute":  true, // Diagnostics
	"journalctl":  true, // Log access
	// SECURITY FIX (HIGH-1): bash/sh removed - shell access eliminated
	// Any operations requiring shell must be refactored to use native Go
	"curl":          true, // HTTP client (for downloads during setup)
	"pihole":        true, // Pi-hole CLI
	"cscli":         true, // CrowdSec CLI
	"tail":          true, // Log reading (for Suricata alerts)
	"./easyrsa":     true, // OpenVPN PKI management (run via runPrivilegedInDir)
	"openvpn":       true, // OpenVPN key generation
	"cp":            true, // File copy (used by OpenVPN setup)
	"speedtest-cli": true, // WAN speed test
	"uptime":          true, // System uptime
	"mkdir":           true, // Creating directories
	"suricata":        true, // Suricata IPS engine
	"suricata-update": true, // Suricata rule updater
	"ss":              true, // Socket statistics (active connections)
	"netstat":         true, // Network statistics (fallback)
	"dnsmasq":         true, // DHCP/DNS server (version check)
	"conntrack":       true, // Connection tracking CLI
	"./update.sh":     true, // System update script
}

// commandExecutionLog stores recent command executions for debugging
type commandExecutionLog struct {
	Timestamp time.Time
	Command   string
	Args      []string
	Success   bool
	Error     string
}

var recentCommands []commandExecutionLog
var recentCommandsMu sync.Mutex

// logCommandExecution records command execution for audit trail
func logCommandExecution(cmd string, args []string, success bool, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	entry := commandExecutionLog{
		Timestamp: time.Now(),
		Command:   cmd,
		Args:      args,
		Success:   success,
		Error:     errMsg,
	}

	// SECURITY FIX: Mutex-protect shared slice to prevent data races
	recentCommandsMu.Lock()
	recentCommands = append(recentCommands, entry)
	if len(recentCommands) > 100 {
		recentCommands = recentCommands[1:]
	}
	recentCommandsMu.Unlock()

	// Log to system logger
	if success {
		log.Printf("[PRIV_EXEC] SUCCESS: %s %s", cmd, strings.Join(args, " "))
	} else {
		log.Printf("[PRIV_EXEC] FAILED: %s %s - Error: %s", cmd, strings.Join(args, " "), errMsg)
	}

	// Also log to audit system if available
	// Note: We don't want circular dependency, so we'll just use standard logging here
	// The audit_log.go system will pick up these logs if needed
}

// validateCommand checks if a command is allowed and performs basic validation
func validateCommand(cmd string, args []string) error {
	// Check if command is in allow-list
	if !allowedCommands[cmd] {
		return fmt.Errorf("SECURITY: command '%s' is not in the allowed command list", cmd)
	}

	// SECURITY FIX (HIGH-2): Strict argument validation - zero exceptions
	// Comprehensive blocklist of dangerous shell metacharacters
	dangerousChars := []string{
		";", "|", "&", // Command separators/backgrounding
		"`", "$", // Command substitution/variables
		">", "<", // Redirects
		"\n", "\r", // Line breaks
		"(", ")", // Subshells
		"{", "}", // Command grouping
	}

	for _, arg := range args {
		for _, char := range dangerousChars {
			if strings.Contains(arg, char) {
				log.Printf("SECURITY: Blocked dangerous character '%s' in argument: %s", char, arg)
				return fmt.Errorf("SECURITY: dangerous character '%s' in argument", char)
			}
		}

		// Check for potential path traversal in arguments
		if strings.Contains(arg, "..") {
			log.Printf("SECURITY: Blocked potential path traversal in argument: %s", arg)
			return fmt.Errorf("SECURITY: potential path traversal in argument")
		}
	}

	// Command-specific validation
	switch cmd {
	case "bash", "sh":
		// Shell commands completely removed from allow-list
		return fmt.Errorf("SECURITY: shell commands are not permitted (HIGH-1 fix)")
	case "nft":
		// NFTables should generally use -f for file-based application
		if len(args) == 0 {
			return fmt.Errorf("nft requires arguments")
		}
	case "rm", "rmdir", "mv":
		// These should never be in the allow-list, but double-check
		return fmt.Errorf("SECURITY: destructive file operations are not allowed")
	}

	return nil
}

func getCommandContext(cmd string) (context.Context, context.CancelFunc) {
	timeout := 30 * time.Second
	if cmd == "speedtest-cli" || cmd == "suricata-update" || cmd == "curl" {
		timeout = 5 * time.Minute
	}
	return context.WithTimeout(context.Background(), timeout)
}

func getExecCommand(ctx context.Context, cmd string, args ...string) *exec.Cmd {
	if os.Getuid() != 0 && flag.Lookup("test.v") == nil {
		return exec.CommandContext(ctx, "sudo", append([]string{cmd}, args...)...)
	}
	return exec.CommandContext(ctx, cmd, args...)
}


// runPrivileged executes a privileged command with full security controls
// This is for commands where we expect success and don't need output
func runPrivileged(cmd string, args ...string) error {
	if err := validateCommand(cmd, args); err != nil {
		logCommandExecution(cmd, args, false, err)
		return err
	}

	ctx, cancel := getCommandContext(cmd)
	defer cancel()

	// #nosec G204 G702: cmd and args are strictly validated by validateCommand
	execCmd := getExecCommand(ctx, cmd, args...)
	err := execCmd.Run()

	logCommandExecution(cmd, args, err == nil, err)

	if err != nil {
		return fmt.Errorf("command '%s %s' failed: %w", cmd, strings.Join(args, " "), err)
	}

	return nil
}

// runPrivilegedOutput executes a privileged command and returns stdout
// This is for commands where we need the output (e.g., ip route show)
func runPrivilegedOutput(cmd string, args ...string) ([]byte, error) {
	if err := validateCommand(cmd, args); err != nil {
		logCommandExecution(cmd, args, false, err)
		return nil, err
	}

	ctx, cancel := getCommandContext(cmd)
	defer cancel()

	// #nosec G204 G702: cmd and args are strictly validated by validateCommand
	execCmd := getExecCommand(ctx, cmd, args...)
	output, err := execCmd.Output()

	logCommandExecution(cmd, args, err == nil, err)

	if err != nil {
		return output, fmt.Errorf("command '%s %s' failed: %w", cmd, strings.Join(args, " "), err)
	}

	return output, nil
}

// runPrivilegedCombinedOutput executes a privileged command and returns stdout+stderr
// This is for commands where we need both streams (e.g., diagnostics)
func runPrivilegedCombinedOutput(cmd string, args ...string) ([]byte, error) {
	if err := validateCommand(cmd, args); err != nil {
		logCommandExecution(cmd, args, false, err)
		return nil, err
	}

	ctx, cancel := getCommandContext(cmd)
	defer cancel()

	// #nosec G204 G702: cmd and args are strictly validated by validateCommand
	execCmd := getExecCommand(ctx, cmd, args...)
	output, err := execCmd.CombinedOutput()

	logCommandExecution(cmd, args, err == nil, err)

	if err != nil {
		return output, fmt.Errorf("command '%s %s' failed: %w", cmd, strings.Join(args, " "), err)
	}

	return output, nil
}

// GetRecentCommandExecutions returns the recent command execution log
// This is useful for debugging and security auditing
func GetRecentCommandExecutions() []commandExecutionLog {
	recentCommandsMu.Lock()
	defer recentCommandsMu.Unlock()
	// Return a copy to prevent data races on the returned slice
	copy := make([]commandExecutionLog, len(recentCommands))
	for i, cmd := range recentCommands {
		copy[i] = cmd
	}
	return copy
}

// runPrivilegedWithStdin executes a privileged command with data piped to stdin
// This replaces shell piping patterns like "echo X | cmd" without requiring shell access
func runPrivilegedWithStdin(stdinData []byte, cmd string, args ...string) ([]byte, error) {
	if err := validateCommand(cmd, args); err != nil {
		logCommandExecution(cmd, args, false, err)
		return nil, err
	}

	ctx, cancel := getCommandContext(cmd)
	defer cancel()

	// #nosec G204 G702: cmd and args are strictly validated by validateCommand
	execCmd := getExecCommand(ctx, cmd, args...)
	execCmd.Stdin = strings.NewReader(string(stdinData))
	output, err := execCmd.CombinedOutput()

	logCommandExecution(cmd, args, err == nil, err)

	if err != nil {
		return output, fmt.Errorf("command '%s %s' failed: %w", cmd, strings.Join(args, " "), err)
	}

	return output, nil
}

// deriveWireGuardPublicKey derives a public key from a private key
// without using shell piping (sh/bash removed from allowlist)
func deriveWireGuardPublicKey(privKey []byte) ([]byte, error) {
	return runPrivilegedWithStdin([]byte(strings.TrimSpace(string(privKey))+"\n"), "wg", "pubkey")
}

// runPrivilegedInDir executes a privileged command in a specific working directory.
// This replaces `bash -c "cd DIR && command"` patterns without needing shell access.
func runPrivilegedInDir(dir string, cmd string, args ...string) error {
	if err := validateCommand(cmd, args); err != nil {
		logCommandExecution(cmd, args, false, err)
		return err
	}

	ctx, cancel := getCommandContext(cmd)
	defer cancel()

	// #nosec G204 G702: cmd and args are strictly validated by validateCommand
	execCmd := getExecCommand(ctx, cmd, args...)
	execCmd.Dir = dir
	err := execCmd.Run()

	logCommandExecution(cmd, args, err == nil, err)

	if err != nil {
		return fmt.Errorf("command '%s %s' (in %s) failed: %w", cmd, strings.Join(args, " "), dir, err)
	}

	return nil
}

// runPrivilegedInDirCombinedOutput executes a privileged command in a specific working
// directory and returns stdout+stderr.
func runPrivilegedInDirCombinedOutput(dir string, cmd string, args ...string) ([]byte, error) {
	if err := validateCommand(cmd, args); err != nil {
		logCommandExecution(cmd, args, false, err)
		return nil, err
	}

	ctx, cancel := getCommandContext(cmd)
	defer cancel()

	// #nosec G204 G702: cmd and args are strictly validated by validateCommand
	execCmd := getExecCommand(ctx, cmd, args...)
	execCmd.Dir = dir
	output, err := execCmd.CombinedOutput()

	logCommandExecution(cmd, args, err == nil, err)

	if err != nil {
		return output, fmt.Errorf("command '%s %s' (in %s) failed: %w", cmd, strings.Join(args, " "), dir, err)
	}

	return output, nil
}

// runPrivilegedWithStdinInDir executes a privileged command in a directory with stdin data.
// Combines the functionality of runPrivilegedWithStdin and runPrivilegedInDir.
func runPrivilegedWithStdinInDir(dir string, stdinData []byte, cmd string, args ...string) ([]byte, error) {
	if err := validateCommand(cmd, args); err != nil {
		logCommandExecution(cmd, args, false, err)
		return nil, err
	}

	ctx, cancel := getCommandContext(cmd)
	defer cancel()

	// #nosec G204 G702: cmd and args are strictly validated by validateCommand
	execCmd := getExecCommand(ctx, cmd, args...)
	execCmd.Dir = dir
	execCmd.Stdin = strings.NewReader(string(stdinData))
	output, err := execCmd.CombinedOutput()

	logCommandExecution(cmd, args, err == nil, err)

	if err != nil {
		return output, fmt.Errorf("command '%s %s' (in %s) failed: %w", cmd, strings.Join(args, " "), dir, err)
	}

	return output, nil
}
