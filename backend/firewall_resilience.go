package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// FirewallResilience provides safety mechanisms for firewall operations
// This module prevents router lockout and enables recovery from bad configurations

const (
	knownGoodSnapshotPath  = "/etc/softrouter/firewall.good.nft"
	watchdogTimeoutSeconds = 60
	deadManSwitchRuleset   = "firewall-deadman.nft"
)

var (
	watchdogActive     bool
	watchdogMutex      sync.Mutex
	watchdogCancelChan chan bool
)

// installDeadManSwitch adds temporary emergency access rules
// These rules ensure SSH and WebUI remain accessible during firewall transitions
// They are removed after successful application or on rollback
func installDeadManSwitch() error {
	log.Println("[RESILIENCE] Installing dead-man switch (emergency access rules)")

	// Create temporary ruleset that accepts SSH and WebUI traffic unconditionally
	// This is applied BEFORE flushing existing rules
	deadManRules := `
# Emergency access rules - applied during firewall transitions
# These rules ensure management access survives firewall application failures

table inet deadman {
	chain input {
		type filter hook input priority -200; policy accept;
		
		# Accept SSH unconditionally
		tcp dport 22 accept comment "Dead-man switch: SSH"
		
		# Accept WebUI on localhost
		iif lo tcp dport 8090 accept comment "Dead-man switch: WebUI"
		iif lo tcp dport 443 accept comment "Dead-man switch: WebUI HTTPS"
		
		# Accept established connections
		ct state established,related accept
	}
}
`

	tmpfile, err := os.CreateTemp("", "softrouter-deadman-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create dead-man switch temp file: %w", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(deadManRules); err != nil {
		return fmt.Errorf("failed to write dead-man switch rules: %w", err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Printf("WARNING: Failed to close dead-man temp file: %v", err)
	}

	// Apply dead-man switch rules
	if err := runPrivileged("nft", "-f", tmpfile.Name()); err != nil {
		return fmt.Errorf("failed to apply dead-man switch: %w", err)
	}

	log.Println("[RESILIENCE] ✓ Dead-man switch installed successfully")
	return nil
}

// removeDeadManSwitch removes the emergency access rules after successful application
func removeDeadManSwitch() error {
	log.Println("[RESILIENCE] Removing dead-man switch (firewall apply succeeded)")

	// Remove the temporary dead-man table
	if err := runPrivileged("nft", "delete", "table", "inet", "deadman"); err != nil {
		// Log but don't fail - the table might not exist if we're recovering from a failed apply
		log.Printf("[RESILIENCE] Note: Could not remove dead-man table (may not exist): %v", err)
	}

	return nil
}

// saveKnownGoodSnapshot saves a verified working firewall configuration to disk
// This snapshot is used for boot-safe fallback and emergency recovery
func saveKnownGoodSnapshot(ruleset string) error {
	log.Println("[RESILIENCE] Saving known-good firewall snapshot")

	// Ensure directory exists
	if err := os.MkdirAll("/etc/softrouter", 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write snapshot
	if err := os.WriteFile(knownGoodSnapshotPath, []byte(ruleset), 0600); err != nil {
		return fmt.Errorf("failed to write known-good snapshot: %w", err)
	}

	log.Printf("[RESILIENCE] ✓ Known-good snapshot saved to %s", knownGoodSnapshotPath)
	return nil
}

// loadKnownGoodSnapshot loads the last verified working configuration
func loadKnownGoodSnapshot() (string, error) {
	log.Println("[RESILIENCE] Loading known-good firewall snapshot")

	data, err := os.ReadFile(knownGoodSnapshotPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no known-good snapshot exists yet")
		}
		return "", fmt.Errorf("failed to read known-good snapshot: %w", err)
	}

	log.Println("[RESILIENCE] ✓ Known-good snapshot loaded")
	return string(data), nil
}

// getBootSafeFallbackRuleset returns a minimal safe ruleset for emergency boot recovery
// This ruleset allows SSH and basic connectivity even if all configs are corrupted
func getBootSafeFallbackRuleset() string {
	return `
# Boot-safe fallback ruleset
# This is the absolute minimal configuration to allow emergency access

flush ruleset

table inet emergency {
	chain input {
		type filter hook input priority filter; policy accept;
		
		# Accept all on loopback
		iif lo accept
		
		# Accept established connections
		ct state established,related accept
		
		# Accept SSH
		tcp dport 22 accept comment "Emergency SSH access"
		
		# Accept ICMP
		ip protocol icmp accept
		ip6 nexthdr icmpv6 accept
	}
	
	chain forward {
		type filter hook forward priority filter; policy drop;
		
		# Accept established connections
		ct state established,related accept
	}
}
`
}

// startWatchdogTimer initiates a countdown that will rollback firewall changes
// unless the user confirms them via the API
func startWatchdogTimer(rollbackSnapshot string) error {
	watchdogMutex.Lock()
	defer watchdogMutex.Unlock()

	if watchdogActive {
		return fmt.Errorf("watchdog already active")
	}

	watchdogActive = true
	watchdogCancelChan = make(chan bool, 1)

	log.Printf("[RESILIENCE] Starting watchdog timer (%d seconds)", watchdogTimeoutSeconds)

	go func() {
		timer := time.NewTimer(watchdogTimeoutSeconds * time.Second)
		defer timer.Stop()

		select {
		case <-timer.C:
			// Timer expired - rollback required
			log.Println("[RESILIENCE] ⚠️  WATCHDOG TIMEOUT - Rolling back firewall changes")

			if err := performRollback(rollbackSnapshot); err != nil {
				log.Printf("[RESILIENCE] CRITICAL: Rollback failed: %v", err)
				// Try emergency fallback
				if err := applyBootSafeFallback(); err != nil {
					log.Printf("[RESILIENCE] CRITICAL: Emergency fallback also failed: %v", err)
				}
			} else {
				log.Println("[RESILIENCE] ✓ Rollback completed successfully")
			}

			watchdogMutex.Lock()
			watchdogActive = false
			watchdogMutex.Unlock()

		case <-watchdogCancelChan:
			// User confirmed - no rollback needed
			log.Println("[RESILIENCE] ✓ Firewall changes confirmed by user")

			watchdogMutex.Lock()
			watchdogActive = false
			watchdogMutex.Unlock()
		}
	}()

	return nil
}

// confirmFirewallChanges is an HTTP handler that confirms firewall changes.
// It cancels the watchdog timer when the user confirms changes are working.
func confirmFirewallChanges(w http.ResponseWriter, r *http.Request) {
	watchdogMutex.Lock()
	defer watchdogMutex.Unlock()

	if !watchdogActive {
		http.Error(w, "No watchdog timer active", http.StatusBadRequest)
		return
	}

	// Cancel the timer
	watchdogCancelChan <- true
	close(watchdogCancelChan)

	log.Println("[RESILIENCE] Firewall changes confirmed - watchdog cancelled")

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"confirmed","message":"Firewall changes confirmed successfully"}`))
}

// performRollback restores the previous firewall configuration
func performRollback(snapshot string) error {
	log.Println("[RESILIENCE] Performing firewall rollback")

	if snapshot == "" {
		log.Println("[RESILIENCE] No snapshot available, using known-good config")
		var err error
		snapshot, err = loadKnownGoodSnapshot()
		if err != nil {
			return fmt.Errorf("no rollback snapshot available: %w", err)
		}
	}

	// Write snapshot to temp file
	tmpfile, err := os.CreateTemp("", "softrouter-rollback-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create rollback temp file: %w", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(snapshot); err != nil {
		return fmt.Errorf("failed to write rollback rules: %w", err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Printf("WARNING: Failed to close rollback temp file: %v", err)
	}

	// Apply rollback
	if err := runPrivileged("nft", "-f", tmpfile.Name()); err != nil {
		return fmt.Errorf("failed to apply rollback rules: %w", err)
	}

	log.Println("[RESILIENCE] ✓ Rollback applied successfully")
	return nil
}

// applyBootSafeFallback applies the emergency minimal ruleset
// This is the last resort if all else fails
func applyBootSafeFallback() error {
	log.Println("[RESILIENCE] Applying boot-safe fallback ruleset (EMERGENCY)")

	fallbackRules := getBootSafeFallbackRuleset()

	tmpfile, err := os.CreateTemp("", "softrouter-emergency-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create emergency temp file: %w", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(fallbackRules); err != nil {
		return fmt.Errorf("failed to write emergency rules: %w", err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Printf("WARNING: Failed to close emergency temp file: %v", err)
	}

	if err := runPrivileged("nft", "-f", tmpfile.Name()); err != nil {
		return fmt.Errorf("failed to apply emergency rules: %w", err)
	}

	log.Println("[RESILIENCE] ✓ Boot-safe fallback applied")
	return nil
}

// isWatchdogActive returns whether the watchdog timer is currently running
func isWatchdogActive() bool {
	watchdogMutex.Lock()
	defer watchdogMutex.Unlock()
	return watchdogActive
}
