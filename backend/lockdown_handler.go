package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// provisioningWindow is how long WAN SSH/DNS stay open after a fresh install
// before the router locks itself down automatically.
const provisioningWindow = 60 * time.Minute

// startProvisioningWindowLocked opens the provisioning window. Caller holds configLock.
func startProvisioningWindowLocked() {
	now := time.Now().UTC()
	config.ProvisioningMode = true
	config.ProvisioningStarted = now
	config.ProvisioningExpires = now.Add(provisioningWindow)
}

// applyLockdown closes provisioning mode and WAN management exposure.
// closeWebUIWAN additionally disables WAN WebUI access.
func applyLockdown(closeWebUIWAN bool) error {
	configLock.Lock()
	config.ProvisioningMode = false
	config.AllowWANSSH = false
	config.AllowWANDNS = false
	config.FirewallEnabled = true
	if closeWebUIWAN {
		config.WebAccess.AllowWAN = false
	}
	err := saveConfigLocked()
	configLock.Unlock()
	if err != nil {
		return err
	}
	// A rollback timer from an earlier apply (e.g. the setup wizard) holds a
	// snapshot with WAN SSH/DNS still open; it must not undo the lockdown.
	cancelWatchdog()
	// Boot-style apply (no watchdog): the operator is already authenticated and
	// the dead-man switch protects LAN management during the transition.
	return firewallManager.ApplyFirewallRules(true)
}

// startProvisioningExpiry auto-locks the router when the window elapses.
func startProvisioningExpiry() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			configLock.RLock()
			active := config.ProvisioningMode
			expires := config.ProvisioningExpires
			configLock.RUnlock()
			if !active {
				continue
			}
			if expires.IsZero() || time.Now().After(expires) {
				log.Println("[PROVISIONING] Window expired - locking down WAN SSH/DNS")
				if err := applyLockdown(false); err != nil {
					log.Printf("[PROVISIONING] Auto-lockdown failed: %v", err)
				}
				logAuditEvent("system", "system.lockdown", "provisioning", "auto-lockdown on expiry", "127.0.0.1", true)
			}
		}
	}()
}

// lockdownHandler implements POST /api/system/lockdown.
func lockdownHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CloseWebUIWAN bool `json:"close_webui_wan"`
	}
	// Empty body is fine: defaults to keeping the current WAN WebUI setting.
	_ = json.NewDecoder(r.Body).Decode(&req)

	user := getUsernameFromToken(r)
	if err := applyLockdown(req.CloseWebUIWAN); err != nil {
		logAuditEvent(user, "system.lockdown", "provisioning", err.Error(), getClientIP(r), false)
		respondSystemError(w, ErrGenericInternalError, "Lockdown failed", err)
		return
	}
	logAuditEvent(user, "system.lockdown", "provisioning", "WAN SSH/DNS closed", getClientIP(r), true)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true, "provisioning_mode": false})
}

// kernelHasTable reports whether `nft list table <family> <name>` succeeds.
func kernelHasTable(family, name string) bool {
	_, err := runPrivilegedOutput("nft", "list", "table", family, name)
	return err == nil
}
