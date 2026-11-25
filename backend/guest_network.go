package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Guest / IoT isolation
//
// An interface labelled "Guest" (or "IoT" / "Isolated") is NOT treated as a
// trusted LAN interface by the firewall generator. It receives only:
//
//	input:   DHCP (udp 67) and DNS (udp/tcp 53) from the router itself
//	forward: traffic to the WAN interfaces, plus the explicit exceptions listed
//	         in config.json under "guest_allow"
//
// Everything else (SSH, the web UI, other LAN subnets, LAN servers) falls
// through to the chains' default-drop policy. Replies to connections the guest
// opened are covered by the existing "ct state established,related accept".

// GuestAllowRule is one exception that lets guest/IoT clients reach a specific
// internal destination, e.g. a reverse proxy in front of Jellyfin. Rules are
// managed from the dashboard (Guest / IoT page) and stored in guest_access.json.
type GuestAllowRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`        // free text, used in the nft comment
	Destination string `json:"destination"` // IPv4 address or CIDR
	Protocol    string `json:"protocol"`    // "tcp" (default) or "udp"
	Ports       []int  `json:"ports"`       // 1-65535, at most maxGuestAllowPorts
	Enabled     bool   `json:"enabled"`
	// Interfaces limits the rule to these isolated networks. Empty means every
	// isolated network. A rule whose listed networks no longer exist matches nothing.
	Interfaces []string `json:"interfaces"`
}

const (
	maxGuestAllowPorts = 16
	maxGuestAllowRules = 64
	maxGuestNameLen    = 64
)

// isGuestLabel reports whether an interface label requests guest isolation.
func isGuestLabel(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "guest", "iot", "isolated":
		return true
	}
	return false
}

// validateGuestAllowRule checks every field that ends up in the ruleset.
func validateGuestAllowRule(r GuestAllowRule) error {
	dest := strings.TrimSpace(r.Destination)
	if dest == "" {
		return fmt.Errorf("destination is required")
	}
	if strings.Contains(dest, "/") {
		ip, _, err := net.ParseCIDR(dest)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("destination %q is not a valid IPv4 CIDR", dest)
		}
	} else {
		ip := net.ParseIP(dest)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("destination %q is not a valid IPv4 address", dest)
		}
	}
	switch strings.ToLower(r.Protocol) {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("protocol %q must be tcp or udp", r.Protocol)
	}
	if len(r.Ports) == 0 {
		return fmt.Errorf("at least one port is required")
	}
	if len(r.Ports) > maxGuestAllowPorts {
		return fmt.Errorf("at most %d ports per rule", maxGuestAllowPorts)
	}
	for _, p := range r.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
	}
	if len(r.Interfaces) > maxGuestAllowRules {
		return fmt.Errorf("too many networks selected")
	}
	for _, iface := range r.Interfaces {
		if !isValidInterfaceName(iface) {
			return fmt.Errorf("invalid network name %q", iface)
		}
	}
	return nil
}

// appliesToGuest reports whether a rule covers the given isolated interface.
func (r GuestAllowRule) appliesToGuest(iface string) bool {
	if len(r.Interfaces) == 0 {
		return true
	}
	for _, name := range r.Interfaces {
		if name == iface {
			return true
		}
	}
	return false
}

// writeGuestInputRules emits the only things a guest interface may ask of the
// router itself: an address (DHCP) and name resolution (DNS).
func writeGuestInputRules(b *strings.Builder, guestInterfaces []string) {
	for _, g := range guestInterfaces {
		b.WriteString(fmt.Sprintf("    iifname \"%s\" udp dport 67 accept comment \"Guest DHCP\"\n", g))
		b.WriteString(fmt.Sprintf("    iifname \"%s\" udp dport 53 accept comment \"Guest DNS\"\n", g))
		b.WriteString(fmt.Sprintf("    iifname \"%s\" tcp dport 53 accept comment \"Guest DNS\"\n", g))
	}
}

// writeGuestForwardRules emits the explicit exceptions first, then plain
// internet access. There is deliberately no guest->LAN and no LAN->guest rule.
func writeGuestForwardRules(b *strings.Builder, guestInterfaces, wanInterfaces []string, allow []GuestAllowRule) {
	for _, g := range guestInterfaces {
		for _, r := range allow {
			if !r.Enabled || !r.appliesToGuest(g) {
				continue
			}
			if err := validateGuestAllowRule(r); err != nil {
				log.Printf("WARNING: Skipping invalid guest_allow rule %q: %v", r.Name, err)
				continue
			}
			proto := strings.ToLower(r.Protocol)
			if proto == "" {
				proto = "tcp"
			}
			ports := make([]string, 0, len(r.Ports))
			for _, p := range r.Ports {
				ports = append(ports, fmt.Sprintf("%d", p))
			}
			portExpr := ports[0]
			if len(ports) > 1 {
				portExpr = "{ " + strings.Join(ports, ", ") + " }"
			}
			comment := sanitizeComment("Guest allow - " + r.Name)
			b.WriteString(fmt.Sprintf("    iifname \"%s\" ip daddr %s %s dport %s accept comment \"%s\"\n",
				g, strings.TrimSpace(r.Destination), proto, portExpr, comment))
		}
		for _, w := range wanInterfaces {
			b.WriteString(fmt.Sprintf("    iifname \"%s\" oifname \"%s\" accept comment \"Guest to WAN\"\n", g, w))
		}
	}
}

// normalizeGuestAllowRule trims and canonicalises user input, then validates it.
// The returned rule is what gets stored (ID and Enabled are set by the caller).
func normalizeGuestAllowRule(r GuestAllowRule) (GuestAllowRule, error) {
	r.Name = strings.TrimSpace(r.Name)
	r.Destination = strings.TrimSpace(r.Destination)
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	if r.Protocol == "" {
		r.Protocol = "tcp"
	}
	if len(r.Name) > maxGuestNameLen {
		return r, fmt.Errorf("name too long (max %d characters)", maxGuestNameLen)
	}
	for _, ch := range r.Name {
		if ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\\' {
			return r, fmt.Errorf("name contains invalid characters")
		}
	}
	// Drop duplicate ports, keep the order the user typed.
	seen := map[int]bool{}
	ports := make([]int, 0, len(r.Ports))
	for _, p := range r.Ports {
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	r.Ports = ports
	seenIf := map[string]bool{}
	ifaces := make([]string, 0, len(r.Interfaces))
	for _, iface := range r.Interfaces {
		iface = strings.TrimSpace(iface)
		if iface != "" && !seenIf[iface] {
			seenIf[iface] = true
			ifaces = append(ifaces, iface)
		}
	}
	r.Interfaces = ifaces
	if err := validateGuestAllowRule(r); err != nil {
		return r, err
	}
	return r, nil
}

// ---------------------------------------------------------------- storage

type guestAllowStore struct {
	Rules    []GuestAllowRule `json:"rules"`
	Settings GuestSettings    `json:"settings"`
}

var (
	guestStore      = guestAllowStore{Rules: []GuestAllowRule{}}
	guestStoreLock  sync.RWMutex
	guestStoreReady bool
	guestConfigPath = "/etc/softrouter/guest_access.json"
)

// loadGuestAllowRules reads the store from disk. A missing file is an empty
// list; a corrupt file never wipes rules that are already in memory.
func loadGuestAllowRules() {
	guestStoreLock.Lock()
	defer guestStoreLock.Unlock()
	guestStoreReady = true

	data, err := os.ReadFile(guestConfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Error loading guest access rules: %v", err)
		}
		return
	}
	var tmp guestAllowStore
	if err := json.Unmarshal(data, &tmp); err != nil {
		log.Printf("Error parsing guest access rules from %s: %v", guestConfigPath, err)
		return
	}
	if tmp.Rules == nil {
		tmp.Rules = []GuestAllowRule{}
	}
	guestStore = tmp
}

// GetGuestAllowRules returns a copy of the stored rules.
func GetGuestAllowRules() []GuestAllowRule {
	guestStoreLock.RLock()
	ready := guestStoreReady
	guestStoreLock.RUnlock()
	if !ready {
		loadGuestAllowRules()
	}
	guestStoreLock.RLock()
	defer guestStoreLock.RUnlock()
	out := make([]GuestAllowRule, len(guestStore.Rules))
	copy(out, guestStore.Rules)
	return out
}

// setGuestAllowRules replaces the stored rules (keeping the settings) and persists them atomically.
func setGuestAllowRules(rules []GuestAllowRule) error {
	guestStoreLock.Lock()
	defer guestStoreLock.Unlock()
	return saveGuestStoreLocked(guestAllowStore{Rules: rules, Settings: guestStore.Settings})
}

// setGuestSettings replaces the settings (keeping the rules) and persists them atomically.
func setGuestSettings(settings GuestSettings) error {
	guestStoreLock.Lock()
	defer guestStoreLock.Unlock()
	return saveGuestStoreLocked(guestAllowStore{Rules: guestStore.Rules, Settings: settings})
}

// GetGuestSettings returns the stored settings (all off when nothing has been saved).
func GetGuestSettings() GuestSettings {
	guestStoreLock.RLock()
	ready := guestStoreReady
	guestStoreLock.RUnlock()
	if !ready {
		loadGuestAllowRules()
	}
	guestStoreLock.RLock()
	defer guestStoreLock.RUnlock()
	return guestStore.Settings
}

// saveGuestStoreLocked writes the store to disk atomically; the caller holds guestStoreLock.
func saveGuestStoreLocked(store guestAllowStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(guestConfigPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "guest_access-*.json.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, guestConfigPath); err != nil {
		os.Remove(name)
		return fmt.Errorf("failed to replace guest access config: %w", err)
	}
	guestStore = store
	guestStoreReady = true
	return nil
}
