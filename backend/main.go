package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Security Globals
var (
	loginAttempts = make(map[string]int)
	loginBanUntil = make(map[string]time.Time)
	loginMu       sync.Mutex

	// CSRF Protection
	csrfTokens    sync.Map // map[token]time.Time
	csrfExpiryDur = 24 * time.Hour
)

// Auth related constants and structs
const secretFilePath = "/etc/softrouter/token_secret.key"
const credentialsFilePath = "/etc/softrouter/user_credentials.json"
const metadataFilePath = "/etc/softrouter/interface_metadata.json"
const dhcpConfigPath = "/etc/softrouter/dhcp-config.json"
const dnsmasqDHCPPath = "/etc/dnsmasq.d/softrouter-dhcp.conf"

// tokenSecret is loaded at runtime from a protected file
var tokenSecret []byte

func loadTokenSecret() {
	data, err := os.ReadFile(secretFilePath)
	if err != nil {
		// SECURITY FIX (MEDIUM-2): Fail-safe approach - refuse to start without secret
		// Authentication security is non-negotiable
		log.Fatal("CRITICAL: token_secret.key not found. Refusing to start without cryptographic secret.")
		// System will exit - no fallback
	}
	tokenSecret = data
}

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"` // SHA256 hashed
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Config represents the system configuration
type Config struct {
	AdGuard         AdGuardConfig   `json:"adguard"`
	TLS             TLSConfig       `json:"tls"`
	CORS            CORSConfig      `json:"cors"`
	ProtectedSubnet string          `json:"protected_subnet"`
	WebAccess       WebAccessConfig `json:"web_access"`

	// Merged AppConfig fields
	CloudflareToken string `json:"cf_token"`
	AdBlocker       string `json:"ad_blocker"` // "none", "adguard", "pihole"
	OpenVPNPort     int    `json:"openvpn_port"`
	VPNServer       struct {
		Endpoint     string `json:"endpoint"`      // Empty = auto-detect, or IP/hostname
		EndpointType string `json:"endpoint_type"` // "auto", "ip", "hostname"
		Port         int    `json:"port"`
		Protocol     string `json:"protocol"`
	} `json:"vpn_server"`
}

type WebAccessConfig struct {
	AllowWAN     bool `json:"allow_wan"`
	WANPortHTTP  int  `json:"wan_port_http"`
	WANPortHTTPS int  `json:"wan_port_https"`
}

type AdGuardConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	Port     string `json:"port"` // Default ":443"
}

type CORSConfig struct {
	AllowedOrigins []string `json:"allowed_origins"`
}

var (
	config     Config
	configLock sync.RWMutex
	configPath = "/etc/softrouter/config.json"
)

func initWireGuard() {
	configDir := "/etc/softrouter"
	wgDir := "/etc/wireguard"
	os.MkdirAll(configDir, 0755)
	os.MkdirAll(wgDir, 0700)

	privPath := filepath.Join(configDir, "vpn_server_private.key")
	pubPath := filepath.Join(configDir, "vpn_server_public.key")
	confPath := filepath.Join(wgDir, "wg0.conf")

	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		fmt.Println("Initializing WireGuard Server Keys...")
		privKey, err := runPrivilegedOutput("wg", "genkey")
		if err != nil {
			log.Fatalf("CRITICAL: WireGuard key generation failed: %v", err)
		}
		if len(strings.TrimSpace(string(privKey))) == 0 {
			log.Fatalf("CRITICAL: WireGuard generated empty private key")
		}
		if err := os.WriteFile(privPath, privKey, 0600); err != nil {
			log.Fatalf("CRITICAL: Failed to write WireGuard private key: %v", err)
		}

		pubKey, err := deriveWireGuardPublicKey(privKey)
		if err != nil {
			log.Fatalf("CRITICAL: WireGuard public key derivation failed: %v", err)
		}
		if err := os.WriteFile(pubPath, pubKey, 0644); err != nil {
			log.Fatalf("CRITICAL: Failed to write WireGuard public key: %v", err)
		}
	}

	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		fmt.Println("Initializing WireGuard Base Config...")
		privData, err := os.ReadFile(privPath)
		if err != nil {
			log.Fatalf("CRITICAL: Failed to read WireGuard private key for config: %v", err)
		}
		baseConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.1/24\nListenPort = 51820\nPostUp = nft add table inet wg-filter; nft add chain inet wg-filter postrouting { type nat hook postrouting priority 100; policy accept; }; nft add rule inet wg-filter postrouting oifname \"*\" masquerade\nPostDown = nft delete table inet wg-filter\n", strings.TrimSpace(string(privData)))
		if err := os.WriteFile(confPath, []byte(baseConf), 0600); err != nil {
			log.Fatalf("CRITICAL: Failed to write WireGuard config: %v", err)
		}
	}
}

type UpdateCredsRequest struct {
	NewUsername string `json:"newUsername"`
	NewPassword string `json:"newPassword"`
}

// SystemStatus represents the basic health and info
type SystemStatus struct {
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Uptime      string    `json:"uptime"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsed  uint64    `json:"memory_used"`
	MemoryTotal uint64    `json:"memory_total"`
	Timestamp   time.Time `json:"timestamp"`
}

// Response cache for expensive operations
type CachedResponse struct {
	Data      interface{}
	Timestamp time.Time
	mu        sync.RWMutex
}

// Global caches for performance optimization
var (
	statusCache   *CachedResponse
	statusCacheMu sync.RWMutex
	cacheDuration = 5 * time.Second // Cache responses for 5 seconds
)

// InterfaceInfo represents a network interface
type InterfaceInfo struct {
	Index         int      `json:"index"`
	Name          string   `json:"name"`
	MAC           string   `json:"mac"`
	IPAddresses   []string `json:"ip_addresses"`   // IPv4 addresses
	IPv6Addresses []string `json:"ipv6_addresses"` // IPv6 addresses
	MTU           int      `json:"mtu"`
	Flags         string   `json:"flags"`
	IsUp          bool     `json:"is_up"`
	BytesSent     uint64   `json:"bytes_sent,omitempty"` // Placeholder
	BytesRecv     uint64   `json:"bytes_recv,omitempty"` // Placeholder
}

// --- NFTables Structs ---

type NftablesRoot struct {
	Nftables []map[string]interface{} `json:"nftables"`
}

type FirewallRule struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Handle  int    `json:"handle"`
	Comment string `json:"comment"`
	Raw     string `json:"raw"`
}

// DNSStats represents aggregate metrics from the ad-blocker
type DNSStats struct {
	TotalQueries      int         `json:"total_queries"`
	BlockedFiltering  int         `json:"blocked_filtering"`
	BlockedPercentage float64     `json:"blocked_percentage"`
	TopBlocked        []TopDomain `json:"top_blocked"`
	TopQueries        []TopDomain `json:"top_queries"`
	TopClients        []TopDomain `json:"top_clients"`
}

type TopDomain struct {
	Domain string `json:"domain"`
	Hits   int    `json:"hits"`
}

// ServiceStatus represents a managed service (DHCP, DNS, VPN)
type ServiceStatus struct {
	Name      string `json:"name"`
	ServiceID string `json:"service_id"`
	Status    string `json:"status"` // Running, Stopped, Error
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
}

// InterfaceMetadata stores custom labels and descriptions for interfaces
type InterfaceMetadata struct {
	InterfaceName string `json:"interface_name"`
	Label         string `json:"label"`       // WAN, LAN, DMZ, Guest, etc.
	Description   string `json:"description"` // User-provided description
	Color         string `json:"color"`       // Color for UI display
}

// VPNClientConfig represents a generated WireGuard client profile
type VPNClientConfig struct {
	ClientName string `json:"name"`
	PublicKey  string `json:"public_key"`
	CreatedAt  string `json:"created_at"`
	IPAddress  string `json:"ip_address"`
}

// AppConfig handles persistent settings for advanced modules
type AppConfig struct {
	CloudflareToken string          `json:"cf_token"`
	ProtectedSubnet string          `json:"protected_subnet"`
	AdBlocker       string          `json:"ad_blocker"` // "none", "adguard", "pihole"
	OpenVPNPort     int             `json:"openvpn_port"`
	WebAccess       WebAccessConfig `json:"web_access"`
	VPNServer       struct {
		Endpoint     string `json:"endpoint"`      // Empty = auto-detect, or IP/hostname
		EndpointType string `json:"endpoint_type"` // "auto", "ip", "hostname"
		Port         int    `json:"port"`
		Protocol     string `json:"protocol"`
	} `json:"vpn_server"`
}

// DHCPConfig represents DHCP configuration for a single interface
type DHCPConfig struct {
	Enabled    bool     `json:"enabled"`
	StartIP    string   `json:"startIP"`
	EndIP      string   `json:"endIP"`
	LeaseTime  string   `json:"leaseTime"` // e.g., "12h"
	Gateway    string   `json:"gateway"`
	DNSServers []string `json:"dnsServers"`

	// DHCPv6 fields
	EnabledIPv6    bool     `json:"enabledIPv6"`
	StartIPv6      string   `json:"startIPv6"`      // e.g., "2001:db8::100"
	EndIPv6        string   `json:"endIPv6"`        // e.g., "2001:db8::200"
	LeaseTimeIPv6  string   `json:"leaseTimeIPv6"`  // e.g., "12h"
	DNSServersIPv6 []string `json:"dnsServersIPv6"` // IPv6 DNS servers
}

// DHCPConfigStore manages all DHCP configurations
type DHCPConfigStore struct {
	Configs      map[string]DHCPConfig `json:"configs"` // Key: interface name
	StaticLeases []StaticLease         `json:"static_leases"`
}

// StaticLease represents a static DHCP reservation
type StaticLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// DHCPLease represents an active DHCP lease
type DHCPLease struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	Expires   string `json:"expires"`
	Interface string `json:"interface"`
}

const configFilePath = "/etc/softrouter/config.json"

// InterfaceMetadataStore manages interface metadata
type InterfaceMetadataStore struct {
	Metadata map[string]InterfaceMetadata `json:"metadata"`
}

var services = []ServiceStatus{
	{Name: "DHCP Server (dnsmasq)", Status: "Running", Version: "2.89", Uptime: "2d 4h"},
	{Name: "DNS Resolver (Unbound)", Status: "Running", Version: "1.19", Uptime: "2d 4h"},
	{Name: "WireGuard VPN", Status: "Stopped", Version: "1.0", Uptime: "-"},
	{Name: "Suricata (IDS/IPS)", Status: "Stopped", Version: "7.0", Uptime: "-"},
	{Name: "OpenVPN Server", Status: "Stopped", Version: "2.6", Uptime: "-"},
	{Name: "Cloudflare Tunnel", Status: "Stopped", Version: "2024", Uptime: "-"},
	{Name: "Ad-blocking DNS", Status: "Stopped", Version: "AdGuard/Pihole", Uptime: "-"},
}

// Security Validation Helpers

func isValidClientName(name string) bool {
	// Only allow alphanumeric, dash, and underscore
	// No dots, slashes, or other special characters to prevent path traversal
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, ch := range name {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

// writeJSON safely encodes data as JSON to the response writer with error handling
func writeJSON(w http.ResponseWriter, data interface{}) {
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("ERROR: Failed to encode JSON response: %v", err)
		// Don't write error to client if headers already sent
	}
}

// safeClose safely closes a file and logs any errors
func safeClose(f *os.File, context string) {
	if err := f.Close(); err != nil {
		log.Printf("WARNING: Failed to close file (%s): %v", context, err)
	}
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get allowed origins from config
		configLock.RLock()
		allowedOrigins := config.CORS.AllowedOrigins
		configLock.RUnlock()

		// Default to localhost for development if not configured
		if len(allowedOrigins) == 0 {
			allowedOrigins = []string{"http://localhost:5173"}
		}

		// Check if request origin is allowed
		origin := r.Header.Get("Origin")
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin || allowedOrigin == "*" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				allowed = true
				break
			}
		}

		// If origin not specifically allowed and no wildcard, don't set CORS headers
		// SECURITY FIX (MEDIUM-3): Properly reject unauthorized origins
		if !allowed {
			log.Printf("SECURITY: Blocked CORS request from unauthorized origin: %s", origin)
			// Don't set ANY CORS headers for unauthorized origins
			// This prevents CORS bypass attacks
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")

		// Security Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maxBodyMiddleware wraps all request bodies with http.MaxBytesReader to prevent
// memory exhaustion attacks (Go's equivalent of buffer overflow protection).
// SECURITY: This is a defense-in-depth measure — individual endpoints with
// multipart forms already have their own ParseMultipartForm limits.
func maxBodyMiddleware(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip body limit for multipart uploads (they have their own limits)
		contentType := r.Header.Get("Content-Type")
		if r.Body != nil && !strings.HasPrefix(contentType, "multipart/") {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// --- Audit Helpers ---

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// --- Handlers ---

// --- VPN Handlers ---

// getFirewallRules attempts to read real nftables rules
func getFirewallRules(w http.ResponseWriter, r *http.Request) {
	// Try to execute nft command
	// Note: This often requires sudo in a real environment.
	out, err := runPrivilegedOutput("nft", "-j", "list", "ruleset")

	if err != nil {
		// keeping mock fallback but simplified for brevity
		mockRules := []FirewallRule{
			{Family: "inet", Table: "filter", Chain: "INPUT", Handle: 1, Comment: "Allow Localhost", Raw: "iifname lo accept"},
		}
		w.Header().Set("X-Start-Warning", "Could not fetch NFT rules. Mock data.")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockRules)
		return
	}

	// Parse JSON output from NFTables
	var root NftablesRoot
	if err := json.Unmarshal(out, &root); err != nil {
		http.Error(w, "Failed to parse nft output", http.StatusInternalServerError)
		return
	}

	// Flatten the NFTable structure into simple rules for our UI
	var rules []FirewallRule

	for _, item := range root.Nftables {
		if ruleObj, ok := item["rule"].(map[string]interface{}); ok {
			// Extract details
			table, _ := ruleObj["table"].(string)
			family, _ := ruleObj["family"].(string)
			chain, _ := ruleObj["chain"].(string)
			handle, _ := ruleObj["handle"].(float64)
			comment, _ := ruleObj["comment"].(string)

			// The "expr" field in `nft -j list ruleset` is an ARRAY of objects.
			// Example: [{"counter":...}, {"jump":...}]
			// We want to convert this back into a human-readable string like "counter packets 0 bytes 0 jump piavpn..."
			// However, `nft` doesn't give us a "raw string" easily from JSON.
			// The user sees raw JSON in the UI currently.

			rawJsonBytes, _ := json.Marshal(ruleObj["expr"])
			rawJson := string(rawJsonBytes)

			// Simple heuristic to make the "Raw" field editable for ADDING rules.
			// When adding, we need "tcp dport 22 accept".
			// But what we READ is JSON.
			// We'll store the JSON for display, but the UI expects a statement for adding.

			rules = append(rules, FirewallRule{
				Family:  family,
				Table:   table,
				Chain:   chain,
				Handle:  int(handle),
				Comment: comment,
				Raw:     rawJson, // This is JSON. usage in UI needs to be careful.
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func addFirewallRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rule FirewallRule
	// Read body for debug purposes if needed, but Decoder is standard
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Validation
	if rule.Family == "" {
		rule.Family = "inet"
	} // Default
	if rule.Table == "" || rule.Chain == "" || rule.Raw == "" {
		http.Error(w, "Missing required fields (table, chain, raw)", http.StatusBadRequest)
		return
	}

	// Security: Sanitize firewall rule input to prevent command injection
	// Block dangerous characters and command sequences
	dangerousPatterns := []string{";", "|", "&", "$", "`", "$(", "||", "&&", "\n", "\r"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(rule.Raw, pattern) {
			http.Error(w, "Invalid characters in firewall rule", http.StatusBadRequest)
			return
		}
	}

	// Whitelist allowed nftables keywords
	allowedKeywords := []string{
		"tcp", "udp", "icmp", "ip", "ip6", "accept", "drop", "reject", "dport", "sport",
		"daddr", "saddr", "ct", "state", "established", "related", "new", "invalid",
		"counter", "packets", "bytes", "limit", "rate", "log", "prefix", "to",
	}

	// Validate that rule contains at least one allowed keyword
	hasValidKeyword := false
	ruleLower := strings.ToLower(rule.Raw)
	for _, keyword := range allowedKeywords {
		if strings.Contains(ruleLower, keyword) {
			hasValidKeyword = true
			break
		}
	}
	if !hasValidKeyword {
		http.Error(w, "Firewall rule must contain valid nftables keywords", http.StatusBadRequest)
		return
	}

	// Command: nft add rule <family> <table> <chain> <statement>
	// Note: Validating "statement" is hard, we pass it raw and hope.
	args := []string{"add", "rule", rule.Family, rule.Table, rule.Chain}

	// Split raw string by spaces (rudimentary) - this is fragile for complex rules like "ct state { established }"
	// For basic commands "tcp dport 22 accept" it works.
	// A better approach for complex args is parsing them respecting quotes/braces, but for now:
	parts := strings.Fields(rule.Raw)
	args = append(args, parts...)

	// Add comment if provided
	if rule.Comment != "" {
		args = append(args, "comment", fmt.Sprintf(`"%s"`, rule.Comment))
	}

	fmt.Printf("Executing NFT: nft %v\n", args) // Debug log

	ruleJSON, _ := json.Marshal(rule)

	if out, err := runPrivilegedCombinedOutput("nft", args...); err != nil {
		errorMsg := fmt.Sprintf("NFT Error: %s (CMD: nft %v)", string(out), args)
		fmt.Println(errorMsg)

		// Log failed firewall rule addition
		logAuditEvent(getUsernameFromToken(r), "firewall.add",
			fmt.Sprintf("%s/%s", rule.Table, rule.Chain),
			string(ruleJSON), getClientIP(r), false)

		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// Log successful firewall rule addition
	logAuditEvent(getUsernameFromToken(r), "firewall.add",
		fmt.Sprintf("%s/%s", rule.Table, rule.Chain),
		string(ruleJSON), getClientIP(r), true)

	w.WriteHeader(http.StatusOK)
}

func deleteFirewallRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	family := r.URL.Query().Get("family")
	table := r.URL.Query().Get("table")
	chain := r.URL.Query().Get("chain")
	handle := r.URL.Query().Get("handle")

	if family == "" || table == "" || chain == "" || handle == "" {
		http.Error(w, "Missing params", http.StatusBadRequest)
		return
	}

	// Command: nft delete rule <family> <table> <chain> handle <handle>
	if out, err := runPrivilegedCombinedOutput("nft", "delete", "rule", family, table, chain, "handle", handle); err != nil {
		logAuditEvent(getUsernameFromToken(r), "firewall.delete",
			fmt.Sprintf("%s/%s", table, chain),
			fmt.Sprintf("{\"handle\":\"%s\",\"error\":\"%s\"}", handle, string(out)),
			getClientIP(r), false)
		respondFirewallError(w, ErrFirewallListFailed, "NFT command failed", fmt.Errorf("%s", string(out)))
		return
	}

	logAuditEvent(getUsernameFromToken(r), "firewall.delete",
		fmt.Sprintf("%s/%s", table, chain),
		fmt.Sprintf("{\"handle\":\"%s\"}", handle), getClientIP(r), true)

	w.WriteHeader(http.StatusOK)
}

func getServiceStatus(name, serviceName string) ServiceStatus {
	status := "Stopped"
	// Check systemd status
	if err := runPrivileged("systemctl", "is-active", serviceName); err == nil {
		status = "Running"
	} else {
		// Try fallback for AdGuard if the standard lowercase doesn't match
		if serviceName == "adguardhome" {
			if err := runPrivileged("systemctl", "is-active", "AdGuardHome"); err == nil {
				status = "Running"
				serviceName = "AdGuardHome" // Use the correctly case-matched name
			}
		}
	}

	// Try to get version (generic approach, might need tailoring)
	version := "-"
	if name == "DHCP Server (dnsmasq)" {
		out, _ := runPrivilegedOutput("dnsmasq", "-v")
		if len(out) > 0 {
			parts := strings.Fields(string(out))
			if len(parts) >= 3 {
				version = parts[2]
			}
		}
	} else if name == "Cloudflare Tunnel" {
		out, _ := runPrivilegedOutput("cloudflared", "--version")
		if len(out) > 0 {
			parts := strings.Fields(string(out))
			if len(parts) >= 3 {
				version = parts[2]
			}
		}
	} else if name == "OpenVPN Server" {
		out, _ := runPrivilegedOutput("openvpn", "--version")
		if len(out) > 0 {
			parts := strings.Fields(string(out))
			if len(parts) >= 2 {
				version = parts[1]
			}
		}
	} else if name == "Ad-blocking DNS" {
		// Check for pihole version
		out, _ := runPrivilegedOutput("pihole", "-v")
		if len(out) > 0 {
			// Pi-hole version is v5.18.2 (usually)
			parts := strings.Fields(string(out))
			for i, part := range parts {
				if part == "version" && i+1 < len(parts) {
					version = parts[i+1]
					break
				}
			}
		}
	} else if name == "WireGuard VPN" {
		// WireGuard is a kernel module + tools, wg --version not always available standardly like others
		// We'll leave version as - for now
	}

	return ServiceStatus{
		Name:      name,
		ServiceID: serviceName,
		Status:    status,
		Version:   version,
		Uptime:    "-", // Complex to parse from systemctl show without more work
	}
}

func getServices(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig()
	adBlockerService := "adguardhome"
	if cfg.AdBlocker == "pihole" {
		adBlockerService = "pihole-FTL"
	}

	servicesToMonitor := []struct {
		displayName string
		serviceName string
	}{
		{"DHCP Server (dnsmasq)", "dnsmasq"},
		{"DNS Resolver (Unbound)", "unbound"},
		{"WireGuard VPN", "wg-quick@wg0"},
		{"Suricata (IDS/IPS)", "suricata"},
		{"UniFi Controller", "unifi"},
		{"OpenVPN Server", "openvpn"},
		{"Cloudflare Tunnel", "cloudflared"},
		{"Ad-blocking DNS", adBlockerService},
	}

	var results []ServiceStatus
	for _, s := range servicesToMonitor {
		results = append(results, getServiceStatus(s.displayName, s.serviceName))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// VLANCreateRequest represents a request to create a VLAN interface
type VLANCreateRequest struct {
	ParentInterface string `json:"parentInterface"` // e.g., "eth0"
	VLANId          int    `json:"vlanId"`          // e.g., 10
}

// IPConfigRequest represents IP address configuration
type IPConfigRequest struct {
	InterfaceName string `json:"interfaceName"` // e.g., "eth0" or "eth0.10"
	IPAddress     string `json:"ipAddress"`     // e.g., "192.168.10.1/24"
	Action        string `json:"action"`        // "add" or "del"
}

// InterfaceStateRequest for bringing interface up/down
type InterfaceStateRequest struct {
	InterfaceName string `json:"interfaceName"`
	State         string `json:"state"` // "up" or "down"
}

// InterfaceStats represents traffic statistics for an interface
type InterfaceStats struct {
	InterfaceName string `json:"interface_name"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	RxPackets     uint64 `json:"rx_packets"`
	TxPackets     uint64 `json:"tx_packets"`
	RxErrors      uint64 `json:"rx_errors"`
	TxErrors      uint64 `json:"tx_errors"`
	RxDropped     uint64 `json:"rx_dropped"`
	TxDropped     uint64 `json:"tx_dropped"`
}

// ConnectionInfo represents active network connections
type ConnectionInfo struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	Program    string `json:"program,omitempty"`
}

func getTrafficStats(w http.ResponseWriter, r *http.Request) {
	stats := make(map[string]InterfaceStats)

	// Read /proc/net/dev for interface statistics
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read interface stats: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, "face") {
			continue
		}

		// Parse line: "eth0: 123456 789 ..."
		parts := strings.Fields(line)
		if len(parts) < 17 {
			continue
		}

		interfaceName := strings.TrimSuffix(parts[0], ":")

		// Parse statistics (see /proc/net/dev format)
		var stat InterfaceStats
		stat.InterfaceName = interfaceName

		// RX: bytes, packets, errs, drop, fifo, frame, compressed, multicast
		fmt.Sscanf(parts[1], "%d", &stat.RxBytes)
		fmt.Sscanf(parts[2], "%d", &stat.RxPackets)
		fmt.Sscanf(parts[3], "%d", &stat.RxErrors)
		fmt.Sscanf(parts[4], "%d", &stat.RxDropped)

		// TX: bytes, packets, errs, drop, fifo, colls, carrier, compressed
		fmt.Sscanf(parts[9], "%d", &stat.TxBytes)
		fmt.Sscanf(parts[10], "%d", &stat.TxPackets)
		fmt.Sscanf(parts[11], "%d", &stat.TxErrors)
		fmt.Sscanf(parts[12], "%d", &stat.TxDropped)

		stats[interfaceName] = stat
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=2") // Stats change frequently
	json.NewEncoder(w).Encode(stats)
}

func getActiveConnections(w http.ResponseWriter, r *http.Request) {
	// Use 'ss' command to get active connections
	output, err := runPrivilegedOutput("ss", "-tunap")
	if err != nil {
		// Fallback to netstat if ss fails
		output, err = runPrivilegedOutput("netstat", "-tunap")
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get connections: %s", err.Error()), http.StatusInternalServerError)
			return
		}
	}

	connections := []ConnectionInfo{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		conn := ConnectionInfo{}

		// ss output format: Netid State Recv-Q Send-Q Local Remote
		if strings.HasPrefix(parts[0], "tcp") || strings.HasPrefix(parts[0], "udp") {
			conn.Protocol = parts[0]
			if len(parts) > 1 {
				conn.State = parts[1]
			}
			if len(parts) > 4 {
				conn.LocalAddr = parts[4]
			}
			if len(parts) > 5 {
				conn.RemoteAddr = parts[5]
			}
		}

		if conn.Protocol != "" && conn.LocalAddr != "" {
			connections = append(connections, conn)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connections)
}

// SuricataAlert represents a parsed Suricata alert from eve.json
type SuricataAlert struct {
	Timestamp   string `json:"timestamp"`
	AlertAction string `json:"alert_action"`
	Signature   string `json:"signature"`
	Severity    int    `json:"severity"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Protocol    string `json:"protocol"`
	Category    string `json:"category"`
}

// CrowdSecDecision represents a CrowdSec blocking decision
type CrowdSecDecision struct {
	ID       int    `json:"id"`
	Source   string `json:"source"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Scenario string `json:"scenario"`
	Duration string `json:"duration"`
}

// SecurityStats aggregates security statistics
type SecurityStats struct {
	SuricataStats struct {
		TotalAlerts    int      `json:"total_alerts"`
		HighSeverity   int      `json:"high_severity"`
		MediumSeverity int      `json:"medium_severity"`
		LowSeverity    int      `json:"low_severity"`
		TopSignatures  []string `json:"top_signatures"`
		AlertsLastHour int      `json:"alerts_last_hour"`
	} `json:"suricata_stats"`
	CrowdSecStats struct {
		ActiveDecisions int      `json:"active_decisions"`
		BlockedIPs      int      `json:"blocked_ips"`
		TopScenarios    []string `json:"top_scenarios"`
	} `json:"crowdsec_stats"`
}

func getSuricataAlerts(w http.ResponseWriter, r *http.Request) {
	// Read last N lines from eve.json
	limit := 100 // Get last 100 alerts

	eveLogPath := "/var/log/suricata/eve.json"

	// Check if file exists
	if _, err := os.Stat(eveLogPath); os.IsNotExist(err) {
		http.Error(w, "Suricata not installed or eve.json not found", http.StatusNotFound)
		return
	}

	// Use tail command to get last N lines
	output, err := runPrivilegedOutput("tail", "-n", fmt.Sprintf("%d", limit), eveLogPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read Suricata logs: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	alerts := []SuricataAlert{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}

		// Only process alert events
		if eventType, ok := event["event_type"].(string); !ok || eventType != "alert" {
			continue
		}

		alert := SuricataAlert{}

		if ts, ok := event["timestamp"].(string); ok {
			alert.Timestamp = ts
		}

		if alertData, ok := event["alert"].(map[string]interface{}); ok {
			if action, ok := alertData["action"].(string); ok {
				alert.AlertAction = action
			}
			if signature, ok := alertData["signature"].(string); ok {
				alert.Signature = signature
			}
			if severity, ok := alertData["severity"].(float64); ok {
				alert.Severity = int(severity)
			}
			if category, ok := alertData["category"].(string); ok {
				alert.Category = category
			}
		}

		if srcIP, ok := event["src_ip"].(string); ok {
			alert.SrcIP = srcIP
		}
		if srcPort, ok := event["src_port"].(float64); ok {
			alert.SrcPort = int(srcPort)
		}
		if destIP, ok := event["dest_ip"].(string); ok {
			alert.DestIP = destIP
		}
		if destPort, ok := event["dest_port"].(float64); ok {
			alert.DestPort = int(destPort)
		}
		if proto, ok := event["proto"].(string); ok {
			alert.Protocol = proto
		}

		alerts = append(alerts, alert)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func getCrowdSecDecisions(w http.ResponseWriter, r *http.Request) {
	// Execute cscli to get decisions
	output, err := runPrivilegedOutput("cscli", "decisions", "list", "-o", "json")
	if err != nil {
		// CrowdSec might not be installed
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]CrowdSecDecision{})
		return
	}

	var decisions []CrowdSecDecision
	if err := json.Unmarshal(output, &decisions); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse CrowdSec decisions: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(decisions)
}

// loadSystemConfig loads configuration from file or uses defaults
func loadSystemConfig() {
	configLock.Lock()
	defer configLock.Unlock()

	// Create config directory if it doesn't exist
	os.MkdirAll(filepath.Dir(configPath), 0755)

	// Try to read existing config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		// File doesn't exist, use defaults
		config = Config{
			ProtectedSubnet: "10.0.0.0/24",
			WebAccess: WebAccessConfig{
				AllowWAN:     true,
				WANPortHTTP:  980,
				WANPortHTTPS: 9443,
			},
			TLS: TLSConfig{
				Enabled:  true,
				CertFile: tlsCertPath,
				KeyFile:  tlsKeyPath,
				Port:     ":443",
			},
			AdGuard: AdGuardConfig{
				URL:      getEnvOrDefault("AGH_URL", "http://localhost:3000"),
				Username: os.Getenv("AGH_USERNAME"),
				Password: os.Getenv("AGH_PASSWORD"),
			},
		}
		// Save default config
		saveConfigLocked()
		return
	}

	// Parse existing config
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Printf("Error parsing config file: %v. Using defaults.\n", err)
	}

	// Upgrade Logic: If WebAccess is uninitialized, set defaults
	if config.WebAccess.WANPortHTTP == 0 {
		config.WebAccess.AllowWAN = true
		config.WebAccess.WANPortHTTP = 980
		config.WebAccess.WANPortHTTPS = 9443
	}

	// Upgrade Logic: If TLS is uninitialized, enable it with defaults
	if !config.TLS.Enabled && config.TLS.CertFile == "" {
		config.TLS.Enabled = true
		config.TLS.CertFile = tlsCertPath
		config.TLS.KeyFile = tlsKeyPath
		config.TLS.Port = ":443"
		saveConfigLocked()
		log.Println("Config upgrade: TLS enabled with default self-signed certificate paths")
	}

	// Environment variables override config file
	if url := os.Getenv("AGH_URL"); url != "" {
		config.AdGuard.URL = url
	}
	if username := os.Getenv("AGH_USERNAME"); username != "" {
		config.AdGuard.Username = username
	}
	if password := os.Getenv("AGH_PASSWORD"); password != "" {
		config.AdGuard.Password = password
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func saveConfigLocked() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func maskPassword(password string) string {
	if password == "" {
		return ""
	}
	return "****"
}

func getDNSStats(w http.ResponseWriter, r *http.Request) {
	stats := DNSStats{}

	// Get AdGuard Home configuration from config
	configLock.RLock()
	aghURL := config.AdGuard.URL
	aghUsername := config.AdGuard.Username
	aghPassword := config.AdGuard.Password
	configLock.RUnlock()

	if aghURL == "" {
		aghURL = "http://localhost:3000" // Fallback default
	}

	// Try to fetch stats from AdGuard Home
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", aghURL+"/control/stats", nil)
	if err != nil {
		// Fall back to mock data
		stats = getMockDNSStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
		return
	}

	// Add Basic Auth if credentials are provided
	if aghUsername != "" && aghPassword != "" {
		req.SetBasicAuth(aghUsername, aghPassword)
	}

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		// Fall back to mock data if AdGuard Home is not available
		stats = getMockDNSStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
		return
	}
	defer resp.Body.Close()

	var aghData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&aghData); err != nil {
		stats = getMockDNSStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
		return
	}

	// Parse basic statistics
	if val, ok := aghData["num_dns_queries"].(float64); ok {
		stats.TotalQueries = int(val)
	}
	if val, ok := aghData["num_blocked_filtering"].(float64); ok {
		stats.BlockedFiltering = int(val)
	}
	if stats.TotalQueries > 0 {
		stats.BlockedPercentage = (float64(stats.BlockedFiltering) / float64(stats.TotalQueries)) * 100
	}

	// Parse top blocked domains
	if topBlocked, ok := aghData["top_blocked_domains"].([]interface{}); ok {
		for i, item := range topBlocked {
			if i >= 10 { // Limit to top 10
				break
			}
			if domainData, ok := item.(map[string]interface{}); ok {
				domain := TopDomain{}
				if name, ok := domainData["name"].(string); ok {
					domain.Domain = name
				}
				if count, ok := domainData["count"].(float64); ok {
					domain.Hits = int(count)
				}
				if domain.Domain != "" {
					stats.TopBlocked = append(stats.TopBlocked, domain)
				}
			}
		}
	}

	// Parse top queried domains
	if topQueried, ok := aghData["top_queried_domains"].([]interface{}); ok {
		for i, item := range topQueried {
			if i >= 10 { // Limit to top 10
				break
			}
			if domainData, ok := item.(map[string]interface{}); ok {
				domain := TopDomain{}
				if name, ok := domainData["name"].(string); ok {
					domain.Domain = name
				}
				if count, ok := domainData["count"].(float64); ok {
					domain.Hits = int(count)
				}
				if domain.Domain != "" {
					stats.TopQueries = append(stats.TopQueries, domain)
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// getMockDNSStats returns mock data for development/testing when AdGuard Home is not available
func getMockDNSStats() DNSStats {
	return DNSStats{
		TotalQueries:      1250,
		BlockedFiltering:  340,
		BlockedPercentage: 27.2,
		TopBlocked: []TopDomain{
			{Domain: "doubleclick.net", Hits: 85},
			{Domain: "google-analytics.com", Hits: 62},
			{Domain: "facebook.com", Hits: 44},
		},
		TopQueries: []TopDomain{
			{Domain: "google.com", Hits: 210},
			{Domain: "github.com", Hits: 155},
		},
	}
}

func getSecurityStats(w http.ResponseWriter, r *http.Request) {
	stats := SecurityStats{}

	// Get Suricata statistics from eve.json
	eveLogPath := "/var/log/suricata/eve.json"
	if _, err := os.Stat(eveLogPath); err == nil {
		output, err := runPrivilegedOutput("tail", "-n", "1000", eveLogPath)
		if err == nil {
			lines := strings.Split(string(output), "\n")
			signatureCounts := make(map[string]int)

			for _, line := range lines {
				if line == "" {
					continue
				}

				var event map[string]interface{}
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					continue
				}

				if eventType, ok := event["event_type"].(string); ok && eventType == "alert" {
					stats.SuricataStats.TotalAlerts++

					if alertData, ok := event["alert"].(map[string]interface{}); ok {
						if severity, ok := alertData["severity"].(float64); ok {
							switch int(severity) {
							case 1:
								stats.SuricataStats.HighSeverity++
							case 2:
								stats.SuricataStats.MediumSeverity++
							case 3:
								stats.SuricataStats.LowSeverity++
							}
						}

						if signature, ok := alertData["signature"].(string); ok {
							signatureCounts[signature]++
						}
					}
				}
			}

			// Get top 5 signatures
			type sigCount struct {
				sig   string
				count int
			}
			var sigList []sigCount
			for sig, count := range signatureCounts {
				sigList = append(sigList, sigCount{sig, count})
			}
			// Simple sort (top 5)
			for i := 0; i < len(sigList) && i < 5; i++ {
				for j := i + 1; j < len(sigList); j++ {
					if sigList[j].count > sigList[i].count {
						sigList[i], sigList[j] = sigList[j], sigList[i]
					}
				}
				stats.SuricataStats.TopSignatures = append(stats.SuricataStats.TopSignatures, sigList[i].sig)
			}
		}
	}

	// Get CrowdSec statistics
	output, err := runPrivilegedOutput("cscli", "decisions", "list", "-o", "json")
	if err == nil {
		var decisions []map[string]interface{}
		if err := json.Unmarshal(output, &decisions); err == nil {
			stats.CrowdSecStats.ActiveDecisions = len(decisions)

			ipSet := make(map[string]bool)
			scenarioCounts := make(map[string]int)

			for _, dec := range decisions {
				if value, ok := dec["value"].(string); ok {
					ipSet[value] = true
				}
				if scenario, ok := dec["scenario"].(string); ok {
					scenarioCounts[scenario]++
				}
			}

			stats.CrowdSecStats.BlockedIPs = len(ipSet)

			// Top scenarios
			for scenario := range scenarioCounts {
				stats.CrowdSecStats.TopScenarios = append(stats.CrowdSecStats.TopScenarios, scenario)
				if len(stats.CrowdSecStats.TopScenarios) >= 5 {
					break
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// ServiceControlRequest represents the payload for controlling services
type ServiceControlRequest struct {
	ServiceName string `json:"serviceName"` // systemd service name, e.g., "dnsmasq"
	Action      string `json:"action"`      // "start", "stop", "restart"
}

func controlService(w http.ResponseWriter, r *http.Request) {
	var req ServiceControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate action
	validActions := map[string]bool{"start": true, "stop": true, "restart": true}
	if !validActions[req.Action] {
		http.Error(w, "Invalid action. Must be 'start', 'stop', or 'restart'", http.StatusBadRequest)
		return
	}

	// Validate service name (whitelist for security)
	validServices := map[string]bool{
		"dnsmasq":      true,
		"wg-quick@wg0": true,
		"wg-quick@wg1": true,
		"unbound":      true,
		"openvpn":      true,
		"cloudflared":  true,
		"adguardhome":  true,
		"AdGuardHome":  true,
		"pihole-FTL":   true,
		"suricata":     true,
		"crowdsec":     true,
		"unifi":        true,
		"softrouter":   true,
	}
	if !validServices[req.ServiceName] {
		http.Error(w, "Invalid service name: "+req.ServiceName, http.StatusBadRequest)
		return
	}

	fmt.Printf("Controlling service: %s %s\n", req.Action, req.ServiceName)

	// Execute systemctl command
	output, err := runPrivilegedCombinedOutput("systemctl", req.Action, req.ServiceName)

	if err != nil {
		errMsg := fmt.Sprintf("Service control failed: %s\nOutput: %s", err.Error(), string(output))
		fmt.Printf("ERROR: %s\n", errMsg)
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	fmt.Printf("Service %s %s successfully\n", req.ServiceName, req.Action)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Service %s %sed successfully", req.ServiceName, req.Action),
	})
}

// --- Port Forwarding Handlers ---

func listPortForwardingRules(w http.ResponseWriter, r *http.Request) {
	pfStoreLock.RLock()
	defer pfStoreLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pfStore.Rules)
}

func createPortForwardingRule(w http.ResponseWriter, r *http.Request) {
	var rule PortForwardingRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Basic Validation
	if rule.ExternalPort < 1 || rule.ExternalPort > 65535 || rule.InternalPort < 1 || rule.InternalPort > 65535 {
		http.Error(w, "Invalid ports", http.StatusBadRequest)
		return
	}
	if rule.InternalIP == "" {
		http.Error(w, "Internal IP required", http.StatusBadRequest)
		return
	}

	rule.ID = uuid.New().String()
	rule.Enabled = true // Default to enabled

	if err := addPortForwardingRule(rule); err != nil {
		respondSystemError(w, ErrNetworkRuleAddFailed, "Failed to save rule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

func removePortForwardingRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	if err := deletePortForwardingRule(id); err != nil {
		respondSystemError(w, ErrNetworkRuleDeleteFailed, "Failed to delete rule", err)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func updatePortForwardingRuleHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	var rule PortForwardingRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Basic Validation
	if rule.ExternalPort < 1 || rule.ExternalPort > 65535 || rule.InternalPort < 1 || rule.InternalPort > 65535 {
		http.Error(w, "Invalid ports", http.StatusBadRequest)
		return
	}
	if rule.InternalIP == "" {
		http.Error(w, "Internal IP required", http.StatusBadRequest)
		return
	}

	if err := updatePortForwardingRule(id, rule); err != nil {
		respondSystemError(w, ErrNetworkRuleAddFailed, "Failed to update rule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

func main() {
	loadSystemConfig()
	loadTokenSecret()
	initWireGuard()
	// initFirewall() // Deprecated by FirewallManager
	InitQoS() // 4. Initialize Networking
	// initFirewall() // Deprecated by FirewallManager
	// initPortForwarding() // Deprecated by FirewallManager

	InitFirewallManager()
	// Apply rules initially (will use default/detected WAN/LAN)
	firewallManager.ApplyFirewallRules()

	initTrafficStats()
	initDynamicRouting()

	// Initialize audit logging
	if err := initAuditLog(); err != nil {
		log.Printf("WARNING: Failed to initialize audit log: %v", err)
	}
	startAuditLogRotation()

	// Initialize rate limiters
	authLimiter := NewRateLimiter()  // 10 req/min for login
	writeLimiter := NewRateLimiter() // 30 req/min for mutations
	readLimiter := NewRateLimiter()  // 60 req/min for reads

	// Rate-limited middleware helpers
	// authWrite: auth + CSRF + rate limit for state-changing endpoints
	authWrite := func(handler http.HandlerFunc) http.HandlerFunc {
		return rateLimitMiddleware(writeLimiter, 30, time.Minute)(authMiddleware(csrfMiddleware(handler)))
	}
	// authRead: auth + rate limit for read-only endpoints
	authRead := func(handler http.HandlerFunc) http.HandlerFunc {
		return rateLimitMiddleware(readLimiter, 60, time.Minute)(authMiddleware(handler))
	}
	// Suppress unused warnings until all routes are migrated
	_ = authWrite
	_ = authRead

	cleanupCSRFTokens()   // Start CSRF token cleanup
	startSessionCleanup() // Start session cleanup

	mux := http.NewServeMux()

	// SECURITY: Wrap all handlers with a max body size limit to prevent
	// memory exhaustion attacks (Go's equivalent of buffer overflow protection).
	// Multipart endpoints (VPN upload, backup restore) have their own ParseMultipartForm limits.
	const maxBodySize = 1 << 20 // 1 MB
	wrappedMux := maxBodyMiddleware(mux, maxBodySize)

	// Public Auth Endpoints (strict 10 req/min to prevent brute force)
	mux.HandleFunc("POST /api/login", rateLimitMiddleware(authLimiter, 10, time.Minute)(login))
	mux.HandleFunc("POST /api/logout", authMiddleware(csrfMiddleware(logout)))

	// CSRF Token Endpoint  (authenticated)
	mux.HandleFunc("GET /api/csrf-token", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		token := generateCSRFToken()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}))

	// Protected Endpoints
	mux.HandleFunc("GET /api/status", authMiddleware(getSystemStatus))
	// Configuration
	mux.HandleFunc("GET /api/config", authMiddleware(getConfig))
	mux.HandleFunc("POST /api/config", authMiddleware(csrfMiddleware(updateConfig)))

	// System Setup Wizard
	mux.HandleFunc("GET /api/system/needs-setup", func(w http.ResponseWriter, r *http.Request) {
		// This endpoint doesn't require auth - it's checked before login
		needsSetup := isFirstBoot() && needsWANConfiguration()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{
			"needs_setup": needsSetup,
		})
	})

	mux.HandleFunc("POST /api/interface/metadata/bulk", authMiddleware(csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Updates []struct {
				Interface string `json:"interface"`
				Label     string `json:"label"`
			} `json:"updates"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		metaStore, _ := loadInterfaceMetadata()
		if metaStore == nil {
			metaStore = &InterfaceMetadataStore{
				Metadata: make(map[string]InterfaceMetadata),
			}
		}

		// Apply all updates
		for _, update := range req.Updates {
			metaStore.Metadata[update.Interface] = InterfaceMetadata{
				Label: update.Label,
			}
		}

		if err := saveInterfaceMetadata(metaStore); err != nil {
			http.Error(w, "Failed to save metadata", http.StatusInternalServerError)
			return
		}

		// Mark first boot complete
		if err := markFirstBootComplete(); err != nil {
			log.Printf("Warning: Failed to mark first boot complete: %v", err)
		}

		// Log audit event
		logAuditEvent(getUsernameFromToken(r), "system.setup", "interface_labels",
			fmt.Sprintf("{\"updates\":%d}", len(req.Updates)), getClientIP(r), true)

		// Regenerate firewall with new labels
		go func() {
			if err := firewallManager.ApplyFirewallRules(); err != nil {
				log.Printf("Error regenerating firewall after setup: %v", err)
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})))
	mux.HandleFunc("POST /api/auth/update-credentials", authMiddleware(csrfMiddleware(updateCredentials)))
	mux.HandleFunc("GET /api/settings", authMiddleware(getSettings))
	mux.HandleFunc("POST /api/settings", authMiddleware(csrfMiddleware(updateSettings)))

	// Audit Logs
	mux.HandleFunc("GET /api/audit/logs", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters for filtering
		startTimeStr := r.URL.Query().Get("start")
		endTimeStr := r.URL.Query().Get("end")
		actionFilter := r.URL.Query().Get("action")
		userFilter := r.URL.Query().Get("user")
		limitStr := r.URL.Query().Get("limit")

		var startTime, endTime time.Time
		var limit int = 100 // Default limit

		if startTimeStr != "" {
			if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
				startTime = t
			}
		}
		if endTimeStr != "" {
			if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
				endTime = t
			}
		}
		if limitStr != "" {
			fmt.Sscanf(limitStr, "%d", &limit)
		}

		logs, err := getAuditLogs(startTime, endTime, actionFilter, userFilter, limit)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to retrieve audit logs: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	}))

	// Backup & Restore
	mux.HandleFunc("GET /api/backup/create", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		backupData, err := createBackup()
		if err != nil {
			logAuditEvent(getUsernameFromToken(r), "backup.create", "system",
				fmt.Sprintf("{\"error\":\"%s\"}", err.Error()), getClientIP(r), false)
			http.Error(w, fmt.Sprintf("Failed to create backup: %v", err), http.StatusInternalServerError)
			return
		}

		logAuditEvent(getUsernameFromToken(r), "backup.create", "system",
			"{\"status\":\"success\"}", getClientIP(r), true)

		// Send backup as downloadable file
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"softrouter-backup-%s.json\"",
			time.Now().Format("2006-01-02-150405")))
		w.Write(backupData)
	}))

	mux.HandleFunc("POST /api/backup/restore", authMiddleware(csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Read multipart form file or JSON body
		var backupData []byte

		if err := r.ParseMultipartForm(10 << 20); err == nil { // 10 MB max
			file, _, err := r.FormFile("file")
			if err == nil {
				defer file.Close()
				backupData, err = io.ReadAll(file)
				if err != nil {
					http.Error(w, "Failed to read uploaded file", http.StatusBadRequest)
					return
				}
			}
		}

		// Fallback to JSON body if no file upload
		if len(backupData) == 0 {
			backupData, _ = io.ReadAll(r.Body)
		}

		if len(backupData) == 0 {
			http.Error(w, "No backup data provided", http.StatusBadRequest)
			return
		}

		// Restore system
		if err := restoreBackup(backupData); err != nil {
			logAuditEvent(getUsernameFromToken(r), "backup.restore", "system",
				fmt.Sprintf("{\"error\":\"%s\"}", err.Error()), getClientIP(r), false)
			http.Error(w, fmt.Sprintf("Failed to restore backup: %v", err), http.StatusInternalServerError)
			return
		}

		logAuditEvent(getUsernameFromToken(r), "backup.restore", "system",
			"{\"status\":\"success\"}", getClientIP(r), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "System restored from backup. Please review settings and restart services if needed.",
		})
	})))

	mux.HandleFunc("GET /api/backup/list", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		backups, err := listBackups()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to list backups: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(backups)
	}))

	// Session Management
	mux.HandleFunc("GET /api/sessions", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		username := getUsernameFromToken(r)
		sessions := sessionStore.ListSessions(username)
		log.Printf("GET /api/sessions: user=%s, found %d sessions", username, len(sessions))

		// Extract token value without "Bearer " prefix for comparison
		currentToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		safeInfo := make([]SessionInfo, len(sessions))
		for i, s := range sessions {
			safeInfo[i] = s.ToSafeInfo(currentToken)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(safeInfo)
	}))

	mux.HandleFunc("DELETE /api/sessions", authMiddleware(csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		tokenToRevoke := r.URL.Query().Get("token")
		username := getUsernameFromToken(r)

		if tokenToRevoke == "" {
			http.Error(w, "Token parameter required", http.StatusBadRequest)
			return
		}

		session, exists := sessionStore.GetSession("Bearer " + tokenToRevoke)
		if !exists || session.Username != username {
			http.Error(w, "Cannot revoke this session", http.StatusForbidden)
			return
		}

		sessionStore.DeleteSession("Bearer " + tokenToRevoke)
		logAuditEvent(username, "session.revoke", "token",
			fmt.Sprintf("{\"token\":\"%s\"}", tokenToRevoke), getClientIP(r), true)

		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})))

	mux.HandleFunc("GET /api/interfaces", authMiddleware(getInterfaces))
	mux.HandleFunc("POST /api/interfaces/vlan", authMiddleware(csrfMiddleware(createVLAN)))
	mux.HandleFunc("DELETE /api/interfaces/vlan", authMiddleware(csrfMiddleware(deleteVLAN)))
	mux.HandleFunc("POST /api/interfaces/ip", authMiddleware(csrfMiddleware(configureIP)))
	mux.HandleFunc("POST /api/interfaces/ipv6", authMiddleware(csrfMiddleware(configureIPv6)))
	mux.HandleFunc("POST /api/interfaces/state", authMiddleware(csrfMiddleware(setInterfaceState)))
	mux.HandleFunc("GET /api/interfaces/metadata", authMiddleware(getInterfaceMetadata))
	mux.HandleFunc("POST /api/interfaces/label", authMiddleware(csrfMiddleware(setInterfaceLabel)))

	// Bridge management
	mux.HandleFunc("GET /api/bridges", authMiddleware(getBridges))
	mux.HandleFunc("POST /api/bridges", authMiddleware(csrfMiddleware(createBridge)))
	mux.HandleFunc("DELETE /api/bridges", authMiddleware(csrfMiddleware(deleteBridge)))
	mux.HandleFunc("POST /api/bridges/member", authMiddleware(csrfMiddleware(addBridgeMember)))
	mux.HandleFunc("DELETE /api/bridges/member", authMiddleware(csrfMiddleware(removeBridgeMember)))

	// Bond management (Link Bonding / LACP)
	mux.HandleFunc("GET /api/bonds", authMiddleware(getBonds))
	mux.HandleFunc("POST /api/bonds", authMiddleware(csrfMiddleware(createBond)))
	mux.HandleFunc("DELETE /api/bonds", authMiddleware(csrfMiddleware(deleteBond)))
	mux.HandleFunc("POST /api/bonds/member", authMiddleware(csrfMiddleware(addBondMember)))
	mux.HandleFunc("DELETE /api/bonds/member", authMiddleware(csrfMiddleware(removeBondMember)))

	// Traffic Control / QoS
	mux.HandleFunc("GET /api/qos", authMiddleware(getQoSConfig))
	mux.HandleFunc("POST /api/qos", authMiddleware(csrfMiddleware(updateQoSConfig)))
	mux.HandleFunc("DELETE /api/qos", authMiddleware(csrfMiddleware(deleteQoSConfig)))

	// Diagnostics
	mux.HandleFunc("POST /api/tools/ping", authMiddleware(csrfMiddleware(handlePing)))
	mux.HandleFunc("POST /api/tools/traceroute", authMiddleware(csrfMiddleware(handleTraceroute)))
	mux.HandleFunc("GET /api/system/logs", authMiddleware(handleSystemLogs))

	// Wake-on-LAN
	mux.HandleFunc("POST /api/wol/wake", authMiddleware(csrfMiddleware(handleWakeOnLAN)))
	mux.HandleFunc("GET /api/wol/devices", authMiddleware(handleGetWoLDevices))
	mux.HandleFunc("POST /api/wol/devices", authMiddleware(csrfMiddleware(handleSaveWoLDevice)))
	mux.HandleFunc("DELETE /api/wol/devices", authMiddleware(csrfMiddleware(handleDeleteWoLDevice)))

	// GeoBlocking
	mux.HandleFunc("GET /api/geoblocking/config", authMiddleware(handleGetGeoBlockingConfig))
	mux.HandleFunc("POST /api/geoblocking/config", authMiddleware(csrfMiddleware(handleUpdateGeoBlockingConfig)))
	mux.HandleFunc("POST /api/geoblocking/download", authMiddleware(csrfMiddleware(handleDownloadCountryIPList)))

	// Traffic History
	mux.HandleFunc("GET /api/traffic/history", authMiddleware(getTrafficHistory))
	mux.HandleFunc("GET /api/firewall", authMiddleware(getFirewallRules))
	mux.HandleFunc("POST /api/firewall", authMiddleware(csrfMiddleware(addFirewallRule)))
	mux.HandleFunc("DELETE /api/firewall", authMiddleware(csrfMiddleware(deleteFirewallRule)))
	mux.HandleFunc("POST /api/firewall/confirm", authMiddleware(csrfMiddleware(confirmFirewallChanges))) // Watchdog confirmation
	mux.HandleFunc("GET /api/firewall/aliases", authMiddleware(handleFirewallAliases))
	mux.HandleFunc("POST /api/firewall/aliases", authMiddleware(csrfMiddleware(handleFirewallAliases)))
	mux.HandleFunc("PUT /api/firewall/aliases", authMiddleware(csrfMiddleware(handleFirewallAliases)))
	mux.HandleFunc("DELETE /api/firewall/aliases", authMiddleware(csrfMiddleware(handleFirewallAliases)))
	mux.HandleFunc("GET /api/services", authMiddleware(getServices))
	mux.HandleFunc("POST /api/services/control", authMiddleware(csrfMiddleware(controlService)))
	mux.HandleFunc("GET /api/traffic/stats", authMiddleware(getTrafficStats))

	mux.HandleFunc("GET /api/traffic/connections", authMiddleware(getActiveConnections))
	mux.HandleFunc("GET /api/security/suricata/alerts", authMiddleware(getSuricataAlerts))
	mux.HandleFunc("GET /api/security/crowdsec/decisions", authMiddleware(getCrowdSecDecisions))
	mux.HandleFunc("GET /api/security/stats", authMiddleware(getSecurityStats))
	mux.HandleFunc("GET /api/dns/stats", authMiddleware(getDNSStats))

	// DHCP Endpoints
	mux.HandleFunc("GET /api/dhcp/config", authMiddleware(getDHCPConfig))
	mux.HandleFunc("POST /api/dhcp/config", authMiddleware(csrfMiddleware(setDHCPConfig)))
	mux.HandleFunc("DELETE /api/dhcp/config", authMiddleware(csrfMiddleware(deleteDHCPConfig)))
	mux.HandleFunc("GET /api/dhcp/leases", authMiddleware(getDHCPLeases))
	mux.HandleFunc("POST /api/dhcp/static", authMiddleware(csrfMiddleware(addStaticLease)))
	mux.HandleFunc("DELETE /api/dhcp/static", authMiddleware(csrfMiddleware(removeStaticLease)))

	// Router Advertisement (IPv6 SLAAC)
	mux.HandleFunc("GET /api/ra/config", authMiddleware(getRAConfig))
	mux.HandleFunc("POST /api/ra/config", authMiddleware(csrfMiddleware(setRAConfig)))
	mux.HandleFunc("GET /api/ra/status", authMiddleware(getRAStatus))
	mux.HandleFunc("GET /api/network/clients", authMiddleware(getNetworkClients))

	// VPN Endpoints
	mux.HandleFunc("GET /api/vpn/clients", authMiddleware(listVPNClients))
	mux.HandleFunc("POST /api/vpn/clients", authMiddleware(csrfMiddleware(addVPNClient)))
	mux.HandleFunc("DELETE /api/vpn/clients", authMiddleware(csrfMiddleware(deleteVPNClient)))
	mux.HandleFunc("GET /api/vpn/download", authMiddleware(downloadVPNClient))

	// OpenVPN Client & PBR
	mux.HandleFunc("GET /api/vpn/client/status", authMiddleware(getVPNClientStatus))
	mux.HandleFunc("POST /api/vpn/client/config", authMiddleware(csrfMiddleware(uploadVPNClientConfig)))
	mux.HandleFunc("POST /api/vpn/client/control", authMiddleware(csrfMiddleware(controlVPNClient)))
	mux.HandleFunc("GET /api/vpn/client/policies", authMiddleware(getVPNPolicies))
	mux.HandleFunc("POST /api/vpn/client/policies", authMiddleware(csrfMiddleware(addVPNPolicy)))
	mux.HandleFunc("DELETE /api/vpn/client/policies", authMiddleware(csrfMiddleware(deleteVPNPolicy)))

	// OpenVPN Server
	mux.HandleFunc("GET /api/vpn/server-openvpn/status", authMiddleware(getOpenVPNServerStatus))
	mux.HandleFunc("POST /api/vpn/server-openvpn/setup", authMiddleware(csrfMiddleware(setupOpenVPNServer)))
	mux.HandleFunc("GET /api/vpn/server-openvpn/clients", authMiddleware(listOpenVPNClients))
	mux.HandleFunc("POST /api/vpn/server-openvpn/clients", authMiddleware(csrfMiddleware(createOpenVPNClient)))
	mux.HandleFunc("DELETE /api/vpn/server-openvpn/clients", authMiddleware(csrfMiddleware(deleteOpenVPNClient)))
	// Download .ovpn without CSRF (it's a GET with auth)
	mux.HandleFunc("GET /api/vpn/server-openvpn/download", authMiddleware(downloadOpenVPNClient))

	// VPN Endpoint configuration test
	mux.HandleFunc("GET /api/vpn/endpoint", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		endpoint, err := getVPNEndpoint()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"endpoint": endpoint,
		})
	}))

	// Port Forwarding
	mux.HandleFunc("GET /api/port-forwarding", authMiddleware(listPortForwardingRules))
	mux.HandleFunc("POST /api/port-forwarding", authMiddleware(csrfMiddleware(createPortForwardingRule)))
	mux.HandleFunc("PUT /api/port-forwarding", authMiddleware(csrfMiddleware(updatePortForwardingRuleHandler)))
	mux.HandleFunc("DELETE /api/port-forwarding", authMiddleware(csrfMiddleware(removePortForwardingRule)))

	// Routes (Static)
	mux.HandleFunc("GET /api/routes", authMiddleware(getRoutes))
	mux.HandleFunc("POST /api/routes", authMiddleware(csrfMiddleware(createRoute)))
	mux.HandleFunc("DELETE /api/routes", authMiddleware(csrfMiddleware(deleteRoute)))

	// Multi-WAN
	mux.HandleFunc("GET /api/wan", authMiddleware(getWANInterfaces))
	mux.HandleFunc("POST /api/wan", authMiddleware(csrfMiddleware(updateWANInterfaces)))

	// Dynamic Routing
	mux.HandleFunc("GET /api/routing/dynamic", authMiddleware(getDynamicRouting))
	mux.HandleFunc("POST /api/routing/dynamic", authMiddleware(csrfMiddleware(updateDynamicRouting)))

	// Interface Scheduling
	mux.HandleFunc("GET /api/schedules", authMiddleware(getSchedules))
	mux.HandleFunc("POST /api/schedules", authMiddleware(csrfMiddleware(createSchedule)))
	mux.HandleFunc("PUT /api/schedules", authMiddleware(csrfMiddleware(updateSchedule)))
	mux.HandleFunc("DELETE /api/schedules", authMiddleware(csrfMiddleware(deleteSchedule)))

	// Start Background Services
	go func() {
		// Wait a bit for network to settle then apply routes
		time.Sleep(5 * time.Second)
		initRoutes()
		initWANManager()
		initDynamicRouting()
		initScheduler()
	}()

	// SPA Static File Server
	// Serve from /var/www/softrouter/html
	staticDir := "/var/www/softrouter/html"
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If path starts with /api/, it should have been caught by mux already,
		// but we add this for safety if adding new routes.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		path := filepath.Join(staticDir, r.URL.Path)
		_, err := os.Stat(path)
		if os.IsNotExist(err) || r.URL.Path == "/" {
			// Serve index.html for React Router to handle
			http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
			return
		}
		http.FileServer(http.Dir(staticDir)).ServeHTTP(w, r)
	})

	handler := enableCORS(wrappedMux)

	// Load TLS configuration
	configLock.RLock()
	tlsPort := config.TLS.Port
	certFile := config.TLS.CertFile
	keyFile := config.TLS.KeyFile
	configLock.RUnlock()

	// Set default TLS port if not configured
	if tlsPort == "" {
		tlsPort = ":443"
	}

	// Ensure TLS certificates exist (auto-generate if missing)
	certFile, keyFile, err := ensureTLSCertificates(certFile, keyFile)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to ensure TLS certificates: %v", err)
	}

	// Add HSTS and security headers
	secureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		handler.ServeHTTP(w, r)
	})

	log.Printf("Starting HTTPS server on %s", tlsPort)

	// Start HTTP redirect server on :8080 (redirect only — no API traffic)
	go func() {
		redirectMux := http.NewServeMux()
		redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Extract host without port
			host := r.Host
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}

			// Build HTTPS URL
			target := "https://" + host
			if tlsPort != ":443" {
				target += tlsPort
			}
			target += r.URL.Path
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}

			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		log.Println("Starting HTTP->HTTPS redirect server on :8080")
		if err := http.ListenAndServe(":8080", redirectMux); err != nil {
			log.Printf("HTTP redirect server failed: %v", err)
		}
	}()

	// Start HTTPS server (always — no HTTP fallback)
	log.Fatal(http.ListenAndServeTLS(tlsPort, certFile, keyFile, secureHandler))
}
