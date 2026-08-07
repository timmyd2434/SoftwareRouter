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
	DNSPrivacy      DNSPrivacyConfig `json:"dns_privacy"`

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
	IPSEnabled           bool     `json:"ips_enabled"`
	BlockedAppCategories []string `json:"blocked_app_categories"`
	TrustProxies         bool     `json:"trust_proxies"`
	TrustedProxies       []string `json:"trusted_proxies"`
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

type DNSPrivacyConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"` // "cloudflare", "quad9", "google"
	Mode     string `json:"mode"`     // "dot", "doh"
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
	os.MkdirAll(configDir, 0750)
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
		if err := os.WriteFile(pubPath, pubKey, 0600); err != nil {
			log.Fatalf("CRITICAL: Failed to write WireGuard public key: %v", err)
		}
	}

	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		fmt.Println("Initializing WireGuard Base Config...")
		// #nosec G304 G703: path is validated or constructed from safe internal sources
		privData, err := os.ReadFile(privPath)
		if err != nil {
			log.Fatalf("CRITICAL: Failed to read WireGuard private key for config: %v", err)
		}
		baseConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.1/24\nListenPort = 51820\nPostUp = nft add table inet wg-filter; nft add chain inet wg-filter postrouting { type nat hook postrouting priority 100; policy accept; }; nft add rule inet wg-filter postrouting oifname \"*\" masquerade\nPostDown = nft delete table inet wg-filter\n", strings.TrimSpace(string(privData)))
		// #nosec G304 G703: path is validated or constructed from safe internal sources
		if err := os.WriteFile(confPath, []byte(baseConf), 0600); err != nil {
			log.Fatalf("CRITICAL: Failed to write WireGuard config: %v", err)
		}
	}
}

type UpdateCredsRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewUsername     string `json:"newUsername"`
	NewPassword     string `json:"newPassword"`
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
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	Hostname   string `json:"hostname"`
	Expires    string `json:"expires"`
	Interface  string `json:"interface"`
	Vendor     string `json:"vendor"`
	DeviceName string `json:"device_name"` // User overridden name
	DeviceType string `json:"device_type"` // User classified type
}

const configFilePath = "/etc/softrouter/config.json"

// InterfaceMetadataStore manages interface metadata
type InterfaceMetadataStore struct {
	Metadata map[string]InterfaceMetadata `json:"metadata"`
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

		// Default to empty (same-origin only) in production, but localhost:5173 in testing/dev
		if len(allowedOrigins) == 0 {
			if isTesting || os.Getenv("ENV") == "development" {
				allowedOrigins = []string{"http://localhost:5173"}
			} else {
				allowedOrigins = []string{}
			}
		}

		origin := r.Header.Get("Origin")
		allowed := false

		if origin != "" {
			// Check if same-origin (matches Host)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			sameOrigin := fmt.Sprintf("%s://%s", scheme, r.Host)
			if origin == sameOrigin {
				allowed = true
			}

			// Check allowed origins config
			if !allowed {
				for _, allowedOrigin := range allowedOrigins {
					if origin == allowedOrigin {
						allowed = true
						break
					}
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			} else {
				log.Printf("SECURITY: Blocked CORS request from unauthorized origin: %s", origin)
			}
		}

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
	configLock.RLock()
	trust := config.TrustProxies
	trustedProxies := config.TrustedProxies
	configLock.RUnlock()

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	if trust {
		isTrusted := false
		for _, proxy := range trustedProxies {
			if proxy == ip {
				isTrusted = true
				break
			}
			if _, subnet, err := net.ParseCIDR(proxy); err == nil {
				parsedIP := net.ParseIP(ip)
				if parsedIP != nil && subnet.Contains(parsedIP) {
					isTrusted = true
					break
				}
			}
		}

		// Also default to trust loopback proxies
		if ip == "127.0.0.1" || ip == "::1" {
			isTrusted = true
		}

		if isTrusted {
			// Check X-Forwarded-For header first (if behind proxy)
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				ips := strings.Split(xff, ",")
				for i := len(ips) - 1; i >= 0; i-- {
					candidate := strings.TrimSpace(ips[i])
					cTrusted := false
					for _, proxy := range trustedProxies {
						if proxy == candidate {
							cTrusted = true
							break
						}
						if _, subnet, err := net.ParseCIDR(proxy); err == nil {
							if parsedIP := net.ParseIP(candidate); parsedIP != nil && subnet.Contains(parsedIP) {
								cTrusted = true
								break
							}
						}
					}
					if candidate == "127.0.0.1" || candidate == "::1" {
						cTrusted = true
					}
					if !cTrusted {
						return candidate
					}
				}
				return strings.TrimSpace(ips[0])
			}

			// Check X-Real-IP header
			if xri := r.Header.Get("X-Real-IP"); xri != "" {
				return xri
			}
		}
	}

	return ip
}

// --- Handlers ---

// --- VPN Handlers ---



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



// loadSystemConfig loads configuration from file or uses defaults
func loadSystemConfig() {
	configLock.Lock()
	defer configLock.Unlock()

	// Create config directory if it doesn't exist
	os.MkdirAll(filepath.Dir(configPath), 0750)

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



func main() {
	loadSystemConfig()
	loadTokenSecret()
	applyInterfacesConfig() // Restore custom interfaces (Bonds, VLANs, Bridges, IP configuration)
	initWireGuard()
	InitQoS() // 4. Initialize Networking

	InitFirewallManager()
	// Apply rules initially — skip watchdog since there's no user to confirm at boot
	firewallManager.ApplyFirewallRules(true)

	initTrafficStats()
	initDeviceTraffic()
	initDynamicRouting()
	initParentalControls()
	initUPnP()
	initDeviceFingerprint()

	// Initialize audit logging
	if err := initAuditLog(); err != nil {
		log.Printf("WARNING: Failed to initialize audit log: %v", err)
	}
	startAuditLogRotation()
	initNotifications()

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
			if err := firewallManager.ApplyFirewallRules(false); err != nil {
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
			log.Printf("[ERROR] Failed to retrieve audit logs: %v", err)
			respondSystemError(w, ErrGenericInternalError, "Failed to retrieve audit logs", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	}))

	// Backup & Restore
	mux.HandleFunc("GET /api/backup/create", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		password := r.URL.Query().Get("password")
		if password == "" {
			http.Error(w, "Password parameter required to create encrypted backup", http.StatusBadRequest)
			return
		}

		backupData, err := createBackup(password)
		if err != nil {
			logAuditEvent(getUsernameFromToken(r), "backup.create", "system",
				fmt.Sprintf("{\"error\":\"%s\"}", err.Error()), getClientIP(r), false)
			respondSystemError(w, ErrSystemBackupFailed, "Failed to create backup", err)
			return
		}

		logAuditEvent(getUsernameFromToken(r), "backup.create", "system",
			"{\"status\":\"success\"}", getClientIP(r), true)

		// Send backup as downloadable encrypted file
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"softrouter-backup-%s.enc\"",
			time.Now().Format("2006-01-02-150405")))
		w.Write(backupData)
	}))

	mux.HandleFunc("POST /api/backup/restore", authMiddleware(csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB limit for backup file
		var backupData []byte
		var password string

		// Try parsing as multipart form first (standard file upload)
		if err := r.ParseMultipartForm(10 << 20); err == nil {
			file, _, err := r.FormFile("file")
			if err == nil {
				defer file.Close()
				backupData, err = io.ReadAll(file)
				if err != nil {
					http.Error(w, "Failed to read uploaded file", http.StatusBadRequest)
					return
				}
			}
			password = r.FormValue("password")
		}

		// Fallback to query parameters if form didn't provide them
		if password == "" {
			password = r.URL.Query().Get("password")
		}

		// Fallback to JSON body if not multipart
		if len(backupData) == 0 {
			// Read raw body if we couldn't parse multipart
			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil && len(bodyBytes) > 0 {
				var req struct {
					Data     []byte `json:"data"`
					Password string `json:"password"`
				}
				if err := json.Unmarshal(bodyBytes, &req); err == nil {
					backupData = req.Data
					if password == "" {
						password = req.Password
					}
				} else {
					// Assume body is raw backup bytes
					backupData = bodyBytes
				}
			}
		}

		if len(backupData) == 0 {
			http.Error(w, "No backup data provided", http.StatusBadRequest)
			return
		}

		if password == "" {
			http.Error(w, "Password is required to restore an encrypted backup", http.StatusBadRequest)
			return
		}

		// Restore system
		if err := restoreBackup(backupData, password); err != nil {
			logAuditEvent(getUsernameFromToken(r), "backup.restore", "system",
				fmt.Sprintf("{\"error\":\"%s\"}", err.Error()), getClientIP(r), false)
			respondSystemError(w, ErrSystemRestoreFailed, "Failed to restore backup", err)
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

	mux.HandleFunc("POST /api/backup/restore-local", authMiddleware(csrfMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Filename string `json:"filename"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Filename == "" {
			http.Error(w, "Filename is required", http.StatusBadRequest)
			return
		}

		if req.Password == "" {
			http.Error(w, "Password is required for local restore", http.StatusBadRequest)
			return
		}

		// Prevent path traversal
		safeName := filepath.Base(req.Filename)
		if safeName == "." || safeName == "/" {
			http.Error(w, "Invalid filename", http.StatusBadRequest)
			return
		}

		backupFilePath := filepath.Join(backupDir, safeName)
		// Read backup file
		// #nosec G304: path is constructed from safe inputs
		backupData, err := os.ReadFile(backupFilePath)
		if err != nil {
			log.Printf("ERROR: Failed to read local backup file: %v", err)
			respondSystemError(w, ErrSystemRestoreFailed, "Failed to read backup file", err)
			return
		}

		// Restore system
		if err := restoreBackup(backupData, req.Password); err != nil {
			logAuditEvent(getUsernameFromToken(r), "backup.restore_local", "system",
				fmt.Sprintf("{\"filename\":\"%s\",\"error\":\"%s\"}", safeName, err.Error()), getClientIP(r), false)
			respondSystemError(w, ErrSystemRestoreFailed, "Failed to restore backup", err)
			return
		}

		logAuditEvent(getUsernameFromToken(r), "backup.restore_local", "system",
			fmt.Sprintf("{\"filename\":\"%s\",\"status\":\"success\"}", safeName), getClientIP(r), true)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "System restored from local backup successfully.",
		})
	})))

	mux.HandleFunc("GET /api/backup/list", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		backups, err := listBackups()
		if err != nil {
			log.Printf("[ERROR] Failed to list backups: %v", err)
			respondSystemError(w, ErrGenericInternalError, "Failed to list backups", err)
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

		session, exists := sessionStore.GetSession(tokenToRevoke)
		if !exists || session.Username != username {
			http.Error(w, "Cannot revoke this session", http.StatusForbidden)
			return
		}

		sessionStore.DeleteSession(tokenToRevoke)
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
	mux.HandleFunc("POST /api/diagnostics/speedtest", authMiddleware(csrfMiddleware(handleSpeedTest)))
	mux.HandleFunc("GET /api/diagnostics/speedtest/history", authMiddleware(getSpeedTestHistory))

	// Wake-on-LAN
	mux.HandleFunc("POST /api/wol/wake", authMiddleware(csrfMiddleware(handleWakeOnLAN)))
	mux.HandleFunc("GET /api/wol/devices", authMiddleware(handleGetWoLDevices))
	mux.HandleFunc("POST /api/wol/devices", authMiddleware(csrfMiddleware(handleSaveWoLDevice)))
	mux.HandleFunc("DELETE /api/wol/devices", authMiddleware(csrfMiddleware(handleDeleteWoLDevice)))

	// GeoBlocking
	mux.HandleFunc("GET /api/geoblocking/config", authMiddleware(handleGetGeoBlockingConfig))
	mux.HandleFunc("POST /api/geoblocking/config", authMiddleware(csrfMiddleware(handleUpdateGeoBlockingConfig)))
	mux.HandleFunc("POST /api/geoblocking/download", authMiddleware(csrfMiddleware(handleDownloadCountryIPList)))

	// Suricata (IDS/IPS)
	mux.HandleFunc("GET /api/suricata/ips", authMiddleware(handleSuricataIPS))
	mux.HandleFunc("POST /api/suricata/ips", authMiddleware(csrfMiddleware(handleSuricataIPS)))
	mux.HandleFunc("GET /api/suricata/app-control", authMiddleware(handleSuricataAppControl))
	mux.HandleFunc("POST /api/suricata/app-control", authMiddleware(csrfMiddleware(handleSuricataAppControl)))

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
	mux.HandleFunc("GET /api/traffic/devices", authMiddleware(getDeviceTraffic))
	mux.HandleFunc("GET /api/traffic/device", authMiddleware(getDeviceTrafficDetail))
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

	// Parental Controls
	mux.HandleFunc("GET /api/parental/config", authMiddleware(getParentalConfigHandler))
	mux.HandleFunc("POST /api/parental/config", authMiddleware(csrfMiddleware(updateParentalConfigHandler)))

	// UPnP / NAT-PMP
	mux.HandleFunc("GET /api/upnp/config", authMiddleware(getUPnPConfigHandler))
	mux.HandleFunc("POST /api/upnp/config", authMiddleware(csrfMiddleware(updateUPnPConfigHandler)))

	// Device Metadata
	mux.HandleFunc("POST /api/devices/meta", authMiddleware(csrfMiddleware(updateDeviceMetaHandler)))
	
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

	// Notifications
	mux.HandleFunc("GET /api/notifications/config", authMiddleware(getNotificationConfig))
	mux.HandleFunc("POST /api/notifications/config", authMiddleware(csrfMiddleware(updateNotificationConfig)))
	mux.HandleFunc("POST /api/notifications/test", authMiddleware(csrfMiddleware(sendTestNotification)))

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

		if isFirstBoot() && needsWANConfiguration() {
			ensureFallbackNetwork()
		}
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

		// SECURITY: Prevent path traversal outside staticDir
		cleanPath := filepath.Join(staticDir, filepath.Clean(r.URL.Path))
		if !strings.HasPrefix(cleanPath, staticDir) {
			http.NotFound(w, r)
			return
		}

		_, err := os.Stat(cleanPath)
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
		redirectServer := &http.Server{
			Addr:         ":8080",
			Handler:      redirectMux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		if err := redirectServer.ListenAndServe(); err != nil {
			log.Printf("HTTP redirect server failed: %v", err)
		}
	}()

	// Start HTTPS server (always — no HTTP fallback)
	secureServer := &http.Server{
		Addr:         tlsPort,
		Handler:      secureHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Fatal(secureServer.ListenAndServeTLS(certFile, keyFile))
}
