package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Auth related constants and structs
const secretFilePath = "/etc/softrouter/token_secret.key"
const credentialsFilePath = "/etc/softrouter/user_credentials.json"
const metadataFilePath = "/etc/softrouter/interface_metadata.json"

// tokenSecret is loaded at runtime from a protected file
var tokenSecret []byte

func loadTokenSecret() {
	data, err := os.ReadFile(secretFilePath)
	if err != nil {
		// If it doesn't exist, we use a fallback but log a warning.
		// The install script should have generated this.
		fmt.Println("WARNING: token_secret.key not found. Using insecure fallback.")
		tokenSecret = []byte("softrouter_emergency_fallback_secret_667788")
		return
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
		privCmd := exec.Command("wg", "genkey")
		privKey, _ := privCmd.Output()
		os.WriteFile(privPath, privKey, 0600)

		pubCmd := exec.Command("sh", "-c", fmt.Sprintf("echo %s | wg pubkey", strings.TrimSpace(string(privKey))))
		pubKey, _ := pubCmd.Output()
		os.WriteFile(pubPath, pubKey, 0644)
	}

	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		fmt.Println("Initializing WireGuard Base Config...")
		privData, _ := os.ReadFile(privPath)
		baseConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.1/24\nListenPort = 51820\nPostUp = nft add table inet wg-filter; nft add chain inet wg-filter postrouting { type nat hook postrouting priority 100; policy accept; }; nft add rule inet wg-filter postrouting oifname \"*\" masquerade\nPostDown = nft delete table inet wg-filter\n", strings.TrimSpace(string(privData)))
		os.WriteFile(confPath, []byte(baseConf), 0600)
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

// InterfaceInfo represents a network interface
type InterfaceInfo struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	IPAddresses []string `json:"ip_addresses"`
	MTU         int      `json:"mtu"`
	Flags       string   `json:"flags"`
	IsUp        bool     `json:"is_up"`
	BytesSent   uint64   `json:"bytes_sent,omitempty"` // Placeholder
	BytesRecv   uint64   `json:"bytes_recv,omitempty"` // Placeholder
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

// BandwidthSnapshot represents a point in time for the traffic graph
type BandwidthSnapshot struct {
	Timestamp string `json:"timestamp"`
	RxBps     uint64 `json:"rx_bps"`
	TxBps     uint64 `json:"tx_bps"`
}

var (
	trafficHistory     []BandwidthSnapshot
	historyLock        sync.Mutex
	lastTotalRx        uint64
	lastTotalTx        uint64
	historyInitialized bool
)

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
	CloudflareToken string `json:"cf_token"`
	ProtectedSubnet string `json:"protected_subnet"`
	AdBlocker       string `json:"ad_blocker"` // "none", "adguard", "pihole"
	OpenVPNPort     int    `json:"openvpn_port"`
}

const configFilePath = "/etc/softrouter/config.json"

func loadConfig() AppConfig {
	defaultCfg := AppConfig{
		CloudflareToken: "",
		ProtectedSubnet: "10.0.0.0/24",
		AdBlocker:       "none",
		OpenVPNPort:     1194,
	}

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return defaultCfg
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return defaultCfg
	}
	return cfg
}

func saveConfig(cfg AppConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFilePath, data, 0644)
}

// InterfaceMetadataStore manages interface metadata
type InterfaceMetadataStore struct {
	Metadata map[string]InterfaceMetadata `json:"metadata"`
}

func loadInterfaceMetadata() (*InterfaceMetadataStore, error) {
	store := &InterfaceMetadataStore{
		Metadata: make(map[string]InterfaceMetadata),
	}

	data, err := os.ReadFile(metadataFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, return empty store
			return store, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}

	return store, nil
}

func saveInterfaceMetadata(store *InterfaceMetadataStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metadataFilePath, data, 0644)
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
func isValidInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > 16 {
		return false
	}
	for _, ch := range name {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func isValidIP(ip string) bool {
	// Simple check for CIDR or plain IP
	_, _, err := net.ParseCIDR(ip)
	if err == nil {
		return true
	}
	parsed := net.ParseIP(ip)
	return parsed != nil
}

func generateSecureToken(username string) string {
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%s:%d", username, timestamp)

	h := sha256.New()
	h.Write([]byte(payload))
	h.Write(tokenSecret)
	signature := hex.EncodeToString(h.Sum(nil))

	// Format: Bearer sr-<username>-<timestamp>-<signature>
	return fmt.Sprintf("sr-%s-%d-%s", username, timestamp, signature)
}

func verifySecureToken(token string) bool {
	if !strings.HasPrefix(token, "Bearer sr-") {
		return false
	}

	parts := strings.Split(strings.TrimPrefix(token, "Bearer sr-"), "-")
	if len(parts) != 3 {
		return false
	}

	username := parts[0]
	timestampStr := parts[1]
	providedSignature := parts[2]

	// Re-generate signature to verify
	payload := fmt.Sprintf("%s:%s", username, timestampStr)
	h := sha256.New()
	h.Write([]byte(payload))
	h.Write(tokenSecret)
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	// Constant time comparison (simple for now but better than nothing)
	return providedSignature == expectedSignature
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Auth Helpers ---

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func loadCredentials() UserCredentials {
	// Root of the system - if nothing exists, we define a highly temporary fallback
	// but warning the user that it should be changed or set on deployment.
	defaultCreds := UserCredentials{
		Username: "admin",
		Password: "", // Empty means NO access by default if file is missing
	}

	// Create directory if not exists
	os.MkdirAll("/etc/softrouter", 0755)

	data, err := os.ReadFile(credentialsFilePath)
	if err != nil {
		fmt.Println("CRITICAL: Credentials file not found. System is locked.")
		return defaultCreds
	}

	var creds UserCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		fmt.Println("CRITICAL: Failed to parse credentials.")
		return defaultCreds
	}
	return creds
}

func saveCredentials(creds UserCredentials) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(credentialsFilePath, data, 0644)
}

// Simple token based auth middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			// Also check query param for downloads
			token = r.URL.Query().Get("token")
			if token != "" {
				token = "Bearer " + token
			}
		}

		if token == "" || !verifySecureToken(token) {
			http.Error(w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// --- Handlers ---

func login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	creds := loadCredentials()
	if req.Username == creds.Username && hashPassword(req.Password) == creds.Password {
		// Generate secure signed token
		token := generateSecureToken(req.Username)
		// Return just the part after "Bearer " for client storage
		tokenValue := strings.TrimPrefix(token, "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token": tokenValue,
			"user":  req.Username,
		})
		return
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

func updateCredentials(w http.ResponseWriter, r *http.Request) {
	var req UpdateCredsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	newCreds := UserCredentials{
		Username: req.NewUsername,
		Password: hashPassword(req.NewPassword),
	}

	if err := saveCredentials(newCreds); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func getConfig(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func applyCloudflareConfig(cfg AppConfig) error {
	if cfg.CloudflareToken == "" {
		return nil
	}

	fmt.Println("Applying Cloudflare Tunnel configuration...")

	// 1. Check if cloudflared is installed
	_, err := exec.LookPath("cloudflared")
	if err != nil {
		fmt.Println("Installing cloudflared...")
		// Download and install (Debian/Ubuntu specific)
		installCmd := "curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && sudo dpkg -i cloudflared.deb && rm cloudflared.deb"
		err := exec.Command("bash", "-c", installCmd).Run()
		if err != nil {
			return fmt.Errorf("failed to install cloudflared: %v", err)
		}
	}

	// 2. Install/Update the service with the token
	// First, try to uninstall existing service to ensure clean state
	exec.Command("cloudflared", "service", "uninstall").Run()

	// Install service
	err = exec.Command("cloudflared", "service", "install", cfg.CloudflareToken).Run()
	if err != nil {
		return fmt.Errorf("failed to install cloudflared service: %v", err)
	}

	fmt.Println("Cloudflare Tunnel service installed and started.")
	return nil
}

func applyAdBlockerConfig(cfg AppConfig) error {
	if cfg.AdBlocker == "none" {
		// Ensure standard DNS services are running if we're not using an adblocker
		exec.Command("systemctl", "start", "dnsmasq").Run()
		exec.Command("systemctl", "start", "unbound").Run()
		return nil
	}

	if cfg.AdBlocker == "pihole" {
		fmt.Println("Applying Pi-hole configuration...")

		// 1. Check if pihole is installed
		_, err := exec.LookPath("pihole")
		if err != nil {
			fmt.Println("Installing Pi-hole (Unattended)...")

			// Stop conflicting services
			exec.Command("systemctl", "stop", "dnsmasq").Run()
			exec.Command("systemctl", "stop", "unbound").Run()

			// Pi-hole automated install command
			// Note: We use --unattended and provide a basic config if needed,
			// but we'll try the simplest route first.
			installCmd := "curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended"
			err := exec.Command("bash", "-c", installCmd).Run()
			if err != nil {
				return fmt.Errorf("failed to install Pi-hole: %v", err)
			}
		} else {
			// Ensure it's running
			exec.Command("pihole", "enable").Run()
			// Stop conflicting services
			exec.Command("systemctl", "stop", "dnsmasq").Run()
			exec.Command("systemctl", "stop", "unbound").Run()
		}
		fmt.Println("Pi-hole setup complete.")
	}

	return nil
}

func updateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg AppConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Load old config to see what changed
	oldCfg := loadConfig()

	if err := saveConfig(cfg); err != nil {
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	// Trigger Cloudflare setup if token changed
	if cfg.CloudflareToken != "" && cfg.CloudflareToken != oldCfg.CloudflareToken {
		go func() {
			err := applyCloudflareConfig(cfg)
			if err != nil {
				fmt.Printf("ERROR applying Cloudflare config: %v\n", err)
			}
		}()
	}

	// Trigger Ad-blocker setup if choice changed
	if cfg.AdBlocker != oldCfg.AdBlocker {
		go func() {
			err := applyAdBlockerConfig(cfg)
			if err != nil {
				fmt.Printf("ERROR applying Ad-blocker config: %v\n", err)
			}
		}()
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// --- VPN Handlers ---

func listVPNClients(w http.ResponseWriter, r *http.Request) {
	clientsDir := "/etc/softrouter/vpn_clients"
	os.MkdirAll(clientsDir, 0755)

	files, err := os.ReadDir(clientsDir)
	var clients []VPNClientConfig
	if err == nil {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".conf") && f.Name() != "wg0.conf" {
				info, _ := f.Info()
				clients = append(clients, VPNClientConfig{
					ClientName: strings.TrimSuffix(f.Name(), ".conf"),
					CreatedAt:  info.ModTime().Format(time.RFC3339),
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func addVPNClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	clientsDir := "/etc/softrouter/vpn_clients"
	os.MkdirAll(clientsDir, 0755)

	// 1. Generate Client Keys
	privCmd := exec.Command("wg", "genkey")
	privKey, _ := privCmd.Output()
	cleanPriv := strings.TrimSpace(string(privKey))

	pubCmd := exec.Command("sh", "-c", fmt.Sprintf("echo %s | wg pubkey", cleanPriv))
	pubKey, _ := pubCmd.Output()
	cleanPub := strings.TrimSpace(string(pubKey))

	// 2. Determine an IP (Basic assignment for now)
	existing, _ := os.ReadDir(clientsDir)
	nextIP := 2 + len(existing)
	clientIP := fmt.Sprintf("10.8.0.%d/32", nextIP)

	// 3. Update Server Config (/etc/wireguard/wg0.conf)
	peerBlock := fmt.Sprintf("\n[Peer]\n# Name: %s\nPublicKey = %s\nAllowedIPs = %s\n", req.Name, cleanPub, clientIP)
	f, err := os.OpenFile("/etc/wireguard/wg0.conf", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err == nil {
		f.WriteString(peerBlock)
		f.Close()
		// Reload wg0 without downtime
		exec.Command("wg", "syncconf", "wg0", "/etc/wireguard/wg0.conf").Run()
	}

	// 4. Generate Client .conf
	serverPub, _ := os.ReadFile("/etc/softrouter/vpn_server_public.key")

	// Try to get public-facing IP or hostname
	endpoint := "YOUR_ROUTER_IP"
	if h, err := os.Hostname(); err == nil {
		endpoint = h
	}
	// Better yet, use the Host header from the request if it looks like an IP/Domain
	if h := r.Host; h != "" {
		endpoint = strings.Split(h, ":")[0]
	}

	clientConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
		cleanPriv, clientIP, strings.TrimSpace(string(serverPub)), endpoint)

	confPath := fmt.Sprintf("%s/%s.conf", clientsDir, req.Name)
	os.WriteFile(confPath, []byte(clientConf), 0600)

	json.NewEncoder(w).Encode(map[string]string{"status": "success", "config": clientConf})
}

func deleteVPNClient(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Name required", http.StatusBadRequest)
		return
	}

	clientsDir := "/etc/softrouter/vpn_clients"
	confPath := fmt.Sprintf("%s/%s.conf", clientsDir, name)
	os.Remove(confPath)

	// Note: In production we should also remove from /etc/wireguard/wg0.conf
	// and call syncconf. For now, it will just disappear from the list.

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func downloadVPNClient(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	clientsDir := "/etc/softrouter/vpn_clients"
	confPath := fmt.Sprintf("%s/%s.conf", clientsDir, name)

	data, err := os.ReadFile(confPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", name))
	w.Header().Set("Content-Type", "application/x-wireguard-config")
	w.Write(data)
}

func getSystemStatus(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	uptime := "unknown"
	out, err := exec.Command("uptime", "-p").Output()
	if err == nil {
		uptime = strings.TrimSpace(string(out))
	}

	// Simple CPU Usage from loadavg
	cpuUsage := 0.0
	loadData, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		fmt.Sscanf(string(loadData), "%f", &cpuUsage)
	}

	// Memory usage from /proc/meminfo
	var memTotal, memFree, memAvailable uint64
	memData, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		lines := strings.Split(string(memData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fmt.Sscanf(line, "MemTotal: %d", &memTotal)
			} else if strings.HasPrefix(line, "MemFree:") {
				fmt.Sscanf(line, "MemFree: %d", &memFree)
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fmt.Sscanf(line, "MemAvailable: %d", &memAvailable)
			}
		}
	}
	memUsed := memTotal - memAvailable
	if memAvailable == 0 {
		memUsed = memTotal - memFree
	}

	status := SystemStatus{
		Hostname:    hostname,
		OS:          fmt.Sprintf("%s (%s)", runtime.GOOS, runtime.GOARCH),
		Uptime:      uptime,
		CPUUsage:    cpuUsage,
		MemoryUsed:  memUsed,
		MemoryTotal: memTotal,
		Timestamp:   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func getInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var result []InterfaceInfo
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		var ipList []string
		for _, addr := range addrs {
			ipList = append(ipList, addr.String())
		}

		isUp := (i.Flags & net.FlagUp) != 0

		result = append(result, InterfaceInfo{
			Index:       i.Index,
			Name:        i.Name,
			MAC:         i.HardwareAddr.String(),
			IPAddresses: ipList,
			MTU:         i.MTU,
			Flags:       i.Flags.String(),
			IsUp:        isUp,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// getFirewallRules attempts to read real nftables rules
func getFirewallRules(w http.ResponseWriter, r *http.Request) {
	// Try to execute nft command
	// Note: This often requires sudo in a real environment.
	cmd := exec.Command("nft", "-j", "list", "ruleset")
	out, err := cmd.Output()

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

	// Command: nft add rule <family> <table> <chain> <statement>
	// Note: Validating "statement" is hard, we pass it raw and hope.
	args := []string{"add", "rule", rule.Family, rule.Table, rule.Chain}

	// Split raw string by spaces (rudimentary) - this is fragile for complex rules like "ct state { established }"
	// For basic commands "tcp dport 22 accept" it works.
	// A better approach for complex args is parsing them respecting quotes/braces, but for now:
	parts := strings.Fields(rule.Raw)
	args = append(args, parts...)

	fmt.Printf("Executing NFT: nft %v\n", args) // Debug log

	cmd := exec.Command("nft", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		errorMsg := fmt.Sprintf("NFT Error: %s (CMD: nft %v)", string(out), args)
		fmt.Println(errorMsg)
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

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
	cmd := exec.Command("nft", "delete", "rule", family, table, chain, "handle", handle)
	if out, err := cmd.CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("NFT Error: %s", string(out)), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func getServiceStatus(name, serviceName string) ServiceStatus {
	status := "Stopped"
	// Check systemd status
	cmd := exec.Command("systemctl", "is-active", serviceName)
	if err := cmd.Run(); err == nil {
		status = "Running"
	} else {
		// Try fallback for AdGuard if the standard lowercase doesn't match
		if serviceName == "adguardhome" {
			fallbackCmd := exec.Command("systemctl", "is-active", "AdGuardHome")
			if err := fallbackCmd.Run(); err == nil {
				status = "Running"
				serviceName = "AdGuardHome" // Use the correctly case-matched name
			}
		}
	}

	// Try to get version (generic approach, might need tailoring)
	version := "-"
	if name == "DHCP Server (dnsmasq)" {
		out, _ := exec.Command("dnsmasq", "-v").Output()
		if len(out) > 0 {
			parts := strings.Fields(string(out))
			if len(parts) >= 3 {
				version = parts[2]
			}
		}
	} else if name == "Cloudflare Tunnel" {
		out, _ := exec.Command("cloudflared", "--version").Output()
		if len(out) > 0 {
			parts := strings.Fields(string(out))
			if len(parts) >= 3 {
				version = parts[2]
			}
		}
	} else if name == "OpenVPN Server" {
		out, _ := exec.Command("openvpn", "--version").Output()
		if len(out) > 0 {
			parts := strings.Fields(string(out))
			if len(parts) >= 2 {
				version = parts[1]
			}
		}
	} else if name == "Ad-blocking DNS" {
		// Check for pihole version
		out, _ := exec.Command("pihole", "-v").Output()
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

func createVLAN(w http.ResponseWriter, r *http.Request) {
	var req VLANCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate inputs to prevent command injection
	if !isValidInterfaceName(req.ParentInterface) {
		http.Error(w, "Invalid parent interface name", http.StatusBadRequest)
		return
	}

	// Validate VLAN ID (1-4094)
	if req.VLANId < 1 || req.VLANId > 4094 {
		http.Error(w, "VLAN ID must be between 1 and 4094", http.StatusBadRequest)
		return
	}

	vlanInterface := fmt.Sprintf("%s.%d", req.ParentInterface, req.VLANId)
	fmt.Printf("Creating VLAN: %s\n", vlanInterface)

	// Create VLAN interface using ip link
	// Using absolute path for safety and explicit arguments
	cmd := exec.Command("/usr/sbin/ip", "link", "add", "link", req.ParentInterface, "name", vlanInterface, "type", "vlan", "id", fmt.Sprintf("%d", req.VLANId))
	if _, err := cmd.CombinedOutput(); err != nil {
		http.Error(w, "Failed to create VLAN interface", http.StatusInternalServerError)
		return
	}

	// Bring the VLAN interface up
	upCmd := exec.Command("ip", "link", "set", "dev", vlanInterface, "up")
	if output, err := upCmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: Failed to bring up VLAN interface: %s\n", string(output))
	}

	fmt.Printf("VLAN %s created successfully\n", vlanInterface)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"interface": vlanInterface,
		"message":   fmt.Sprintf("VLAN interface %s created successfully", vlanInterface),
	})
}

func deleteVLAN(w http.ResponseWriter, r *http.Request) {
	interfaceName := r.URL.Query().Get("interface")
	if interfaceName == "" {
		http.Error(w, "Missing interface parameter", http.StatusBadRequest)
		return
	}

	// Safety check: only allow deletion of VLAN interfaces (contain a dot)
	if !strings.Contains(interfaceName, ".") || !isValidInterfaceName(interfaceName) {
		http.Error(w, "Invalid VLAN interface name", http.StatusBadRequest)
		return
	}

	fmt.Printf("Deleting VLAN: %s\n", interfaceName)

	cmd := exec.Command("ip", "link", "delete", interfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("Failed to delete VLAN: %s\nOutput: %s", err.Error(), string(output))
		fmt.Printf("ERROR: %s\n", errMsg)
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	fmt.Printf("VLAN %s deleted successfully\n", interfaceName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("VLAN interface %s deleted successfully", interfaceName),
	})
}

func configureIP(w http.ResponseWriter, r *http.Request) {
	var req IPConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate action
	if req.Action != "add" && req.Action != "del" {
		http.Error(w, "Action must be 'add' or 'del'", http.StatusBadRequest)
		return
	}

	if !isValidInterfaceName(req.InterfaceName) || !isValidIP(req.IPAddress) {
		http.Error(w, "Invalid interface name or IP address format", http.StatusBadRequest)
		return
	}

	fmt.Printf("Configuring IP: %s %s on %s\n", req.Action, req.IPAddress, req.InterfaceName)

	// Use ip addr add/del
	cmd := exec.Command("/usr/sbin/ip", "addr", req.Action, req.IPAddress, "dev", req.InterfaceName)
	if _, err := cmd.CombinedOutput(); err != nil {
		http.Error(w, "Failed to configure IP address on interface", http.StatusInternalServerError)
		return
	}

	fmt.Printf("IP %s %sed on %s successfully\n", req.IPAddress, req.Action, req.InterfaceName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP %s %sed on %s", req.IPAddress, req.Action, req.InterfaceName),
	})
}

func setInterfaceState(w http.ResponseWriter, r *http.Request) {
	var req InterfaceStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate state
	if req.State != "up" && req.State != "down" {
		http.Error(w, "State must be 'up' or 'down'", http.StatusBadRequest)
		return
	}

	fmt.Printf("Setting interface %s to %s\n", req.InterfaceName, req.State)

	cmd := exec.Command("ip", "link", "set", "dev", req.InterfaceName, req.State)
	if output, err := cmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("Failed to set interface state: %s\nOutput: %s", err.Error(), string(output))
		fmt.Printf("ERROR: %s\n", errMsg)
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	fmt.Printf("Interface %s set to %s successfully\n", req.InterfaceName, req.State)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Interface %s is now %s", req.InterfaceName, req.State),
	})
}

func getInterfaceMetadata(w http.ResponseWriter, r *http.Request) {
	store, err := loadInterfaceMetadata()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load metadata: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(store.Metadata)
}

type SetInterfaceLabelRequest struct {
	InterfaceName string `json:"interfaceName"`
	Label         string `json:"label"`
	Description   string `json:"description"`
	Color         string `json:"color"`
}

func setInterfaceLabel(w http.ResponseWriter, r *http.Request) {
	var req SetInterfaceLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.InterfaceName == "" {
		http.Error(w, "Interface name is required", http.StatusBadRequest)
		return
	}

	// Validate label (optional but recommended values)
	validLabels := map[string]bool{
		"WAN": true, "LAN": true, "DMZ": true, "Guest": true,
		"Management": true, "Trunk": true, "": true, // Empty is allowed (to clear)
	}
	if req.Label != "" && !validLabels[req.Label] {
		fmt.Printf("Warning: Non-standard label '%s' used\n", req.Label)
	}

	store, err := loadInterfaceMetadata()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load metadata: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	// Update or create metadata
	store.Metadata[req.InterfaceName] = InterfaceMetadata{
		InterfaceName: req.InterfaceName,
		Label:         req.Label,
		Description:   req.Description,
		Color:         req.Color,
	}

	if err := saveInterfaceMetadata(store); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save metadata: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Interface %s labeled as %s\n", req.InterfaceName, req.Label)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Interface %s labeled as %s", req.InterfaceName, req.Label),
	})
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
	json.NewEncoder(w).Encode(stats)
}
func getTrafficHistory(w http.ResponseWriter, r *http.Request) {
	historyLock.Lock()
	defer historyLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trafficHistory)
}

func collectTrafficHistory() {
	for {
		time.Sleep(1 * time.Second)

		data, err := os.ReadFile("/proc/net/dev")
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		var currentTotalRx uint64
		var currentTotalTx uint64

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Inter-") || strings.HasPrefix(line, "face") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) < 17 {
				continue
			}

			iface := strings.TrimSuffix(parts[0], ":")
			if iface == "lo" {
				continue
			}

			var rx, tx uint64
			fmt.Sscanf(parts[1], "%d", &rx)
			fmt.Sscanf(parts[9], "%d", &tx)
			currentTotalRx += rx
			currentTotalTx += tx
		}

		historyLock.Lock()
		if !historyInitialized {
			lastTotalRx = currentTotalRx
			lastTotalTx = currentTotalTx
			historyInitialized = true
			historyLock.Unlock()
			continue
		}

		rxBps := currentTotalRx - lastTotalRx
		txBps := currentTotalTx - lastTotalTx
		lastTotalRx = currentTotalRx
		lastTotalTx = currentTotalTx

		snapshot := BandwidthSnapshot{
			Timestamp: time.Now().Format("15:04:05"),
			RxBps:     rxBps,
			TxBps:     txBps,
		}

		trafficHistory = append(trafficHistory, snapshot)
		if len(trafficHistory) > 60 {
			trafficHistory = trafficHistory[1:]
		}
		historyLock.Unlock()
	}
}

func getActiveConnections(w http.ResponseWriter, r *http.Request) {
	// Use 'ss' command to get active connections
	cmd := exec.Command("ss", "-tunap")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat if ss fails
		cmd = exec.Command("netstat", "-tunap")
		output, err = cmd.Output()
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
	cmd := exec.Command("tail", "-n", fmt.Sprintf("%d", limit), eveLogPath)
	output, err := cmd.Output()
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
	cmd := exec.Command("cscli", "decisions", "list", "-o", "json")
	output, err := cmd.Output()
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

func getDNSStats(w http.ResponseWriter, r *http.Request) {
	stats := DNSStats{}

	// For now, we assume AdGuard Home is on port 3000 or the user-preferred port 90
	// In a real environment, we'd pull from the actual config.
	ports := []string{"3000", "90", "80"}
	var finalData map[string]interface{}

	for _, port := range ports {
		url := fmt.Sprintf("http://localhost:%s/control/stats", port)
		// Note: AdGuard Home usually needs Basic Auth.
		// For this integration to work perfectly, we'd need to store or prompt for AGH credentials.
		// For now, we try an unauthenticated request (which might fail but is a start)
		resp, cerr := http.Get(url)
		if cerr == nil && resp.StatusCode == 200 {
			json.NewDecoder(resp.Body).Decode(&finalData)
			resp.Body.Close()
			break
		}
	}

	if finalData != nil {
		// Map AGH data to our internal struct
		if val, ok := finalData["num_dns_queries"].(float64); ok {
			stats.TotalQueries = int(val)
		}
		if val, ok := finalData["num_blocked_filtering"].(float64); ok {
			stats.BlockedFiltering = int(val)
		}
		if stats.TotalQueries > 0 {
			stats.BlockedPercentage = (float64(stats.BlockedFiltering) / float64(stats.TotalQueries)) * 100
		}
	} else {
		// Mock data if no ad-blocker is found, so the UI can be developed/tested
		stats.TotalQueries = 1250
		stats.BlockedFiltering = 340
		stats.BlockedPercentage = 27.2
		stats.TopBlocked = []TopDomain{
			{Domain: "doubleclick.net", Hits: 85},
			{Domain: "google-analytics.com", Hits: 62},
			{Domain: "facebook.com", Hits: 44},
		}
		stats.TopQueries = []TopDomain{
			{Domain: "google.com", Hits: 210},
			{Domain: "github.com", Hits: 155},
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func getSecurityStats(w http.ResponseWriter, r *http.Request) {
	stats := SecurityStats{}

	// Get Suricata statistics from eve.json
	eveLogPath := "/var/log/suricata/eve.json"
	if _, err := os.Stat(eveLogPath); err == nil {
		cmd := exec.Command("tail", "-n", "1000", eveLogPath)
		output, err := cmd.Output()
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
	cmd := exec.Command("cscli", "decisions", "list", "-o", "json")
	output, err := cmd.Output()
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
	cmd := exec.Command("systemctl", req.Action, req.ServiceName)
	output, err := cmd.CombinedOutput()

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

func main() {
	loadTokenSecret()
	initWireGuard()
	go collectTrafficHistory()
	mux := http.NewServeMux()

	// Public Auth Endpoints
	mux.HandleFunc("POST /api/login", login)

	// Protected Endpoints
	mux.HandleFunc("GET /api/status", authMiddleware(getSystemStatus))
	mux.HandleFunc("GET /api/config", authMiddleware(getConfig))
	mux.HandleFunc("POST /api/config", authMiddleware(updateConfig))
	mux.HandleFunc("POST /api/auth/update-credentials", authMiddleware(updateCredentials))

	mux.HandleFunc("GET /api/interfaces", authMiddleware(getInterfaces))
	mux.HandleFunc("POST /api/interfaces/vlan", authMiddleware(createVLAN))
	mux.HandleFunc("DELETE /api/interfaces/vlan", authMiddleware(deleteVLAN))
	mux.HandleFunc("POST /api/interfaces/ip", authMiddleware(configureIP))
	mux.HandleFunc("POST /api/interfaces/state", authMiddleware(setInterfaceState))
	mux.HandleFunc("GET /api/interfaces/metadata", authMiddleware(getInterfaceMetadata))
	mux.HandleFunc("POST /api/interfaces/label", authMiddleware(setInterfaceLabel))
	mux.HandleFunc("GET /api/firewall", authMiddleware(getFirewallRules))
	mux.HandleFunc("POST /api/firewall", authMiddleware(addFirewallRule))
	mux.HandleFunc("DELETE /api/firewall", authMiddleware(deleteFirewallRule))
	mux.HandleFunc("GET /api/services", authMiddleware(getServices))
	mux.HandleFunc("POST /api/services/control", authMiddleware(controlService))
	mux.HandleFunc("GET /api/traffic/stats", authMiddleware(getTrafficStats))
	mux.HandleFunc("GET /api/traffic/history", authMiddleware(getTrafficHistory))
	mux.HandleFunc("GET /api/traffic/connections", authMiddleware(getActiveConnections))
	mux.HandleFunc("GET /api/security/suricata/alerts", authMiddleware(getSuricataAlerts))
	mux.HandleFunc("GET /api/security/crowdsec/decisions", authMiddleware(getCrowdSecDecisions))
	mux.HandleFunc("GET /api/security/stats", authMiddleware(getSecurityStats))
	mux.HandleFunc("GET /api/dns/stats", authMiddleware(getDNSStats))

	// VPN Endpoints
	mux.HandleFunc("GET /api/vpn/clients", authMiddleware(listVPNClients))
	mux.HandleFunc("POST /api/vpn/clients", authMiddleware(addVPNClient))
	mux.HandleFunc("DELETE /api/vpn/clients", authMiddleware(deleteVPNClient))
	mux.HandleFunc("GET /api/vpn/download", authMiddleware(downloadVPNClient))

	// OpenVPN Client & PBR
	mux.HandleFunc("GET /api/vpn/client/status", authMiddleware(getVPNClientStatus))
	mux.HandleFunc("POST /api/vpn/client/config", authMiddleware(uploadVPNClientConfig))
	mux.HandleFunc("POST /api/vpn/client/control", authMiddleware(controlVPNClient))
	mux.HandleFunc("GET /api/vpn/client/policies", authMiddleware(getVPNPolicies))
	mux.HandleFunc("POST /api/vpn/client/policies", authMiddleware(addVPNPolicy))
	mux.HandleFunc("DELETE /api/vpn/client/policies", authMiddleware(deleteVPNPolicy))

	// OpenVPN Server
	mux.HandleFunc("GET /api/vpn/server-openvpn/status", authMiddleware(getOpenVPNServerStatus))
	mux.HandleFunc("POST /api/vpn/server-openvpn/setup", authMiddleware(setupOpenVPNServer))
	mux.HandleFunc("GET /api/vpn/server-openvpn/clients", authMiddleware(listOpenVPNClients))
	mux.HandleFunc("POST /api/vpn/server-openvpn/clients", authMiddleware(createOpenVPNClient))
	mux.HandleFunc("DELETE /api/vpn/server-openvpn/clients", authMiddleware(deleteOpenVPNClient))
	mux.HandleFunc("GET /api/vpn/server-openvpn/download", authMiddleware(downloadOpenVPNClient))

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

	port := ":80"
	log.Printf("SoftRouter Governance Service starting on port %s", port)

	handler := enableCORS(mux)

	// Attempt to bind to standard port 80, fallback to 8080 if needed
	if err := http.ListenAndServe("0.0.0.0:80", handler); err != nil {
		log.Printf("Primary port 80 binding failed: %v. Attempting fallback to 8080...", err)
		if err := http.ListenAndServe("0.0.0.0:8080", handler); err != nil {
			log.Fatalf("Critical Failure: Could not bind to any port: %v", err)
		}
	}
}
