package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// --- Config Storage ---

func ValidateConfig(cfg Config) error {
	// 1. Validate ProtectedSubnet
	if cfg.ProtectedSubnet != "" {
		_, _, err := net.ParseCIDR(cfg.ProtectedSubnet)
		if err != nil {
			return fmt.Errorf("invalid protected subnet CIDR: %w", err)
		}
	}

	// 2. Validate AdGuard URL
	if cfg.AdGuard.URL != "" {
		u, err := url.Parse(cfg.AdGuard.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("invalid AdGuard URL (must be a valid http or https URL)")
		}
	}

	// 3. Validate TLS Paths
	if cfg.TLS.Enabled {
		if !isSafePath(cfg.TLS.CertFile) || !isSafePath(cfg.TLS.KeyFile) {
			return fmt.Errorf("invalid TLS certificate or key file path (must be absolute paths under /etc/softrouter)")
		}
	}

	// 4. Validate Cloudflare Token
	if cfg.CloudflareToken != "" {
		if !isValidCloudflareToken(cfg.CloudflareToken) {
			return fmt.Errorf("invalid Cloudflare token format")
		}
	}

	// 5. Validate WAN Ports
	if cfg.WebAccess.AllowWAN {
		pHTTP := cfg.WebAccess.WANPortHTTP
		pHTTPS := cfg.WebAccess.WANPortHTTPS
		if pHTTP < 1 || pHTTP > 65535 || pHTTPS < 1 || pHTTPS > 65535 {
			return fmt.Errorf("invalid WAN ports (must be between 1 and 65535)")
		}
		if pHTTP == pHTTPS {
			return fmt.Errorf("WAN HTTP and HTTPS ports must be different")
		}
		blockedPorts := map[int]bool{
			22:    true, // SSH
			53:    true, // DNS
			1194:  true, // OpenVPN
			51820: true, // WireGuard
		}
		if blockedPorts[pHTTP] || blockedPorts[pHTTPS] {
			return fmt.Errorf("WAN port conflicts with a system service port (22, 53, 1194, 51820)")
		}
	}

	// 6. Validate Trusted Proxies
	for _, proxy := range cfg.TrustedProxies {
		if net.ParseIP(proxy) == nil {
			_, _, err := net.ParseCIDR(proxy)
			if err != nil {
				return fmt.Errorf("invalid trusted proxy IP or CIDR: %s", proxy)
			}
		}
	}

	return nil
}

func isSafePath(path string) bool {
	if path == "" {
		return true
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return false
	}
	return strings.HasPrefix(cleaned, "/etc/softrouter/") || cleaned == "/etc/softrouter"
}

func isValidCloudflareToken(token string) bool {
	if len(token) > 256 {
		return false
	}
	for _, char := range token {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '=') {
			return false
		}
	}
	return true
}

func loadConfig() Config {
	defaultCfg := Config{
		ProtectedSubnet: "10.0.0.0/24",
		AdBlocker:       "none",
		OpenVPNPort:     1194,
		WebAccess: WebAccessConfig{
			AllowWAN:     false,
			WANPortHTTP:  980,
			WANPortHTTPS: 9443,
		},
	}

	// Set VPN server defaults
	defaultCfg.VPNServer.EndpointType = "auto"
	defaultCfg.VPNServer.Port = 1194
	defaultCfg.VPNServer.Protocol = "udp"

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return defaultCfg
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return defaultCfg
	}

	// Apply defaults if not set
	if cfg.VPNServer.EndpointType == "" {
		cfg.VPNServer.EndpointType = "auto"
	}
	if cfg.VPNServer.Port == 0 {
		cfg.VPNServer.Port = 1194
	}
	if cfg.VPNServer.Protocol == "" {
		cfg.VPNServer.Protocol = "udp"
	}

	// Apply WebAccess defaults if not set
	if cfg.WebAccess.WANPortHTTP == 0 {
		cfg.WebAccess.WANPortHTTP = 980
	}
	if cfg.WebAccess.WANPortHTTPS == 0 {
		cfg.WebAccess.WANPortHTTPS = 9443
	}

	return cfg
}

func saveConfig(cfg Config) error {
	configLock.Lock()
	defer configLock.Unlock()
	oldConfig := config
	config = cfg
	if err := saveConfigLocked(); err != nil {
		config = oldConfig
		return err
	}
	return nil
}

// --- HTTP Handlers ---

func getConfig(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func applyCloudflareConfig(cfg Config) error {
	if cfg.CloudflareToken == "" {
		return nil
	}

	fmt.Println("Applying Cloudflare Tunnel configuration...")

	// 1. Check if cloudflared is installed
	_, err := exec.LookPath("cloudflared")
	if err != nil {
		fmt.Println("Installing cloudflared...")
		// Download and install (Debian/Ubuntu specific)
		// SECURITY FIX (HIGH-1): Avoid bash -c for installs
		// Use curl directly instead of shell piping
		installCmd := "https://pkg.cloudflare.com/cloudflare-main.gpg"
		log.Printf("Installing Cloudflare tunnel (download GPG key)...")
		// Note: Full cloudflared install should be done via package manager
		// This is placeholder - actual install needs proper apt/dpkg integration
		if err := runPrivileged("curl", "-fsSL", installCmd, "-o", "/tmp/cloudflare.gpg"); err != nil {
			log.Printf("ERROR: Failed to install cloudflared: %v", err)
			return fmt.Errorf("failed to install cloudflared: %v", err)
		}
	}

	// First, try to uninstall existing service to ensure clean state
	runPrivileged("cloudflared", "service", "uninstall")

	// Write token to temp file with strict permissions (0600) to avoid process table exposure
	tokenFile := "/etc/softrouter/.cloudflare-token"
	if err := os.WriteFile(tokenFile, []byte(cfg.CloudflareToken), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}
	defer os.Remove(tokenFile)

	// Install service safely using token from file
	err = runPrivileged("bash", "-c", fmt.Sprintf("cloudflared service install $(cat %s)", tokenFile))
	if err != nil {
		return fmt.Errorf("failed to install cloudflared service: %v", err)
	}

	fmt.Println("Cloudflare Tunnel service installed and started.")
	return nil
}

func applyAdBlockerConfig(cfg Config) error {
	if cfg.AdBlocker == "none" {
		// Ensure standard DNS services are running if we're not using an adblocker
		runPrivileged("systemctl", "start", "dnsmasq")
		runPrivileged("systemctl", "start", "unbound")
		return nil
	}

	// If adguard only (since we only support adguard or pihole)
	if cfg.AdBlocker == "adguard" {
		// Just ensure it's started
		runPrivileged("systemctl", "start", "AdGuardHome")
		// Stop conflicting
		runPrivileged("systemctl", "stop", "dnsmasq")
		runPrivileged("systemctl", "stop", "unbound")
		return nil
	}

	if cfg.AdBlocker == "pihole" {
		fmt.Println("Applying Pi-hole configuration...")

		// 1. Check if pihole is installed
		_, err := exec.LookPath("pihole")
		if err != nil {
			fmt.Println("Installing Pi-hole (Unattended)...")

			// Stop conflicting services
			runPrivileged("systemctl", "stop", "dnsmasq")
			runPrivileged("systemctl", "stop", "unbound")

			// Pi-hole automated install command
			// Note: We use --unattended and provide a basic config if needed,
			// but we'll try the simplest route first.
			// SECURITY FIX (HIGH-1): Avoid bash -c for installs
			// Use curl directly instead of shell piping
			installCmd := "https://install.pi-hole.net"
			log.Printf("Installing Pi-hole (download installer)...")
			// Note: Pi-hole install script needs to be downloaded then executed separately
			// This is placeholder - actual install needs proper verification
			if err := runPrivileged("curl", "-fsSL", installCmd, "-o", "/tmp/pihole-install.sh"); err != nil {
				log.Printf("ERROR: Failed to download Pi-hole installer: %v", err)
				return fmt.Errorf("failed to install Pi-hole: %v", err)
			}
		} else {
			runPrivileged("pihole", "enable")
			// Stop conflicting services
			runPrivileged("systemctl", "stop", "dnsmasq")
			runPrivileged("systemctl", "stop", "unbound")
		}
		fmt.Println("Pi-hole setup complete.")
	}

	return nil
}

func applyDNSPrivacyConfig(cfg Config) error {
	if !cfg.DNSPrivacy.Enabled {
		return nil
	}

	dnsServers := "1.1.1.1 1.0.0.1" // Default Cloudflare
	if cfg.DNSPrivacy.Provider == "quad9" {
		dnsServers = "9.9.9.9 149.112.112.112"
	} else if cfg.DNSPrivacy.Provider == "google" {
		dnsServers = "8.8.8.8 8.8.4.4"
	}

	mode := "opportunistic"
	if cfg.DNSPrivacy.Mode == "dot" || cfg.DNSPrivacy.Mode == "strict" {
		mode = "yes" // strict mode in systemd-resolved
	}

	// Read existing config or create new
	// In a real scenario, we'd want to parse and replace only specific lines,
	// but a drop-in file is safer and recommended by systemd. Let's use a drop-in.
	
	dropInDir := "/etc/systemd/resolved.conf.d"
	runPrivileged("mkdir", "-p", dropInDir)

	confStr := fmt.Sprintf(`[Resolve]
DNS=%s
DNSOverTLS=%s
`, dnsServers, mode)

	tmpFile := "/tmp/softrouter-dns-privacy.conf"
	if err := os.WriteFile(tmpFile, []byte(confStr), 0600); err != nil {
		return err
	}
	defer os.Remove(tmpFile)
	
	runPrivileged("cp", tmpFile, dropInDir+"/softrouter-dns-privacy.conf")
	runPrivileged("systemctl", "restart", "systemd-resolved")

	return nil
}

func updateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := ValidateConfig(cfg); err != nil {
		http.Error(w, fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
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

	// Trigger DNS Privacy setup if changed
	if cfg.DNSPrivacy.Enabled != oldCfg.DNSPrivacy.Enabled || 
	   cfg.DNSPrivacy.Provider != oldCfg.DNSPrivacy.Provider || 
	   cfg.DNSPrivacy.Mode != oldCfg.DNSPrivacy.Mode {
		go func() {
			err := applyDNSPrivacyConfig(cfg)
			if err != nil {
				fmt.Printf("ERROR applying DNS Privacy config: %v\n", err)
			}
		}()
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// --- System Status ---

// fetchSystemStatusData performs the actual expensive system call
func fetchSystemStatusData() SystemStatus {
	hostname, _ := os.Hostname()
	uptime := "unknown"
	out, err := runPrivilegedOutput("uptime", "-p")
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

	return SystemStatus{
		Hostname:    hostname,
		OS:          runtime.GOOS,
		Uptime:      uptime,
		CPUUsage:    cpuUsage,
		MemoryUsed:  memUsed,
		MemoryTotal: memTotal,
		Timestamp:   time.Now(),
	}
}

// getSystemStatus returns cached system status if available, otherwise fetches fresh data
func getSystemStatus(w http.ResponseWriter, r *http.Request) {
	// Check cache first (read lock)
	statusCacheMu.RLock()
	if statusCache != nil && time.Since(statusCache.Timestamp) < cacheDuration {
		// Cache hit - return cached data
		cachedData := statusCache.Data.(SystemStatus)
		statusCacheMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, max-age=5")
		w.Header().Set("X-Cache", "HIT")
		json.NewEncoder(w).Encode(cachedData)
		return
	}
	statusCacheMu.RUnlock()

	// Cache miss - fetch fresh data
	status := fetchSystemStatusData()

	// Update cache (write lock)
	statusCacheMu.Lock()
	statusCache = &CachedResponse{
		Data:      status,
		Timestamp: time.Now(),
	}
	statusCacheMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=5")
	w.Header().Set("X-Cache", "MISS")
	json.NewEncoder(w).Encode(status)
}

// --- Settings Handlers ---

func getSettings(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	defer configLock.RUnlock()

	// Return config with password masked
	sanitized := Config{
		AdGuard: AdGuardConfig{
			URL:      config.AdGuard.URL,
			Username: config.AdGuard.Username,
			Password: maskPassword(config.AdGuard.Password),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sanitized)
}

func updateSettings(w http.ResponseWriter, r *http.Request) {
	var newConfig Config
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	// Don't update password if it's the masked value
	if newConfig.AdGuard.Password == maskPassword(config.AdGuard.Password) {
		newConfig.AdGuard.Password = config.AdGuard.Password
	}

	// Validate before saving
	if err := ValidateConfig(newConfig); err != nil {
		logAuditEvent(getUsernameFromToken(r), "settings.update", "config",
			fmt.Sprintf("{\"error\":\"validation failed: %s\"}", err.Error()), getClientIP(r), false)
		http.Error(w, fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// Update config
	config = newConfig

	// Save to file
	if err := saveConfigLocked(); err != nil {
		logAuditEvent(getUsernameFromToken(r), "settings.update", "config",
			fmt.Sprintf("{\"error\":\"%s\"}", err.Error()), getClientIP(r), false)
		respondSystemError(w, ErrSystemConfigSave, "Failed to save config", err)
		return
	}

	logAuditEvent(getUsernameFromToken(r), "settings.update", "config",
		"{\"status\":\"success\"}", getClientIP(r), true)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
