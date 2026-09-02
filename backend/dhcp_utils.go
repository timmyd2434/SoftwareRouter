package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// loadDHCPConfig loads the DHCP configuration from JSON file
func loadDHCPConfig() (*DHCPConfigStore, error) {
	store := &DHCPConfigStore{
		Configs: make(map[string]DHCPConfig),
	}

	data, err := os.ReadFile(dhcpConfigPath)
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

// saveDHCPConfig saves the DHCP configuration to JSON file
func saveDHCPConfig(store *DHCPConfigStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll("/etc/softrouter", 0750); err != nil {
		log.Printf("ERROR: Failed to create /etc/softrouter directory: %v", err)
		return err
	}

	return os.WriteFile(dhcpConfigPath, data, 0600)
}

// ipToUint32 converts a 4-byte IPv4 address to a uint32 integer
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// isValidDHCPRange is the pure mathematical logic for validating a DHCP pool.
// It ensures the range is valid, within the subnet, and doesn't overlap
// with the router's own IP or special subnet addresses.
func isValidDHCPRange(startIPStr, endIPStr string, routerIP net.IP, subnet *net.IPNet) error {
	startIP := net.ParseIP(startIPStr)
	endIP := net.ParseIP(endIPStr)

	if startIP == nil || endIP == nil {
		return fmt.Errorf("invalid IP address format for start or end IP")
	}

	start := startIP.To4()
	end := endIP.To4()
	router := routerIP.To4()

	if start == nil || end == nil {
		return fmt.Errorf("only IPv4 addresses are supported for this check")
	}

	// 1. Must be within the subnet
	if !subnet.Contains(start) {
		return fmt.Errorf("start IP %s is not in interface subnet %s", startIPStr, subnet.String())
	}
	if !subnet.Contains(end) {
		return fmt.Errorf("end IP %s is not in interface subnet %s", endIPStr, subnet.String())
	}

	// 2. Convert to integers for range checking
	startInt := ipToUint32(start)
	endInt := ipToUint32(end)
	routerInt := uint32(0)
	if router != nil {
		routerInt = ipToUint32(router)
	}

	// Calculate network and broadcast addresses
	maskInt := ipToUint32(net.IP(subnet.Mask))
	networkInt := startInt & maskInt
	broadcastInt := networkInt | ^maskInt

	// 3. Start must be <= End
	if startInt > endInt {
		return fmt.Errorf("start IP must be less than or equal to end IP")
	}

	// 4. Must not include Network Address (lowest IP)
	if startInt <= networkInt {
		// #nosec G115: Intentionally taking lowest 8 bits
		networkIPStr := net.IP{byte(networkInt >> 24), byte(networkInt >> 16), byte(networkInt >> 8), byte(networkInt)}.String()
		return fmt.Errorf("DHCP range cannot include the subnet's network address (%s)", networkIPStr)
	}

	// 5. Must not include Broadcast Address (highest IP)
	if endInt >= broadcastInt {
		// #nosec G115: Intentionally taking lowest 8 bits
		broadcastIPStr := net.IP{byte(broadcastInt >> 24), byte(broadcastInt >> 16), byte(broadcastInt >> 8), byte(broadcastInt)}.String()
		return fmt.Errorf("DHCP range cannot include the subnet's broadcast address (%s)", broadcastIPStr)
	}

	// 6. Must NOT hand out the router's own IP address
	if routerInt != 0 {
		if routerInt >= startInt && routerInt <= endInt {
			return fmt.Errorf("DHCP range includes the router's own IP address (%s) - this will cause critical IP conflicts on your network", routerIP.String())
		}
	}

	return nil
}

// validateIPRange checks if the IP range is valid and within the interface subnet
func validateIPRange(interfaceName, startIP, endIP, gateway string) error {
	// Get interface IP to determine subnet
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %v", err)
	}

	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("interface has no IP address assigned")
	}

	// Find the first IPv4 address
	var interfaceNet *net.IPNet
	var routerIP net.IP

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			interfaceNet = ipnet
			routerIP = ipnet.IP
			break
		}
	}

	if interfaceNet == nil {
		return fmt.Errorf("interface has no IPv4 address")
	}

	if err := isValidDHCPRange(startIP, endIP, routerIP, interfaceNet); err != nil {
		return err
	}

	// Validate gateway only if provided (it's optional)
	if gateway != "" {
		gatewayParsed := net.ParseIP(gateway)
		if gatewayParsed == nil {
			return fmt.Errorf("invalid gateway IP format")
		}
		if !interfaceNet.Contains(gatewayParsed) {
			return fmt.Errorf("gateway %s is not in interface subnet %s", gateway, interfaceNet.String())
		}
	}

	return nil
}

// ARPEntry represents a row in /proc/net/arp
type ARPEntry struct {
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	Device     string `json:"device"`
	Hostname   string `json:"hostname"`
	IsStatic   bool   `json:"is_static"`
	IsActive   bool   `json:"is_active"`
	Expires    string `json:"expires"`
	Vendor     string `json:"vendor"`
	DeviceName string `json:"device_name"`
	DeviceType string `json:"device_type"`
}

// getARPTable parses /proc/net/arp
func getARPTable() ([]ARPEntry, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck

	var entries []ARPEntry
	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		// IP HWType Flags HWAddr Mask Device
		// 192.168.1.50 0x1 0x2 00:11:22:33:44:55 * eth0
		entries = append(entries, ARPEntry{
			IP:       fields[0],
			MAC:      fields[3],
			Device:   fields[5],
			IsActive: true,
		})
	}
	return entries, nil
}

// regenerateDnsmasqDHCPConfig generates the dnsmasq DHCP configuration file
func regenerateDnsmasqDHCPConfig(store *DHCPConfigStore) error {
	var config strings.Builder

	config.WriteString("# Auto-generated by SoftRouter - DO NOT EDIT MANUALLY\n")
	config.WriteString("# Edit via Web UI: Interfaces > Configure DHCP\n\n")

	for ifaceName, dhcpConf := range store.Configs {
		// IPv4 DHCP configuration
		if dhcpConf.Enabled {
			config.WriteString(fmt.Sprintf("# DHCPv4 for %s\n", ifaceName))
			config.WriteString(fmt.Sprintf("interface=%s\n", ifaceName))
			config.WriteString(fmt.Sprintf("dhcp-range=%s,%s,%s,%s\n",
				ifaceName, dhcpConf.StartIP, dhcpConf.EndIP, dhcpConf.LeaseTime))

			// Gateway (option 3)
			if dhcpConf.Gateway != "" {
				config.WriteString(fmt.Sprintf("dhcp-option=%s,3,%s\n", ifaceName, dhcpConf.Gateway))
			}

			// DNS servers (option 6)
			if len(dhcpConf.DNSServers) > 0 {
				config.WriteString(fmt.Sprintf("dhcp-option=%s,6,%s\n", ifaceName, strings.Join(dhcpConf.DNSServers, ",")))
			}

			config.WriteString("\n")
		}

		// IPv6 DHCPv6 configuration
		if dhcpConf.EnabledIPv6 {
			config.WriteString(fmt.Sprintf("# DHCPv6 for %s\n", ifaceName))
			// Enable RA for DHCPv6 (required for DHCPv6 to work)
			config.WriteString("enable-ra\n")

			// DHCPv6 range - constructor tells dnsmasq to use the interface's prefix
			// Format: dhcp-range=::start,::end,constructor:interface,lease-time
			config.WriteString(fmt.Sprintf("dhcp-range=%s,%s,constructor:%s,%s\n",
				dhcpConf.StartIPv6, dhcpConf.EndIPv6, ifaceName, dhcpConf.LeaseTimeIPv6))

			// DNS servers for DHCPv6 (option 23)
			if len(dhcpConf.DNSServersIPv6) > 0 {
				config.WriteString(fmt.Sprintf("dhcp-option=option6:dns-server,%s\n",
					strings.Join(dhcpConf.DNSServersIPv6, ",")))
			}

			config.WriteString("\n")
		}
	}

	// Static Leases
	if len(store.StaticLeases) > 0 {
		config.WriteString("# Static Reservations\n")
		for _, lease := range store.StaticLeases {
			// dhcp-host=MAC,IP,HOSTNAME
			config.WriteString(fmt.Sprintf("dhcp-host=%s,%s,%s\n", lease.MAC, lease.IP, lease.Hostname))
		}
	}

	// Ensure directory exists
	if err := os.MkdirAll("/etc/dnsmasq.d", 0750); err != nil {
		log.Printf("ERROR: Failed to create /etc/dnsmasq.d directory: %v", err)
		return fmt.Errorf("failed to create dnsmasq.d directory: %w", err)
	}

	// Write the configuration file
	err := os.WriteFile(dnsmasqDHCPPath, []byte(config.String()), 0600)
	if err != nil {
		return err
	}

	// Restart dnsmasq to apply changes
	if err := runPrivileged("systemctl", "restart", "dnsmasq"); err != nil {
		log.Printf("WARNING: Failed to restart dnsmasq: %v", err)
		return fmt.Errorf("failed to restart dnsmasq: %w", err)
	}

	return nil
}

// parseDHCPLeases reads the dnsmasq leases file
func parseDHCPLeases() ([]DHCPLease, error) {
	leaseFile := "/var/lib/misc/dnsmasq.leases"

	file, err := os.Open(leaseFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []DHCPLease{}, nil // No leases file yet
		}
		return nil, err
	}
	defer file.Close() //nolint:errcheck

	var leases []DHCPLease
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 5 {
			continue
		}

		// Format: <expiry> <mac> <ip> <hostname> <client-id>
		expiryTimestamp := fields[0]
		expiryTime := time.Unix(0, 0) // Default
		if ts, err := time.Parse("1136239445", expiryTimestamp); err == nil {
			expiryTime = ts
		} else {
			// Try int parse if timestamp is robust
			var tsInt int64
			if _, err := fmt.Sscanf(expiryTimestamp, "%d", &tsInt); err != nil {
				log.Printf("WARNING: Failed to parse DHCP lease timestamp: %v", err)
			} else {
				expiryTime = time.Unix(tsInt, 0)
			}
		}

		lease := DHCPLease{
			Expires:   expiryTime.Format("2006-01-02 15:04:05"),
			MAC:       fields[1],
			IP:        fields[2],
			Hostname:  fields[3],
			Interface: "", // dnsmasq doesn't track interface in leases file
		}

		leases = append(leases, lease)
	}

	return leases, scanner.Err()
}

// HTTP Handlers

func getNetworkClients(w http.ResponseWriter, r *http.Request) {
	// 1. Get ARP Table (Live devices)
	arpEntries, _ := getARPTable()

	// 2. Get DHCP Leases (Dynamic history)
	dhcpLeases, _ := parseDHCPLeases()

	// 3. Get Static Leases (Configured)
	store, _ := loadDHCPConfig()

	// Merge logic
	// Map by MAC for deduplication
	clientMap := make(map[string]ARPEntry)

	// Add Static Leases first (Authoritative for config)
	if store != nil {
		for _, static := range store.StaticLeases {
			clientMap[static.MAC] = ARPEntry{
				MAC:      static.MAC,
				IP:       static.IP,
				Hostname: static.Hostname,
				IsStatic: true,
				Device:   "static", // Placeholder
			}
		}
	}

	// Add DHCP Leases (Update IP/Expires if exists, else create)
	for _, lease := range dhcpLeases {
		entry, exists := clientMap[lease.MAC]
		if !exists {
			entry = ARPEntry{
				MAC:      lease.MAC,
				IP:       lease.IP,
				Hostname: lease.Hostname,
			}
		} else {
			// Update dynamic fields if not strictly static overridden IP (though static usually matches)
			if !entry.IsStatic {
				entry.IP = lease.IP
				entry.Hostname = lease.Hostname
			}
		}
		entry.Expires = lease.Expires
		clientMap[lease.MAC] = entry
	}

	// Add ARP Entries (Set IsActive)
	for _, arp := range arpEntries {
		// Ignore incomplete entries
		if arp.MAC == "00:00:00:00:00:00" {
			continue
		}
		entry, exists := clientMap[arp.MAC]
		if !exists {
			entry = arp
			entry.IsStatic = false // Pure ARP = unknown/static config elsewhere or just talking
		} else {
			entry.IsActive = true
			if entry.IP == "" {
				entry.IP = arp.IP // Prefer ARP IP if lease missing
			}
			entry.Device = arp.Device
		}
		clientMap[arp.MAC] = entry
	}

	// Convert map to slice and enrich with metadata
	clients := make([]ARPEntry, 0, len(clientMap))
	for _, c := range clientMap {
		vendor, dName, dType := GetDeviceFingerprint(c.MAC)
		c.Vendor = vendor
		c.DeviceName = dName
		c.DeviceType = dType
		clients = append(clients, c)
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, clients)
}

func addStaticLease(w http.ResponseWriter, r *http.Request) {
	var req StaticLease
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.MAC == "" || req.IP == "" {
		http.Error(w, "MAC and IP required", http.StatusBadRequest)
		return
	}

	if match, _ := regexp.MatchString(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`, req.MAC); !match {
		http.Error(w, "Invalid MAC address", http.StatusBadRequest)
		return
	}

	if net.ParseIP(req.IP) == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	if req.Hostname != "" {
		if match, _ := regexp.MatchString(`^[a-zA-Z0-9_-]{1,63}$`, req.Hostname); !match {
			http.Error(w, "Invalid hostname", http.StatusBadRequest)
			return
		}
	}

	store, err := loadDHCPConfig()
	if err != nil {
		http.Error(w, "Failed to load config", http.StatusInternalServerError)
		return
	}

	// Check if already exists, update if so
	found := false
	for i, lease := range store.StaticLeases {
		if lease.MAC == req.MAC {
			store.StaticLeases[i] = req
			found = true
			break
		}
	}
	if !found {
		store.StaticLeases = append(store.StaticLeases, req)
	}

	if err := saveDHCPConfig(store); err != nil {
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	if err := regenerateDnsmasqDHCPConfig(store); err != nil {
		http.Error(w, "Failed to apply config", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success"})
}

func removeStaticLease(w http.ResponseWriter, r *http.Request) {
	mac := r.URL.Query().Get("mac")
	if mac == "" {
		http.Error(w, "MAC address required", http.StatusBadRequest)
		return
	}

	store, err := loadDHCPConfig()
	if err != nil {
		http.Error(w, "Failed to load config", http.StatusInternalServerError)
		return
	}

	newLeases := []StaticLease{}
	for _, lease := range store.StaticLeases {
		if lease.MAC != mac {
			newLeases = append(newLeases, lease)
		}
	}
	store.StaticLeases = newLeases

	if err := saveDHCPConfig(store); err != nil {
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	if err := regenerateDnsmasqDHCPConfig(store); err != nil {
		http.Error(w, "Failed to apply config", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success"})
}

func getDHCPConfig(w http.ResponseWriter, r *http.Request) {
	store, err := loadDHCPConfig()
	if err != nil {
		respondSystemError(w, ErrDHCPConfigFailed, "Failed to load DHCP config", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, store)
}

func setDHCPConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InterfaceName string     `json:"interfaceName"`
		Config        DHCPConfig `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate interface name
	if !isValidInterfaceName(req.InterfaceName) {
		http.Error(w, "Invalid interface name", http.StatusBadRequest)
		return
	}

	// Validate LeaseTime and IPv6 fields
	if req.Config.LeaseTime != "" {
		if match, _ := regexp.MatchString(`^[0-9]+[hmd]$`, req.Config.LeaseTime); !match {
			respondInvalidRequest(w, "Invalid LeaseTime")
			return
		}
	}
	if req.Config.LeaseTimeIPv6 != "" {
		if match, _ := regexp.MatchString(`^[0-9]+[hmd]$`, req.Config.LeaseTimeIPv6); !match {
			respondInvalidRequest(w, "Invalid LeaseTimeIPv6")
			return
		}
	}
	if req.Config.StartIPv6 != "" && net.ParseIP(req.Config.StartIPv6) == nil {
		respondInvalidRequest(w, "Invalid StartIPv6")
		return
	}
	if req.Config.EndIPv6 != "" && net.ParseIP(req.Config.EndIPv6) == nil {
		respondInvalidRequest(w, "Invalid EndIPv6")
		return
	}

	// Validate IPv4 range if IPv4 DHCP is enabled
	if req.Config.Enabled {
		// Only validate if the fields are actually populated
		if req.Config.StartIP != "" && req.Config.EndIP != "" {
			if err := validateIPRange(req.InterfaceName, req.Config.StartIP, req.Config.EndIP, req.Config.Gateway); err != nil {
				respondInvalidRequest(w, "IPv4 DHCP validation error")
				return
			}
		}
	}

	// Load existing config
	store, err := loadDHCPConfig()
	if err != nil {
		respondSystemError(w, ErrDHCPConfigFailed, "Failed to load config", err)
		return
	}

	// Update the configuration
	store.Configs[req.InterfaceName] = req.Config

	// Save to file
	if err := saveDHCPConfig(store); err != nil {
		respondSystemError(w, ErrDHCPSaveFailed, "Failed to save config", err)
		return
	}

	// Regenerate dnsmasq config
	if err := regenerateDnsmasqDHCPConfig(store); err != nil {
		respondSystemError(w, ErrDHCPConfigFailed, "Failed to update dnsmasq", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{"status": "success"})
}

func deleteDHCPConfig(w http.ResponseWriter, r *http.Request) {
	interfaceName := r.URL.Query().Get("interface")
	if interfaceName == "" {
		http.Error(w, "Interface name required", http.StatusBadRequest)
		return
	}

	store, err := loadDHCPConfig()
	if err != nil {
		respondSystemError(w, ErrDHCPConfigFailed, "Failed to load config", err)
		return
	}

	// Remove the configuration
	delete(store.Configs, interfaceName)

	// Save to file
	if err := saveDHCPConfig(store); err != nil {
		respondSystemError(w, ErrDHCPSaveFailed, "Failed to save config", err)
		return
	}

	// Regenerate dnsmasq config
	if err := regenerateDnsmasqDHCPConfig(store); err != nil {
		respondSystemError(w, ErrDHCPConfigFailed, "Failed to update dnsmasq", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{"status": "success"})
}

func getDHCPLeases(w http.ResponseWriter, r *http.Request) {
	leases, err := parseDHCPLeases()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to read leases", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, leases)
}

// InitDHCP initializes the DHCP service (dnsmasq) on router boot
func InitDHCP() {
	log.Println("[INFO] Initializing DHCP Server (dnsmasq)...")

	// Ensure systemd service is enabled
	if err := runPrivileged("systemctl", "enable", "dnsmasq"); err != nil {
		log.Printf("[WARN] Failed to enable dnsmasq service: %v", err)
	}

	// Load DHCP config and regenerate /etc/dnsmasq.d/softrouter-dhcp.conf
	store, err := loadDHCPConfig()
	if err != nil {
		log.Printf("[WARN] Failed to load DHCP config: %v", err)
	} else if store != nil {
		if err := regenerateDnsmasqDHCPConfig(store); err != nil {
			log.Printf("[WARN] Failed to regenerate dnsmasq config: %v", err)
		}
	}

	// Ensure dnsmasq service is active
	if err := runPrivileged("systemctl", "start", "dnsmasq"); err != nil {
		log.Printf("[WARN] Failed to start dnsmasq service: %v", err)
	}
}

// InitDNSServices ensures the appropriate DNS resolver and DHCP server are running on startup
func InitDNSServices() {
	InitDHCP()

	configLock.RLock()
	adBlocker := config.AdBlocker
	configLock.RUnlock()

	if adBlocker == "none" || adBlocker == "" {
		log.Println("[INFO] Initializing standard DNS resolver (unbound)...")
		runPrivileged("systemctl", "enable", "unbound")
		runPrivileged("systemctl", "start", "unbound")
	} else if adBlocker == "adguard" {
		log.Println("[INFO] Initializing AdGuard Home DNS...")
		runPrivileged("systemctl", "enable", "AdGuardHome")
		runPrivileged("systemctl", "start", "AdGuardHome")
	}
}
