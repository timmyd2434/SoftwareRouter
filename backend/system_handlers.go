package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// ServiceStatus represents a managed service (DHCP, DNS, VPN)
type ServiceStatus struct {
	Name      string `json:"name"`
	ServiceID string `json:"service_id"`
	Status    string `json:"status"` // Running, Stopped, Error
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
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

// ServiceControlRequest represents the payload for controlling services
type ServiceControlRequest struct {
	ServiceName string `json:"serviceName"` // systemd service name, e.g., "dnsmasq"
	Action      string `json:"action"`      // "start", "stop", "restart"
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

func getTrafficStats(w http.ResponseWriter, r *http.Request) {
	stats := make(map[string]InterfaceStats)

	// Read /proc/net/dev for interface statistics
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		log.Printf("[ERROR] Failed to read interface stats: %v", err)
		respondSystemError(w, ErrGenericInternalError, "Failed to read interface stats", err)
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
			log.Printf("[ERROR] Failed to get connections: %v", err)
			respondSystemError(w, ErrGenericInternalError, "Failed to get active connections", err)
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
	}
	if !validServices[req.ServiceName] {
		http.Error(w, "Invalid service name", http.StatusBadRequest)
		return
	}

	// Pre-start check for WireGuard
	if strings.HasPrefix(req.ServiceName, "wg-quick@") && (req.Action == "start" || req.Action == "restart") {
		initWireGuard()
	}

	log.Printf("Controlling service: %s %s", req.Action, req.ServiceName)

	// Execute systemctl command
	output, err := runPrivilegedCombinedOutput("systemctl", req.Action, req.ServiceName)

	if err != nil {
		outStr := strings.TrimSpace(string(output))
		log.Printf("[ERROR] Service control failed: %s - output: %s", err.Error(), outStr)

		detailMsg := fmt.Sprintf("Service %s failed to %s", req.ServiceName, req.Action)
		if strings.Contains(outStr, "not be found") || strings.Contains(outStr, "not-found") || strings.Contains(outStr, "No such file") {
			if strings.HasPrefix(req.ServiceName, "wg-quick") {
				detailMsg = "WireGuard package is not installed on this router. Please run 'sudo apt install wireguard wireguard-tools' or update via update.sh."
			} else {
				detailMsg = fmt.Sprintf("Service unit %s is not installed on this router system.", req.ServiceName)
			}
		} else if outStr != "" {
			detailMsg = fmt.Sprintf("Failed to %s %s: %s", req.Action, req.ServiceName, outStr)
		}

		respondSystemError(w, ErrSystemServiceControl, detailMsg, fmt.Errorf("%s", outStr))
		return
	}

	fmt.Printf("Service %s %s successfully\n", req.ServiceName, req.Action)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Service %s %sed successfully", req.ServiceName, req.Action),
	})
}
