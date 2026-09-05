package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DeviceTrafficEntry represents bandwidth usage for a single device
type DeviceTrafficEntry struct {
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	Hostname   string `json:"hostname"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	RxRate     uint64 `json:"rx_rate"`     // Bytes per second
	TxRate     uint64 `json:"tx_rate"`     // Bytes per second
	TotalToday uint64 `json:"total_today"` // Total bytes since midnight
}

// deviceTrafficState tracks cumulative bytes and rates per IP
type deviceTrafficState struct {
	RxBytes    uint64
	TxBytes    uint64
	RxRate     uint64
	TxRate     uint64
	LastUpdate time.Time
}

var (
	deviceTrafficMu    sync.RWMutex
	deviceTrafficMap   = make(map[string]*deviceTrafficState) // IP -> state
	deviceTrafficDay   = make(map[string]uint64)              // IP -> total bytes today
	deviceTrafficReset time.Time                              // When daily counters were last reset
)

func initDeviceTraffic() {
	deviceTrafficReset = todayMidnight()

	// Load nf_conntrack module
	if err := runPrivileged("modprobe", "nf_conntrack"); err != nil {
		log.Printf("[WARN] Could not load nf_conntrack module: %v", err)
	}

	// CRITICAL: Enable per-connection byte accounting.
	// Without this sysctl, bytes= fields in /proc/net/nf_conntrack are always 0.
	if err := runPrivileged("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1"); err != nil {
		log.Printf("[WARN] Could not enable nf_conntrack_acct: %v (per-device byte counts will be inaccurate)", err)
	}

	// Make accounting persistent across reboots
	_ = runPrivileged("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")

	collectDeviceTraffic()
	go deviceTrafficLoop()
	log.Println("[INFO] Per-device traffic monitoring started")
}

func todayMidnight() time.Time {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

func deviceTrafficLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		collectDeviceTraffic()
	}
}

// collectDeviceTraffic gathers per-IP byte counts using the best available method:
//  1. /proc/net/nf_conntrack  (kernel conntrack with accounting enabled)
//  2. conntrack CLI tool       (fallback when proc file unavailable)
//  3. /proc/net/dev            (per-interface totals, divided across ARP peers —
//     used only when no per-IP data is available at all)
func collectDeviceTraffic() {
	// Reset daily counters at midnight
	midnight := todayMidnight()
	if midnight.After(deviceTrafficReset) {
		deviceTrafficMu.Lock()
		deviceTrafficDay = make(map[string]uint64)
		deviceTrafficReset = midnight
		deviceTrafficMu.Unlock()
	}

	perIP := make(map[string][2]uint64) // ip -> [rx, tx]

	// --- Strategy 1: /proc/net/nf_conntrack ---
	if data, err := os.ReadFile("/proc/net/nf_conntrack"); err == nil && len(data) > 0 {
		parseConntrackLines(string(data), perIP)
		if len(perIP) > 0 {
			updateDeviceTrafficFromSnapshot(perIP)
			return
		}
	}

	// --- Strategy 2: conntrack CLI ---
	// Try with -o extended to get accounting output
	if out, err := runPrivilegedOutput("conntrack", "-L", "-o", "extended"); err == nil && len(out) > 0 {
		parseConntrackLines(string(out), perIP)
		if len(perIP) > 0 {
			updateDeviceTrafficFromSnapshot(perIP)
			return
		}
	}
	// Try without extended flag
	if out, err := runPrivilegedOutput("conntrack", "-L"); err == nil && len(out) > 0 {
		parseConntrackLines(string(out), perIP)
		if len(perIP) > 0 {
			updateDeviceTrafficFromSnapshot(perIP)
			return
		}
	}

	// --- Strategy 3: /proc/net/dev (interface-level stats) ---
	// When conntrack is unavailable, use per-interface counters.
	// Map traffic on each interface proportionally to its ARP neighbors.
	collectFromProcNetDev(perIP)
	if len(perIP) > 0 {
		updateDeviceTrafficFromSnapshot(perIP)
	}
}

// parseConntrackLines parses nf_conntrack / conntrack-CLI output into per-IP byte counts.
//
// Format of /proc/net/nf_conntrack (with nf_conntrack_acct=1):
//
//	ipv4 2 tcp 6 3600 ESTABLISHED src=192.168.1.10 dst=8.8.8.8 sport=... dport=... \
//	  packets=123 bytes=9876 src=8.8.8.8 dst=192.168.1.10 ... packets=45 bytes=4321 ...
//
// The first src=/dst= pair is the original direction, the second is the reply.
// First bytes= = bytes sent from src (upload from LAN device).
// Second bytes= = bytes sent in reply (download to LAN device).
func parseConntrackLines(data string, perIP map[string][2]uint64) {
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		// Collect all src=, dst=, bytes= values in order of appearance
		var srcs, dsts []string
		var byteVals []uint64

		for _, f := range fields {
			switch {
			case strings.HasPrefix(f, "src="):
				srcs = append(srcs, f[4:])
			case strings.HasPrefix(f, "dst="):
				dsts = append(dsts, f[4:])
			case strings.HasPrefix(f, "bytes="):
				v, _ := strconv.ParseUint(f[6:], 10, 64)
				byteVals = append(byteVals, v)
			}
		}

		// Need at least the original direction
		if len(srcs) == 0 || len(byteVals) == 0 {
			continue
		}

		origSrc := srcs[0]

		// Byte values: byteVals[0] = original direction (src→dst), byteVals[1] = reply (dst→src)
		var txBytes, rxBytes uint64
		txBytes = byteVals[0]
		if len(byteVals) > 1 {
			rxBytes = byteVals[1]
		}

		// If either value is zero and acct isn't working, use packets*avg heuristic — skip.
		// Only accumulate if we have actual byte data.
		if txBytes == 0 && rxBytes == 0 {
			continue
		}

		// Track the LAN (private) IP as the device
		if isPrivateIP(origSrc) {
			entry := perIP[origSrc]
			entry[0] += rxBytes // download to device
			entry[1] += txBytes // upload from device
			perIP[origSrc] = entry
		} else if len(dsts) > 0 && isPrivateIP(dsts[0]) {
			// Inbound connection (server on LAN receiving)
			dst := dsts[0]
			entry := perIP[dst]
			entry[0] += txBytes // bytes toward LAN device = download
			entry[1] += rxBytes // reply bytes = upload from device
			perIP[dst] = entry
		}
	}
}

// collectFromProcNetDev reads /proc/net/dev and distributes interface bytes
// across all ARP-known neighbors on that interface.
func collectFromProcNetDev(perIP map[string][2]uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}

	// Parse /proc/net/dev: each line after the header has the format:
	//   iface: rxBytes rxPkts rxErr rxDrop ... txBytes txPkts txErr txDrop ...
	type ifaceStats struct {
		name    string
		rxBytes uint64
		txBytes uint64
	}
	var stats []ifaceStats

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Strip leading space, split on colon
		line = strings.TrimSpace(line)
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		if name == "lo" || name == "" {
			continue
		}
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 9 {
			continue
		}
		rxB, _ := strconv.ParseUint(fields[0], 10, 64)
		txB, _ := strconv.ParseUint(fields[8], 10, 64)
		if rxB == 0 && txB == 0 {
			continue
		}
		stats = append(stats, ifaceStats{name: name, rxBytes: rxB, txBytes: txB})
	}

	if len(stats) == 0 {
		return
	}

	// Build a map of interface -> ARP neighbors (private IPs only)
	ifaceNeighbors := make(map[string][]string)
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			ifaceNeighbors[iface.Name] = []string{}
		}
	}

	// Read ARP table
	if arpData, err := os.ReadFile("/proc/net/arp"); err == nil {
		for _, line := range strings.Split(string(arpData), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			ip := fields[0]
			flags := fields[2]
			device := fields[5]
			// Only valid (flags != 0x0) private IP entries
			if flags == "0x0" || !isPrivateIP(ip) {
				continue
			}
			ifaceNeighbors[device] = append(ifaceNeighbors[device], ip)
		}
	}

	// Also get addresses of the router itself on each interface
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip string
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP.String()
				case *net.IPAddr:
					ip = v.IP.String()
				}
				if ip != "" && isPrivateIP(ip) && ip != "127.0.0.1" {
					ifaceNeighbors[iface.Name] = append(ifaceNeighbors[iface.Name], ip)
				}
			}
		}
	}

	// Distribute each interface's bytes evenly across its neighbors
	for _, s := range stats {
		neighbors := ifaceNeighbors[s.name]
		if len(neighbors) == 0 {
			continue
		}
		rxPerDevice := s.rxBytes / uint64(len(neighbors))
		txPerDevice := s.txBytes / uint64(len(neighbors))
		for _, ip := range neighbors {
			entry := perIP[ip]
			entry[0] += rxPerDevice
			entry[1] += txPerDevice
			perIP[ip] = entry
		}
	}
}

func updateDeviceTrafficFromSnapshot(snapshot map[string][2]uint64) {
	now := time.Now()

	deviceTrafficMu.Lock()
	defer deviceTrafficMu.Unlock()

	for ip, bytes := range snapshot {
		rx := bytes[0]
		tx := bytes[1]

		prev, exists := deviceTrafficMap[ip]
		if !exists {
			deviceTrafficMap[ip] = &deviceTrafficState{
				RxBytes:    rx,
				TxBytes:    tx,
				LastUpdate: now,
			}
			deviceTrafficDay[ip] += rx + tx
			continue
		}

		// Calculate rates based on delta since last collection
		elapsed := now.Sub(prev.LastUpdate).Seconds()
		if elapsed > 0 {
			if rx >= prev.RxBytes {
				prev.RxRate = uint64(float64(rx-prev.RxBytes) / elapsed)
			} else {
				// Counter wrapped or connection table was flushed — reset rate
				prev.RxRate = 0
			}
			if tx >= prev.TxBytes {
				prev.TxRate = uint64(float64(tx-prev.TxBytes) / elapsed)
			} else {
				prev.TxRate = 0
			}
		}

		// Track daily delta
		if rx > prev.RxBytes {
			deviceTrafficDay[ip] += rx - prev.RxBytes
		}
		if tx > prev.TxBytes {
			deviceTrafficDay[ip] += tx - prev.TxBytes
		}

		prev.RxBytes = rx
		prev.TxBytes = tx
		prev.LastUpdate = now
	}
}

func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "172.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "169.254.")
}

// --- API Handlers ---

func getDeviceTraffic(w http.ResponseWriter, r *http.Request) {
	// Get ARP table and DHCP leases for hostname resolution
	arpEntries, _ := getARPTable()
	dhcpLeases, _ := parseDHCPLeases()

	type devInfo struct {
		MAC      string
		Hostname string
	}
	knownDevices := make(map[string]devInfo)

	for _, lease := range dhcpLeases {
		if lease.IP == "" {
			continue
		}
		knownDevices[lease.IP] = devInfo{
			MAC:      lease.MAC,
			Hostname: lease.Hostname,
		}
	}

	for _, arp := range arpEntries {
		if arp.IP == "" {
			continue
		}
		dev := knownDevices[arp.IP]
		if arp.MAC != "" {
			dev.MAC = arp.MAC
		}
		if arp.Hostname != "" && (dev.Hostname == "" || dev.Hostname == "*") {
			dev.Hostname = arp.Hostname
		}
		knownDevices[arp.IP] = dev
	}

	// Also check static leases
	store, _ := loadDHCPConfig()
	if store != nil {
		for _, sl := range store.StaticLeases {
			if sl.IP == "" {
				continue
			}
			dev := knownDevices[sl.IP]
			if sl.MAC != "" {
				dev.MAC = sl.MAC
			}
			if sl.Hostname != "" && (dev.Hostname == "" || dev.Hostname == "*") {
				dev.Hostname = sl.Hostname
			}
			knownDevices[sl.IP] = dev
		}
	}

	deviceTrafficMu.RLock()
	defer deviceTrafficMu.RUnlock()

	// Add any additional IPs currently in deviceTrafficMap
	for ip := range deviceTrafficMap {
		if _, exists := knownDevices[ip]; !exists {
			knownDevices[ip] = devInfo{}
		}
	}

	var entries []DeviceTrafficEntry
	for ip, dev := range knownDevices {
		if !isPrivateIP(ip) || ip == "127.0.0.1" {
			continue
		}

		state := deviceTrafficMap[ip]
		var rxBytes, txBytes, rxRate, txRate, totalToday uint64
		if state != nil {
			rxBytes = state.RxBytes
			txBytes = state.TxBytes
			rxRate = state.RxRate
			txRate = state.TxRate
			totalToday = deviceTrafficDay[ip]
		}

		hostname := dev.Hostname
		if hostname == "*" || hostname == "" {
			hostname = "Device (" + ip + ")"
		}

		entry := DeviceTrafficEntry{
			IP:         ip,
			MAC:        dev.MAC,
			Hostname:   hostname,
			RxBytes:    rxBytes,
			TxBytes:    txBytes,
			RxRate:     rxRate,
			TxRate:     txRate,
			TotalToday: totalToday,
		}

		entries = append(entries, entry)
	}

	if entries == nil {
		entries = []DeviceTrafficEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=5")
	json.NewEncoder(w).Encode(entries)
}

func getDeviceTrafficDetail(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		respondWithError(w, ErrGenericInvalidRequest, "IP address parameter is required", http.StatusBadRequest, nil)
		return
	}

	deviceTrafficMu.RLock()
	state, exists := deviceTrafficMap[ip]
	dailyTotal := deviceTrafficDay[ip]
	deviceTrafficMu.RUnlock()

	var rxBytes, txBytes, rxRate, txRate uint64
	var lastUpdate time.Time = time.Now()
	if exists && state != nil {
		rxBytes = state.RxBytes
		txBytes = state.TxBytes
		rxRate = state.RxRate
		txRate = state.TxRate
		lastUpdate = state.LastUpdate
	}

	detail := map[string]interface{}{
		"ip":          ip,
		"rx_bytes":    rxBytes,
		"tx_bytes":    txBytes,
		"rx_rate":     rxRate,
		"tx_rate":     txRate,
		"total_today": dailyTotal,
		"last_update": lastUpdate,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detail)
}

// formatBytes returns a human-readable byte string (used in notifications)
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
