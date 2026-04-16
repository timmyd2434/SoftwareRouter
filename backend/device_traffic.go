package main

import (
	"encoding/json"
	"fmt"
	"log"
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
	RxRate     uint64 `json:"rx_rate"`      // Bytes per second
	TxRate     uint64 `json:"tx_rate"`      // Bytes per second
	TotalToday uint64 `json:"total_today"`  // Total bytes since midnight
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
	deviceTrafficDay   = make(map[string]uint64)               // IP -> total bytes today
	deviceTrafficReset time.Time                               // When daily counters were last reset
)

func initDeviceTraffic() {
	deviceTrafficReset = todayMidnight()
	go deviceTrafficLoop()
	log.Println("Per-device traffic monitoring started")
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

// collectDeviceTraffic parses /proc/net/nf_conntrack or uses nft counters
// to compute per-IP byte counts
func collectDeviceTraffic() {
	// Reset daily counters at midnight
	midnight := todayMidnight()
	if midnight.After(deviceTrafficReset) {
		deviceTrafficMu.Lock()
		deviceTrafficDay = make(map[string]uint64)
		deviceTrafficReset = midnight
		deviceTrafficMu.Unlock()
	}

	// Read conntrack table for per-connection byte counts
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		// Fallback: try /proc/net/ip_conntrack (older kernels)
		data, err = os.ReadFile("/proc/net/ip_conntrack")
		if err != nil {
			// conntrack not available — try nft approach
			collectDeviceTrafficNFT()
			return
		}
	}

	// Parse conntrack entries
	// Format: ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.100 dst=142.250.80.46 sport=54321 dport=443 bytes=12345 ...
	perIP := make(map[string][2]uint64) // ip -> [rx, tx]

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		var src, dst string
		var txBytes, rxBytes uint64

		for _, f := range fields {
			if strings.HasPrefix(f, "src=") {
				if src == "" {
					src = f[4:]
				}
			} else if strings.HasPrefix(f, "dst=") {
				if dst == "" {
					dst = f[4:]
				}
			} else if strings.HasPrefix(f, "bytes=") {
				val, _ := strconv.ParseUint(f[6:], 10, 64)
				if txBytes == 0 {
					txBytes = val // First bytes= is src->dst (upload from src)
				} else {
					rxBytes = val // Second bytes= is dst->src (download to src)
				}
			}
		}

		// Only track local (private) IPs
		if src != "" && isPrivateIP(src) {
			entry := perIP[src]
			entry[0] += rxBytes // download to this device
			entry[1] += txBytes // upload from this device
			perIP[src] = entry
		}
		if dst != "" && isPrivateIP(dst) && !isPrivateIP(src) {
			// Inbound from public to private
			entry := perIP[dst]
			entry[0] += txBytes
			entry[1] += rxBytes
			perIP[dst] = entry
		}
	}

	updateDeviceTrafficFromSnapshot(perIP)
}

// collectDeviceTrafficNFT uses nftables counters as a fallback
func collectDeviceTrafficNFT() {
	output, err := runPrivilegedOutput("nft", "list", "ruleset")
	if err != nil {
		return
	}

	// Parse nft output for per-IP counters
	// This is a simplified parser — in production, set up dedicated nft counting rules
	_ = output // Placeholder — conntrack approach is preferred
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

		// Calculate rates
		elapsed := now.Sub(prev.LastUpdate).Seconds()
		if elapsed > 0 {
			if rx >= prev.RxBytes {
				prev.RxRate = uint64(float64(rx-prev.RxBytes) / elapsed)
			}
			if tx >= prev.TxBytes {
				prev.TxRate = uint64(float64(tx-prev.TxBytes) / elapsed)
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

	// Build hostname lookup
	ipToHostname := make(map[string]string)
	ipToMAC := make(map[string]string)
	for _, lease := range dhcpLeases {
		if lease.Hostname != "*" && lease.Hostname != "" {
			ipToHostname[lease.IP] = lease.Hostname
		}
		ipToMAC[lease.IP] = lease.MAC
	}
	for _, arp := range arpEntries {
		if _, ok := ipToMAC[arp.IP]; !ok {
			ipToMAC[arp.IP] = arp.MAC
		}
		if arp.Hostname != "" {
			ipToHostname[arp.IP] = arp.Hostname
		}
	}

	// Also check static leases
	store, _ := loadDHCPConfig()
	if store != nil {
		for _, sl := range store.StaticLeases {
			if sl.Hostname != "" {
				ipToHostname[sl.IP] = sl.Hostname
			}
			ipToMAC[sl.IP] = sl.MAC
		}
	}

	deviceTrafficMu.RLock()
	defer deviceTrafficMu.RUnlock()

	var entries []DeviceTrafficEntry
	for ip, state := range deviceTrafficMap {
		entry := DeviceTrafficEntry{
			IP:         ip,
			MAC:        ipToMAC[ip],
			Hostname:   ipToHostname[ip],
			RxBytes:    state.RxBytes,
			TxBytes:    state.TxBytes,
			RxRate:     state.RxRate,
			TxRate:     state.TxRate,
			TotalToday: deviceTrafficDay[ip],
		}

		// Skip devices with zero traffic
		if state.RxBytes == 0 && state.TxBytes == 0 {
			continue
		}

		entries = append(entries, entry)
	}

	// If no entries, return empty array (not null)
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

	if !exists {
		respondWithError(w, ErrGenericNotFound, "Device not found in traffic tracking", http.StatusNotFound, nil)
		return
	}

	detail := map[string]interface{}{
		"ip":          ip,
		"rx_bytes":    state.RxBytes,
		"tx_bytes":    state.TxBytes,
		"rx_rate":     state.RxRate,
		"tx_rate":     state.TxRate,
		"total_today": dailyTotal,
		"last_update": state.LastUpdate,
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
