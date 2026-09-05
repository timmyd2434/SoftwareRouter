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
	if err := runPrivileged("modprobe", "nf_conntrack"); err != nil {
		log.Printf("[WARN] Could not load nf_conntrack module: %v", err)
	}
	collectDeviceTraffic()
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

	var data []byte
	var err error

	// Read conntrack table for per-connection byte counts
	data, err = os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		data, err = os.ReadFile("/proc/net/ip_conntrack")
	}

	if err != nil || len(data) == 0 {
		// Attempt to load module and try once more
		_ = runPrivileged("modprobe", "nf_conntrack")
		data, err = os.ReadFile("/proc/net/nf_conntrack")
	}

	if (err != nil || len(data) == 0) && allowedCommands["conntrack"] {
		// Fallback: use conntrack CLI if proc file unavailable
		if out, conntrackErr := runPrivilegedOutput("conntrack", "-L"); conntrackErr == nil {
			data = out
			err = nil
		}
	}

	perIP := make(map[string][2]uint64) // ip -> [rx, tx]

	if err == nil && len(data) > 0 {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				continue
			}

			var src, dst string
			var txBytes, rxBytes uint64
			var seenFirstBytes bool

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
					if !seenFirstBytes {
						txBytes = val // First bytes= is src->dst (upload from src)
						seenFirstBytes = true
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
	}

	updateDeviceTrafficFromSnapshot(perIP)
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
