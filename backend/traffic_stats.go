package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TrafficPoint represents a single data point in time
type TrafficPoint struct {
	Timestamp int64  `json:"timestamp"` // Unix epoch
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxRate    uint64 `json:"rx_rate"` // Bps
	TxRate    uint64 `json:"tx_rate"` // Bps
}

// TrafficHistory stores history for an interface
type TrafficHistory struct {
	Points []TrafficPoint
}

var (
	history      = make(map[string]*TrafficHistory)
	historyMutex sync.RWMutex
	lastStats    = make(map[string]TrafficPoint) // To calc rates

	// Config
	historyInterval  = 5 * time.Second
	maxHistoryPoints = 720 // 1 hour at 5s execution (approx) or more.
	// Let's do 120 points for live graph?
	// For "Historical" maybe we want longer terms.
	// Let's keep 1000 points @ 10s = ~2.7 hours.
)

func initTrafficStats() {
	go func() {
		ticker := time.NewTicker(historyInterval)
		for range ticker.C {
			collectTrafficStats()
		}
	}()
}

func collectTrafficStats() {
	// Read /proc/net/dev for Linux
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	now := time.Now().Unix()

	historyMutex.Lock()
	defer historyMutex.Unlock()

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Format: "eth0: 123 45 67 ..." or "eth0:123 ..."
		// Name usually ends with colon
		name := strings.TrimSuffix(fields[0], ":")

		// Parse RX bytes (1st field after name)
		rx, _ := strconv.ParseUint(fields[1], 10, 64)
		// Parse TX bytes (9th field after name) -> index 9
		tx, _ := strconv.ParseUint(fields[9], 10, 64)

		// Calculate Rate
		rxRate := uint64(0)
		txRate := uint64(0)

		last, ok := lastStats[name]
		if ok {
			diffTime := now - last.Timestamp
			if diffTime > 0 {
				// Handle wrap around roughly or ignore (uint64 wrap is rare in 10s)
				if rx >= last.RxBytes {
					rxRate = (rx - last.RxBytes) / uint64(diffTime)
				}
				if tx >= last.TxBytes {
					txRate = (tx - last.TxBytes) / uint64(diffTime)
				}
			}
		}

		point := TrafficPoint{
			Timestamp: now,
			RxBytes:   rx,
			TxBytes:   tx,
			RxRate:    rxRate,
			TxRate:    txRate,
		}

		// Store for next rate calc
		lastStats[name] = point

		// Append to history
		if _, exists := history[name]; !exists {
			history[name] = &TrafficHistory{Points: make([]TrafficPoint, 0)}
		}

		h := history[name]
		h.Points = append(h.Points, point)

		// Prune old
		if len(h.Points) > maxHistoryPoints {
			h.Points = h.Points[len(h.Points)-maxHistoryPoints:]
		}
	}

	// Calculate Total Traffic
	totalRx := uint64(0)
	totalTx := uint64(0)
	totalRxRate := uint64(0)
	totalTxRate := uint64(0)
	// We iterate over the history just updated for the current timestamp
	// Actually, easier to iterate over lines/fields again? No.
	// We can iterate over lastStats if we trust it, or accumulated as we went.
	// But we need the *rate*, which we just calculated.
	// Let's re-iterate lastStats but that includes everything.
	// Better: accumulate inside the loop above.
	// But resetting loop logic is annoying.
	// Let's just loop over history for the "latest" point of each interface.
	// Valid interfaces only.
	for name, h := range history {
		if name == "total" || name == "lo" || strings.HasPrefix(name, "tun") { // Skip virtuals?
			continue
		}
		if len(h.Points) > 0 {
			lastP := h.Points[len(h.Points)-1]
			if lastP.Timestamp == now {
				totalRx += lastP.RxBytes
				totalTx += lastP.TxBytes
				totalRxRate += lastP.RxRate
				totalTxRate += lastP.TxRate
			}
		}
	}

	totalPoint := TrafficPoint{
		Timestamp: now,
		RxBytes:   totalRx,
		TxBytes:   totalTx,
		RxRate:    totalRxRate,
		TxRate:    totalTxRate,
	}

	// Store total history
	if _, exists := history["total"]; !exists {
		history["total"] = &TrafficHistory{Points: make([]TrafficPoint, 0)}
	}
	th := history["total"]
	th.Points = append(th.Points, totalPoint)
	if len(th.Points) > maxHistoryPoints {
		th.Points = th.Points[len(th.Points)-maxHistoryPoints:]
	}
}

func getTrafficHistory(w http.ResponseWriter, r *http.Request) {
	iface := r.URL.Query().Get("interface")

	historyMutex.RLock()
	defer historyMutex.RUnlock()

	// If interface specified, return only that
	if iface != "" {
		if h, ok := history[iface]; ok {
			json.NewEncoder(w).Encode(h.Points)
			return
		}
		json.NewEncoder(w).Encode([]TrafficPoint{})
		return
	}

	// Else return total history if available
	if h, ok := history["total"]; ok {
		json.NewEncoder(w).Encode(h.Points)
		return
	}

	// Fallback to empty list
	json.NewEncoder(w).Encode([]TrafficPoint{})
}
