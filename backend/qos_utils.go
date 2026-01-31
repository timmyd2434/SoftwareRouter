package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
)

// QoSConfig represents the Traffic Control settings for an interface
type QoSConfig struct {
	Interface string `json:"interface"`
	Mode      string `json:"mode"`     // "cake", "htb", "none"
	Upload    string `json:"upload"`   // e.g., "100mbit", "1gbit"
	Download  string `json:"download"` // e.g., "100mbit" (Requires IFB for true shaping, or ingress policing)
	Overhead  int    `json:"overhead"` // Transport overhead in bytes (e.g. 18, 44) for DSL/ATM
}

var (
	qosConfigs      = make(map[string]QoSConfig)
	qosLock         sync.RWMutex
	qosConfigPath   = "/etc/softrouter/qos_config.json"
	ifbDevicePrefix = "ifb4" // Prefix for IFB devices used for ingress shaping
)

// InitQoS loads configuration and re-applies it (optional on startup)
func InitQoS() {
	loadQoSConfigs()
	// Re-apply could be implemented here if we want persistence across reboots
	// For now, we rely on the user applying or a startup script calling the API.
	// Ideally, we iterate and apply:
	qosLock.RLock()
	defer qosLock.RUnlock()
	for _, cfg := range qosConfigs {
		if cfg.Mode != "none" {
			fmt.Printf("Re-applying QoS for %s\n", cfg.Interface)
			ApplyQoS(cfg)
		}
	}
}

func loadQoSConfigs() {
	qosLock.Lock()
	defer qosLock.Unlock()

	data, err := os.ReadFile(qosConfigPath)
	if err != nil {
		return
	}

	// Temporarily load into a list or map?
	// The file should probably store a list or map.
	// Let's assume Map format in JSON for ease
	var loaded map[string]QoSConfig
	if err := json.Unmarshal(data, &loaded); err == nil {
		qosConfigs = loaded
	}
}

func saveQoSConfigs() error {
	qosLock.RLock()
	defer qosLock.RUnlock()

	data, err := json.MarshalIndent(qosConfigs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(qosConfigPath, data, 0644)
}

// ApplyQoS applies the traffic control settings
func ApplyQoS(cfg QoSConfig) error {
	// 1. Cleanup existing
	RemoveQoS(cfg.Interface)

	if cfg.Mode == "none" {
		return nil
	}

	// 2. Egress Shaping (Upload)
	// using CAKE: tc qdisc add dev <dev> root cake bandwidth <rate>
	if cfg.Upload != "" {
		args := []string{"qdisc", "add", "dev", cfg.Interface, "root", "cake", "bandwidth", cfg.Upload, "besteffort"}
		if cfg.Overhead > 0 {
			args = append(args, "overhead", fmt.Sprintf("%d", cfg.Overhead))
		}

		cmd := exec.Command("tc", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to apply egress cake: %s (%v)", string(out), err)
		}
	}

	// 3. Ingress Shaping (Download)
	// Requires IFB.
	// Setup:
	// ip link add name <ifb> type ifb
	// ip link set dev <ifb> up
	// tc qdisc add dev <dev> handle ffff: ingress
	// tc filter add dev <dev> parent ffff: matchall action mirred egress redirect dev <ifb>
	// tc qdisc add dev <ifb> root cake bandwidth <rate> besteffort

	if cfg.Download != "" {
		ifbDev := ifbDevicePrefix + cfg.Interface // e.g. ifb4eth0

		// Ensure IFB exists (might fail if module not loaded, but 'ip link add type ifb' works on modern kernels if supported)
		// We catch errors but proceed.
		exec.Command("ip", "link", "add", "name", ifbDev, "type", "ifb").Run()
		exec.Command("ip", "link", "set", "dev", ifbDev, "up").Run()

		// Ingress qdisc on real dev
		exec.Command("tc", "qdisc", "add", "dev", cfg.Interface, "handle", "ffff:", "ingress").Run()

		// Redirect to IFB
		redirectCmd := exec.Command("tc", "filter", "add", "dev", cfg.Interface, "parent", "ffff:", "matchall", "action", "mirred", "egress", "redirect", "dev", ifbDev)
		if out, err := redirectCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to redirect ingress to IFB: %s", string(out))
		}

		// Apply CAKE on IFB
		cakeArgs := []string{"qdisc", "add", "dev", ifbDev, "root", "cake", "bandwidth", cfg.Download, "besteffort"}
		if cfg.Overhead > 0 {
			cakeArgs = append(cakeArgs, "overhead", fmt.Sprintf("%d", cfg.Overhead))
		}

		if out, err := exec.Command("tc", cakeArgs...).CombinedOutput(); err != nil {
			return fmt.Errorf("failed to apply ingress cake on %s: %s", ifbDev, string(out))
		}
	}

	return nil
}

// RemoveQoS deletes traffic control settings
func RemoveQoS(iface string) {
	// Remove Root (Egress)
	exec.Command("tc", "qdisc", "del", "dev", iface, "root").Run()

	// Remove Ingress
	exec.Command("tc", "qdisc", "del", "dev", iface, "ingress").Run()

	// Remove IFB if it exists
	ifbDev := ifbDevicePrefix + iface
	exec.Command("ip", "link", "del", "dev", ifbDev).Run()
}

// GetQoSStatus returns the raw 'tc -s qdisc' output
func GetQoSStatus(iface string) (string, error) {
	out, err := exec.Command("tc", "-s", "qdisc", "show", "dev", iface).CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Handlers

func getQoSConfig(w http.ResponseWriter, r *http.Request) {
	qosLock.RLock()
	defer qosLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(qosConfigs)
}

func updateQoSConfig(w http.ResponseWriter, r *http.Request) {
	var req QoSConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Interface == "" {
		http.Error(w, "Interface is required", http.StatusBadRequest)
		return
	}

	// Apply (System)
	if err := ApplyQoS(req); err != nil {
		http.Error(w, "Failed to apply QoS: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Save (Memory + Disk)
	qosLock.Lock()
	qosConfigs[req.Interface] = req
	qosLock.Unlock()

	saveQoSConfigs()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "applied"})
}

func deleteQoSConfig(w http.ResponseWriter, r *http.Request) {
	// Assuming /api/qos?interface=eth0
	iface := r.URL.Query().Get("interface")
	if iface == "" {
		http.Error(w, "Interface param required", http.StatusBadRequest)
		return
	}

	RemoveQoS(iface)

	qosLock.Lock()
	delete(qosConfigs, iface)
	qosLock.Unlock()

	saveQoSConfigs()

	w.WriteHeader(http.StatusOK)
}
