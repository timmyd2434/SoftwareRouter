package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// validVPNClientName ensures the name contains only safe characters (alphanumeric, hyphens, underscores)
// This prevents path traversal (../../etc/passwd) and command injection via easyrsa args
var validVPNClientName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// --- VPN Client Management ---

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

	if req.Name == "" || !validVPNClientName.MatchString(req.Name) {
		http.Error(w, "Invalid name: must be alphanumeric, hyphens, or underscores only", http.StatusBadRequest)
		return
	}

	clientsDir := "/etc/softrouter/vpn_clients"
	os.MkdirAll(clientsDir, 0755)

	// 1. Generate Client Keys
	privKey, err := runPrivilegedOutput("wg", "genkey")
	if err != nil {
		http.Error(w, "Failed to generate client key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cleanPriv := strings.TrimSpace(string(privKey))

	pubKey, err := deriveWireGuardPublicKey(privKey)
	if err != nil {
		http.Error(w, "Failed to derive public key: "+err.Error(), http.StatusInternalServerError)
		return
	}
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
		runPrivileged("wg", "syncconf", "wg0", "/etc/wireguard/wg0.conf")
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
	if name == "" || !validVPNClientName.MatchString(name) {
		http.Error(w, "Invalid name", http.StatusBadRequest)
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
	if name == "" || !validVPNClientName.MatchString(name) {
		http.Error(w, "Invalid name", http.StatusBadRequest)
		return
	}
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
