package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	os.MkdirAll(clientsDir, 0750)

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

	wgMu.Lock()
	defer wgMu.Unlock()

	// 1. Current server config and existing peers
	confBytes, err := os.ReadFile(wgConfPath)
	if err != nil {
		respondSystemError(w, ErrVPNCreateFailed, "WireGuard is not initialised (wg0.conf missing)", err)
		return
	}
	peers := parseWGPeers(string(confBytes))
	for _, p := range peers {
		if p.Name == req.Name {
			http.Error(w, "A VPN client with that name already exists", http.StatusConflict)
			return
		}
	}
	clientConfPath := filepath.Join(wgClientsDir, req.Name+".conf")
	if _, err := os.Stat(clientConfPath); err == nil {
		http.Error(w, "A VPN client with that name already exists", http.StatusConflict)
		return
	}

	// 2. The address the phone must dial. Never derive it from the browser's
	// Host header: opened at home that is a LAN address, which is useless
	// from outside. Refuse to produce a config that cannot work.
	endpoint, err := resolveVPNEndpoint()
	if err == nil {
		err = validateHostOrIP(endpoint)
	}
	if err != nil {
		http.Error(w, "Cannot determine the router's public address for the client config ("+err.Error()+
			"). Set the VPN endpoint (public IP or DDNS hostname) in the VPN settings and try again.", http.StatusUnprocessableEntity)
		return
	}

	serverPubRaw, err := os.ReadFile(wgServerPubKeyPath)
	serverPub := strings.TrimSpace(string(serverPubRaw))
	if err != nil || !wgKeyRe.MatchString(serverPub) {
		respondSystemError(w, ErrVPNCreateFailed, "Server public key is missing or invalid", err)
		return
	}

	// 3. Client keys and a unique address
	privKey, err := runPrivilegedOutput("wg", "genkey")
	if err != nil {
		respondSystemError(w, ErrVPNCreateFailed, "Failed to generate client key", err)
		return
	}
	cleanPriv := strings.TrimSpace(string(privKey))
	pubKey, err := deriveWireGuardPublicKey(privKey)
	if err != nil {
		respondSystemError(w, ErrVPNCreateFailed, "Failed to derive public key", err)
		return
	}
	cleanPub := strings.TrimSpace(string(pubKey))
	if !wgKeyRe.MatchString(cleanPub) {
		respondSystemError(w, ErrVPNCreateFailed, "Derived public key is malformed", fmt.Errorf("unexpected key format"))
		return
	}
	clientAddr, err := nextFreeWGAddress(peers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// 4. Persist the peer (atomic), then load it into the running interface
	if err := writeRootConfigAtomic(wgConfPath, []byte(appendWGPeer(string(confBytes), req.Name, cleanPub, clientAddr)), 0600); err != nil {
		respondSystemError(w, ErrVPNCreateFailed, "Failed to update wg0.conf", err)
		return
	}
	live := true
	if err := runPrivileged("wg", "set", wgIface, "peer", cleanPub, "allowed-ips", clientAddr); err != nil {
		live = false
		log.Printf("WireGuard: peer saved but not loaded into the running interface (%v); it will load on the next wg-quick@wg0 restart", err)
	}

	// 5. The client file, ready to import without edits
	clientConf := buildWGClientConfig(cleanPriv, clientAddr, serverPub, endpoint)
	os.MkdirAll(wgClientsDir, 0750)
	if err := os.WriteFile(clientConfPath, []byte(clientConf), 0600); err != nil {
		// roll back so no orphan peer is left behind
		_ = writeRootConfigAtomic(wgConfPath, confBytes, 0600)
		_ = runPrivileged("wg", "set", wgIface, "peer", cleanPub, "remove")
		respondSystemError(w, ErrVPNCreateFailed, "Failed to save client config", err)
		return
	}

	resp := map[string]interface{}{"status": "success", "config": clientConf, "endpoint": endpoint, "address": clientAddr, "live": live}
	if !live {
		resp["warning"] = "Peer saved, but the WireGuard interface is not running. Start it (systemctl start wg-quick@wg0) and the peer will load."
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func deleteVPNClient(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" || !validVPNClientName.MatchString(name) {
		http.Error(w, "Invalid name", http.StatusBadRequest)
		return
	}

	wgMu.Lock()
	defer wgMu.Unlock()

	removed := 0
	if content, err := os.ReadFile(wgConfPath); err == nil {
		newContent, keys := removeWGPeersByName(string(content), name)
		if len(keys) > 0 {
			if err := writeRootConfigAtomic(wgConfPath, []byte(newContent), 0600); err != nil {
				respondSystemError(w, ErrVPNCreateFailed, "Failed to update wg0.conf", err)
				return
			}
			for _, k := range keys {
				if wgKeyRe.MatchString(k) {
					if err := runPrivileged("wg", "set", wgIface, "peer", k, "remove"); err != nil {
						log.Printf("WireGuard: could not remove live peer (interface down?): %v", err)
					}
				}
				removed++
			}
		}
	}
	os.Remove(filepath.Join(wgClientsDir, name+".conf"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "removed_peers": removed})
}

func downloadVPNClient(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" || !validVPNClientName.MatchString(name) {
		http.Error(w, "Invalid name", http.StatusBadRequest)
		return
	}
	clientsDir := "/etc/softrouter/vpn_clients"
	confPath := fmt.Sprintf("%s/%s.conf", clientsDir, name)

	// #nosec G304 G703: path is validated or constructed from safe internal sources
	data, err := os.ReadFile(confPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", name))
	w.Header().Set("Content-Type", "application/x-wireguard-config")
	w.Write(data)
}
