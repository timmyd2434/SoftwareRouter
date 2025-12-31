package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// OpenVPNServerStatus structure
type OpenVPNServerStatus struct {
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	ClientCount int    `json:"client_count"`
}

// OpenVPNClientCert represents a generated client
type OpenVPNClientCert struct {
	Name      string `json:"name"`
	State     string `json:"state"` // V=Valid, R=Revoked
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

const (
	ovpnServerDir  = "/etc/openvpn/server"
	ovpnEasyRsaDir = "/etc/openvpn/easy-rsa"
	ovpnSystemd    = "openvpn-server@server"
	ovpnPort       = 1194
	ovpnSubnet     = "10.8.1.0 255.255.255.0"
)

// getOpenVPNServerStatus returns the health and install state
func getOpenVPNServerStatus(w http.ResponseWriter, r *http.Request) {
	status := OpenVPNServerStatus{
		Port:     ovpnPort,
		Protocol: "UDP",
	}

	// Check if configured
	if _, err := os.Stat(filepath.Join(ovpnServerDir, "server.conf")); err == nil {
		status.Installed = true
	}

	// Check if running
	cmd := exec.Command("systemctl", "is-active", ovpnSystemd)
	out, _ := cmd.CombinedOutput()
	if strings.TrimSpace(string(out)) == "active" {
		status.Running = true
	}

	// Count clients (using index.txt)
	clients, _ := listOpenVPNClientsInternal()
	status.ClientCount = len(clients)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// setupOpenVPNServer initializes PKI and configures the server
func setupOpenVPNServer(w http.ResponseWriter, r *http.Request) {
	// 1. Prepare Directory
	os.RemoveAll(ovpnEasyRsaDir)
	if err := exec.Command("cp", "-r", "/usr/share/easy-rsa", ovpnEasyRsaDir).Run(); err != nil {
		http.Error(w, "Failed to copy easy-rsa: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 2. PKI Initialization commands
	// We use a helper script to chain these env vars and commands easily
	setupScript := fmt.Sprintf(`
#!/bin/bash
set -e
cd %s
./easyrsa init-pki
echo "SoftRouter-CA" | ./easyrsa build-ca nopass
./easyrsa build-server-full server nopass
./easyrsa gen-dh
openvpn --genkey --secret ta.key
cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key %s/
`, ovpnEasyRsaDir, ovpnServerDir)

	if err := runShellScript(setupScript); err != nil {
		http.Error(w, "PKI Setup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Write Server Config
	serverConf := fmt.Sprintf(`
port %d
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA256
tls-crypt ta.key
topology subnet
server %s
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 10 120
cipher AES-256-GCM
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
`, ovpnPort, ovpnSubnet)

	if err := os.WriteFile(filepath.Join(ovpnServerDir, "server.conf"), []byte(serverConf), 0644); err != nil {
		http.Error(w, "Failed to write config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 4. Enable IP Forwarding (if not already)
	// Managed by SoftRouter core usually, but ensure it

	// 5. Start Service
	exec.Command("systemctl", "enable", ovpnSystemd).Run()
	if err := exec.Command("systemctl", "restart", ovpnSystemd).Run(); err != nil {
		http.Error(w, "Failed to start service: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 6. Firewall Rule (Allow 1194/udp)
	// We'll insert it into nftables.conf if not present, OR assumes user manages via firewall UI.
	// For "Out of box" experience, let's auto-add to firewall via our existing API/logic or just exec nft
	exec.Command("nft", "add", "rule", "inet", "filter", "input", "udp", "dport", fmt.Sprintf("%d", ovpnPort), "accept").Run()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "OpenVPN Server configured and started"})
}

// listOpenVPNClients returns client list
func listOpenVPNClients(w http.ResponseWriter, r *http.Request) {
	clients, err := listOpenVPNClientsInternal()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func listOpenVPNClientsInternal() ([]OpenVPNClientCert, error) {
	indexFile := filepath.Join(ovpnEasyRsaDir, "pki", "index.txt")
	data, err := os.ReadFile(indexFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []OpenVPNClientCert{}, nil
		}
		return nil, err
	}

	var clients []OpenVPNClientCert
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		// Format: V <expiry> <revocation> <serial> <file> <subject>
		// Subject usually: /CN=clientname
		state := parts[0]
		if state != "V" {
			continue
		} // Only show valid for now

		subject := parts[5] // /CN=myclient
		name := strings.TrimPrefix(subject, "/CN=")

		// Parse dates if needed (YYMMDDHHMMSSZ)

		clients = append(clients, OpenVPNClientCert{
			Name:      name,
			State:     state,
			ExpiresAt: parts[1],
		})
	}
	return clients, nil
}

// createOpenVPNClient generates a new client cert and .ovpn file
func createOpenVPNClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Name == "" {
		http.Error(w, "Name required", http.StatusBadRequest)
		return
	}

	// Generate Cert
	cmd := exec.Command(filepath.Join(ovpnEasyRsaDir, "easyrsa"), "build-client-full", req.Name, "nopass")
	cmd.Dir = ovpnEasyRsaDir
	if out, err := cmd.CombinedOutput(); err != nil {
		http.Error(w, "Failed to generate cert: "+string(out), http.StatusInternalServerError)
		return
	}

	// Build .ovpn content
	ca, _ := ioutil.ReadFile(filepath.Join(ovpnServerDir, "ca.crt"))
	ta, _ := ioutil.ReadFile(filepath.Join(ovpnServerDir, "ta.key"))
	cert, _ := ioutil.ReadFile(filepath.Join(ovpnEasyRsaDir, "pki", "issued", req.Name+".crt"))
	key, _ := ioutil.ReadFile(filepath.Join(ovpnEasyRsaDir, "pki", "private", req.Name+".key"))

	// Determine public IP
	publicIP := "YOUR_PUBLIC_IP"
	// Try to get via hostname -I or external service. For now, use Host header or internal logic
	// Using a simpler approach: get WAN IP from command
	outIP, _ := exec.Command("curl", "-s", "ifconfig.me").CombinedOutput()
	if ip := strings.TrimSpace(string(outIP)); ip != "" {
		publicIP = ip
	}

	ovpnConfig := fmt.Sprintf(`client
dev tun
proto udp
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
verb 3
<ca>
%s
</ca>
<cert>
%s
</cert>
<key>
%s
</key>
<tls-crypt>
%s
</tls-crypt>
`, publicIP, ovpnPort, string(ca), string(cert), string(key), string(ta))

	// Store temporarily or just return?
	// The requirement implies we want to download it later.
	// Let's store it in a safe place.
	clientConfDir := "/var/www/softrouter/vpn_configs"
	os.MkdirAll(clientConfDir, 0700) // Restricted
	os.WriteFile(filepath.Join(clientConfDir, req.Name+".ovpn"), []byte(ovpnConfig), 0600)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"config_path": req.Name + ".ovpn",
	})
}

// downloadOpenVPNClient returns the file
func downloadOpenVPNClient(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	path := filepath.Join("/var/www/softrouter/vpn_configs", name+".ovpn")

	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.ovpn\"", name))
	http.ServeFile(w, r, path)
}

// deleteOpenVPNClient revokes the cert
func deleteOpenVPNClient(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// Revoke
	cmd := exec.Command(filepath.Join(ovpnEasyRsaDir, "easyrsa"), "--batch", "revoke", name)
	cmd.Dir = ovpnEasyRsaDir
	cmd.Run()

	// Gen CRL
	cmd2 := exec.Command(filepath.Join(ovpnEasyRsaDir, "easyrsa"), "gen-crl")
	cmd2.Dir = ovpnEasyRsaDir
	cmd2.Run()

	// Copy CRL to server dir
	exec.Command("cp", filepath.Join(ovpnEasyRsaDir, "pki", "crl.pem"), ovpnServerDir+"/").Run()

	// Remove .ovpn
	os.Remove(filepath.Join("/var/www/softrouter/vpn_configs", name+".ovpn"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

func runShellScript(script string) error {
	cmd := exec.Command("bash", "-c", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}
