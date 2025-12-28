# SoftRouter - Web-Based Software Router 🛡️🚀

A modern, high-performance web-based router management interface built with **React** (frontend) and **Go** (backend). Designed to turn any Debian or Ubuntu server into a powerful, security-hardened network appliance.

## 🌟 Key Features

### 🛡️ Integrated Security Stack
- **IDS/IPS (Suricata)**: Real-time network intrusion detection and prevention.
- **Threat Intelligence (CrowdSec)**: Community-driven IP reputation and automated blocking.
- **Firewall (NFTables)**: Full GUI for managing kernel-level network filtering with human-readable parsing.
- **Ad-Blocking**: Native support and management for **AdGuard Home** and **Pi-hole**.

### 🌐 Network & Interfaces
- **VLAN Management**: Create and manage 802.1Q VLANs on physical interfaces.
- **L3 Configuration**: Dynamic IP/CIDR assignment and interface state (Up/Down) control.
- **Smart Labeling**: Organize ports as WAN, LAN, DMZ, or Trunk with custom descriptions.
- **Live Monitoring**: Real-time traffic stats, interface status, and connection tracking.

### ⚙️ System Management
- **Service Governance**: Unified dashboard to Start/Stop/Restart critical services (dnsmasq, WireGuard, OpenVPN, etc.).
- **Credential Security**: SHA-256 password hashing and secure token-based session management.
- **Appliance Deployment**: Single-script installation that converts a fresh OS into a router in minutes.

---

## 🚀 Installation & Deployment

### Master Installation (Recommended)
SoftRouter is optimized for headless servers. Run the comprehensive installer to set up the entire stack:

```bash
git clone -b Dev https://github.com/timmyd2434/SoftwareRouter.git
cd SoftwareRouter
sudo ./master-install.sh
```

**What the installer handles:**
1.  **Core Toolchain**: Installs Go, Node.js, NFTables, and network utilities.
2.  **Security Setup**: configures your admin account and API secrets.
3.  **IDS/IPS Integration**: Optional one-click setup for Suricata & CrowdSec.
4.  **DNS Optimization**: Automatically resolves Port 53 conflicts (disables `systemd-resolved` stub).
5.  **Production Build**: Compiles the Go binary and builds the optimized React frontend.
6.  **Persistence**: Installs a `softrouter.service` for automated startup on boot.

### Accessing the Interface
- **URL**: `http://<YOUR_ROUTER_IP>`
- **Admin Port**: 80
- **Default Credentials**: Set during installation (Step 2/8).

---

## 💡 Professional Tips & Config

### Reclaiming Port 53
If you install **AdGuard Home** or **Pi-hole**, you must free up port 53 which Ubuntu occupies by default. The `master-install.sh` handles this, but you can do it manually:
```bash
# Disable Ubuntu's internal listener
echo -e "[Resolve]\nDNSStubListener=no" | sudo tee /etc/systemd/resolved.conf.d/softrouter.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

### Managing Security
Verify your security stance via CLI:
```bash
# View CrowdSec active bans
sudo cscli decisions list

# Check Suricata logs
tail -f /var/log/suricata/eve.json | jq
```

---

## 📂 Project Structure
- `backend/`: Go API server (Port 80). Handles kernel interactions (IP, NFT, systemd).
- `frontend/`: React + Vite SPA. Modern, glassmorphism-based UI.
- `master-install.sh`: The "glue" script for full appliance deployment.
- `/etc/softrouter/`: Secure persistent storage for credentials and configuration.

## 🛠️ Development
To run in development mode with live-reloading:
1.  **Backend**: `cd backend && sudo go run main.go`
2.  **Frontend**: `cd frontend && npm install && npm run dev -- --host`

---

Built with ❤️ for secure, open-source networking.
