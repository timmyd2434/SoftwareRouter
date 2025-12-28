#!/bin/bash
# SoftRouter - All-Inclusive Master Installation Script
# Targets: Debian/Ubuntu Headless Servers
# Author: Antigravity AI

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}    SoftRouter Master Installation       ${NC}"
echo -e "${BLUE}    Security Hardened & Automated        ${NC}"
echo -e "${BLUE}=========================================${NC}"

# 1. Check for root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Please run this script with sudo.${NC}"
    exit 1
fi

# 2. System Dependencies
echo -e "${CYAN}[1/8] Installing System Dependencies...${NC}"
apt update
apt install -y curl git golang-go nftables iproute2 systemd jq wget bsdmainutils

# Install Node.js LTS if not present
if ! command -v node &> /dev/null; then
    echo -e "${CYAN}Installing Node.js...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

# 3. Interactive Security Setup
echo -e "${CYAN}[2/8] Security Configuration...${NC}"
mkdir -p /etc/softrouter
chmod 700 /etc/softrouter

if [ ! -f "/etc/softrouter/user_credentials.json" ]; then
    echo -e "${BLUE}Define primary administrator account:${NC}"
    read -p "Username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    while true; do
        read -sp "Set Password: " ADMIN_PASS
        echo ""
        read -sp "Confirm Password: " ADMIN_PASS_CONFIRM
        echo ""
        
        if [ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ] && [ ! -z "$ADMIN_PASS" ]; then
            HASHED_PASS=$(echo -n "$ADMIN_PASS" | sha256sum | awk '{print $1}')
            echo "{\"username\":\"$ADMIN_USER\",\"password\":\"$HASHED_PASS\"}" > /etc/softrouter/user_credentials.json
            echo -e "${GREEN}Credentials stored securely.${NC}"
            break
        else
            echo -e "${RED}Passwords do not match or are empty. Try again.${NC}"
        fi
    done
fi

# Generate Secret Key if missing
if [ ! -f "/etc/softrouter/token_secret.key" ]; then
    echo -e "${CYAN}Generating unique API secret key...${NC}"
    head -c 32 /dev/urandom | base64 > /etc/softrouter/token_secret.key
    chmod 600 /etc/softrouter/token_secret.key
fi

# 4. IDS/IPS Stack (Suricata + CrowdSec)
echo -e "${CYAN}[3/8] Integrated Security Stack (Optional)${NC}"
read -p "Would you like to install the IDS/IPS stack (Suricata + CrowdSec)? [y/N]: " INSTALL_SEC
if [[ "$INSTALL_SEC" =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}Installing Suricata & CrowdSec...${NC}"
    apt install -y suricata
    
    # Configure Suricata
    echo -e "Configuring Suricata..."
    cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup
    
    # Detect primary interface
    PRIMARY_IFACE=$(ip -4 route show default | awk '{print $5}' | head -n1)
    PRIMARY_IFACE=${PRIMARY_IFACE:-eth0}
    echo -e "Detected primary interface: ${CYAN}$PRIMARY_IFACE${NC}"
    
    read -p "Enter your LAN network in CIDR (e.g., 192.168.1.0/24): " USER_LAN
    
    # Apply configurations
    sed -i "s|HOME_NET:.*|HOME_NET: \"[$USER_LAN]\"|" /etc/suricata/suricata.yaml
    sed -i 's|EXTERNAL_NET:.*|EXTERNAL_NET: "!$HOME_NET"|' /etc/suricata/suricata.yaml
    sed -i "s/interface: eth0/interface: $PRIMARY_IFACE/g" /etc/suricata/suricata.yaml
    
    # Enable eve-log (robust approach)
    # First ensure we don't have multiple 'enabled:' lines right after eve-log
    sed -i '/- eve-log:/,/enabled:/ { /enabled:/d }' /etc/suricata/suricata.yaml
    sed -i 's/- eve-log:/- eve-log:\n      enabled: yes/' /etc/suricata/suricata.yaml
    
    echo -e "Updating IDS rules..."
    suricata-update || true
    
    # Install CrowdSec
    echo -e "Installing CrowdSec..."
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt install -y crowdsec crowdsec-firewall-bouncer-nftables
    
    # Install standard collections
    cscli collections install crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/iptables crowdsecurity/suricata
    
    # Start security services
    systemctl enable suricata crowdsec crowdsec-firewall-bouncer
    systemctl restart suricata crowdsec crowdsec-firewall-bouncer
    echo -e "${GREEN}IDS/IPS Stack successfully integrated.${NC}"
else
    echo -e "Skipping IDS/IPS installation."
fi

# 5. DNS Optimization (Port 53 Cleanup)
echo -e "${CYAN}[4/8] DNS Optimization...${NC}"
read -p "Disable systemd-resolved stub listener to free up port 53? (Required for AdGuard/Pi-hole) [y/N]: " FREE_PORT_53
if [[ "$FREE_PORT_53" =~ ^[Yy]$ ]]; then
    echo -e "Configuring systemd-resolved..."
    mkdir -p /etc/systemd/resolved.conf.d
    echo -e "[Resolve]\nDNSStubListener=no" > /etc/systemd/resolved.conf.d/softrouter.conf
    if [ -L /etc/resolv.conf ]; then
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    fi
    systemctl restart systemd-resolved
    echo -e "${GREEN}Port 53 is now free for custom DNS servers.${NC}"
fi

# 6. Optional Ad-Blocker (AdGuard Home)
echo -e "${CYAN}[5/8] Ad-Blocking DNS (Optional)${NC}"
read -p "Would you like to install AdGuard Home now? [y/N]: " INSTALL_AGH
if [[ "$INSTALL_AGH" =~ ^[Yy]$ ]]; then
    echo -e "Installing AdGuard Home..."
    curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
    # The setup wizard will be on port 3000 by default
    echo -e "${GREEN}AdGuard Home installed. Complete setup at http://$(hostname -I | awk '{print $1}'):3000${NC}"
fi

# 7. Optional UniFi Controller
echo -e "${CYAN}[6/9] UniFi Network Server (Optional)${NC}"
read -p "Would you like to install the UniFi Controller for your U6 AP? [y/N]: " INSTALL_UNIFI
if [[ "$INSTALL_UNIFI" =~ ^[Yy]$ ]]; then
    echo -e "Installing UniFi Controller dependencies..."
    apt install -y openjdk-17-jre-headless libcap2
    
    echo -e "Adding UniFi Repository..."
    curl -s https://dl.ui.com/unifi/unifi-repo.gpg | tee /usr/share/keyrings/ubiquiti-archive-keyring.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/ubiquiti-archive-keyring.gpg] https://www.ui.com/downloads/unifi/debian stable ubiquiti" | tee /etc/apt/sources.list.d/100-ubnt-unifi.list
    
    echo -e "Installing MongoDB (Required for UniFi)..."
    # MongoDB doesn't have a 'noble' repo yet. Jammy repo is fully compatible with 24.04.
    apt install -y gnupg
    curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg --yes
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list
    
    apt update
    apt install -y mongodb-org
    
    echo -e "Installing UniFi Controller..."
    apt install -y unifi
    systemctl enable unifi
    systemctl start unifi
    echo -e "${GREEN}UniFi Controller installed. Access at https://$(hostname -I | awk '{print $1}'):8443${NC}"
fi

# 8. Build Phase
echo -e "${CYAN}[7/9] Building Software Components...${NC}"

# Stop existing service if running to avoid 'Text file busy' during binary overwrite
systemctl stop softrouter 2>/dev/null || true

# Backend
echo -e "Compiling Go Backend..."
cd backend
go build -o softrouter-backend main.go
cp softrouter-backend /usr/local/bin/softrouter-backend
chmod +x /usr/local/bin/softrouter-backend
cd ..

# Frontend
echo -e "Building React Production Frontend..."
cd frontend
npm install
npm run build
mkdir -p /var/www/softrouter/html
cp -r dist/* /var/www/softrouter/html/
cd ..

# 9. Firewall Baseline
echo -e "${CYAN}[8/9] Applying Firewall Baseline (nftables)...${NC}"
cat <<EOF > /etc/nftables.conf
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "lo" accept
        ct state established,related accept
        tcp dport 80 accept
        tcp dport 22 accept
    }
}
EOF
systemctl enable nftables
systemctl restart nftables

# 10. Service Installation
echo -e "${CYAN}[9/9] Creating Systemd Service...${NC}"

cat <<EOF > /etc/systemd/system/softrouter.service
[Unit]
Description=SoftRouter Governance Backend & UI
After=network.target

[Service]
ExecStart=/usr/local/bin/softrouter-backend
WorkingDirectory=/usr/local/bin
User=root
Restart=always
RestartSec=5
# Security hardening for service
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# 10. Finalize
echo -e "${CYAN}[7/8] Launching System...${NC}"
# Kill existing processes on target ports to avoid 'address already in use'
fuser -k 80/tcp 8080/tcp 2>/dev/null || true
systemctl daemon-reload
systemctl enable softrouter
systemctl restart softrouter

# 9. Success Report
CORE_IP=$(hostname -I | awk '{print $1}')
echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}✅ SoftRouter is now FULLY INSTALLED!${NC}"
echo -e "${BLUE}=========================================${NC}"
echo -e "Access the Dashboard at: ${CYAN}http://${CORE_IP}${NC}"
echo -e "Administrative Port: 80"
echo -e "Service Status: $(systemctl is-active softrouter)"
echo -e "-----------------------------------------"
echo -e "Tips:"
echo -e "- Configure VLANs and Firewalls via the UI."
if [[ "$INSTALL_SEC" =~ ^[Yy]$ ]]; then
    echo -e "- Monitor Security: sudo cscli decisions list"
fi
if [[ "$INSTALL_AGH" =~ ^[Yy]$ ]]; then
    echo -e "- AdGuard Setup: http://${CORE_IP}:90"
fi
if [[ "$INSTALL_UNIFI" =~ ^[Yy]$ ]]; then
    echo -e "- UniFi Controller: https://${CORE_IP}:8443"
fi
echo -e "- Monitor logs: journalctl -u softrouter -f"
echo -e "${BLUE}=========================================${NC}"
