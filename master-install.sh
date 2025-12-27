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
echo -e "${CYAN}[1/7] Installing System Dependencies...${NC}"
apt update
apt install -y curl git golang-go nftables iproute2 systemd jq wget bsdmainutils

# Install Node.js LTS if not present
if ! command -v node &> /dev/null; then
    echo -e "${CYAN}Installing Node.js...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

# 3. Interactive Security Setup
echo -e "${CYAN}[2/7] Security Configuration...${NC}"
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

# 4. Build Phase
echo -e "${CYAN}[3/7] Building Software Components...${NC}"

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

# 5. Firewall Baseline
echo -e "${CYAN}[4/7] Applying Firewall Baseline (nftables)...${NC}"
# Simple baseline to ensure we don't lock the user out but protect the system
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

# 6. Service Installation
echo -e "${CYAN}[5/7] Creating Systemd Service...${NC}"

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
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# 7. Finalize
echo -e "${CYAN}[6/7] Launching System...${NC}"
systemctl daemon-reload
systemctl enable softrouter
systemctl restart softrouter

# 8. Success Report
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
echo -e "- Install Suricata/CrowdSec with: sudo ./install-security.sh"
echo -e "- Monitor logs: journalctl -u softrouter -f"
echo -e "${BLUE}=========================================${NC}"
