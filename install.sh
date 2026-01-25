#!/bin/bash
# SoftRouter - All-Inclusive Master Installation Script
# Targets: Debian/Ubuntu Headless Servers
# Author: Antigravity AI

set -e
VERSION="0.11"


# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}    SoftRouter Master Installer v${VERSION}    ${NC}"
echo -e "${BLUE}    Security Hardened & Automated        ${NC}"
echo -e "${BLUE}=========================================${NC}"

# 1. Check for root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Please run this script with sudo.${NC}"
    exit 1
fi

# ============================================
# PHASE 1: CONFIGURATION COLLECTION
# ============================================
echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}    Configuration Wizard    ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo "Please answer the following questions."
echo "Installation will begin automatically after."
echo ""

# Question 1: Admin Credentials (only if not exists)
if [ ! -f "/etc/softrouter/user_credentials.json" ]; then
    echo -e "${CYAN}[1/5] Administrative Account${NC}"
    read -p "Username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    while true; do
        read -sp "Set Password: " ADMIN_PASS
        echo ""
        read -sp "Confirm Password: " ADMIN_PASS_CONFIRM
        echo ""
        
        if [ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ] && [ ! -z "$ADMIN_PASS" ]; then
            break
        else
            echo -e "${RED}Passwords do not match or are empty. Try again.${NC}"
        fi
    done
else
    echo -e "${CYAN}[1/5] Administrative Account${NC}"
    echo "Existing credentials found. Skipping."
    ADMIN_USER="existing"
    ADMIN_PASS="existing"
fi

# Question 2: Security Stack (IDS/IPS)
echo ""
echo -e "${CYAN}[2/5] Security Stack${NC}"
read -p "Install IDS/IPS (Suricata + CrowdSec)? [y/N]: " INSTALL_SEC
if [[ "$INSTALL_SEC" =~ ^[Yy]$ ]]; then
    read -p "Enter your LAN network in CIDR (e.g., 192.168.1.0/24): " USER_LAN
    while [ -z "$USER_LAN" ]; do
        echo -e "${RED}LAN network is required for IDS/IPS setup.${NC}"
        read -p "Enter your LAN network in CIDR: " USER_LAN
    done
fi

# Question 3: DNS Configuration
echo ""
echo -e "${CYAN}[3/5] DNS Configuration${NC}"
read -p "Free port 53 for custom DNS (AdGuard/Pi-hole)? [y/N]: " FREE_PORT_53

# Question 4: Ad-Blocking DNS
echo ""
echo -e "${CYAN}[4/5] Ad-Blocking DNS${NC}"
read -p "Install AdGuard Home? [y/N]: " INSTALL_AGH

# Question 5: UniFi Controller
echo ""
echo -e "${CYAN}[5/5] UniFi Network Controller${NC}"
read -p "Install UniFi Controller? [y/N]: " INSTALL_UNIFI

# Configuration Summary
echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}    Configuration Summary    ${NC}"
echo -e "${BLUE}=========================================${NC}"
if [ "$ADMIN_USER" != "existing" ]; then
    echo "Admin Username: $ADMIN_USER"
else
    echo "Admin Credentials: Using existing"
fi
echo "IDS/IPS Stack: ${INSTALL_SEC:-N}"
if [[ "$INSTALL_SEC" =~ ^[Yy]$ ]]; then
    echo "  └─ LAN Network: $USER_LAN"
fi
echo "Free Port 53: ${FREE_PORT_53:-N}"
echo "AdGuard Home: ${INSTALL_AGH:-N}"
echo "UniFi Controller: ${INSTALL_UNIFI:-N}"
echo ""
read -p "Proceed with installation? [Y/n]: " CONFIRM
if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
    echo -e "${YELLOW}Installation cancelled by user.${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  Starting Unattended Installation  ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo "You may now leave. Installation will complete automatically."
echo "This may take 10-15 minutes depending on your hardware."
sleep 3

# ============================================
# PHASE 2: UNATTENDED INSTALLATION
# ============================================

# 2. System Dependencies
echo ""
echo -e "${CYAN}[1/10] Installing System Dependencies...${NC}"
apt update
apt install -y curl git golang-go nftables iproute2 systemd jq wget bsdmainutils wireguard openvpn easy-rsa qrencode unbound dnsmasq net-tools iptables ca-certificates gnupg lsb-release

# Install Node.js LTS if not present
if ! command -v node &> /dev/null; then
    echo -e "${CYAN}Installing Node.js...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

# 3. Security Setup (Non-Interactive)
echo -e "${CYAN}[2/10] Security Configuration...${NC}"
mkdir -p /etc/softrouter
chmod 700 /etc/softrouter

if [ ! -f "/etc/softrouter/user_credentials.json" ]; then
    HASHED_PASS=$(echo -n "$ADMIN_PASS" | sha256sum | awk '{print $1}')
    echo "{\"username\":\"$ADMIN_USER\",\"password\":\"$HASHED_PASS\"}" > /etc/softrouter/user_credentials.json
    echo -e "${GREEN}Credentials stored securely.${NC}"
fi

# Generate Secret Key if missing
if [ ! -f "/etc/softrouter/token_secret.key" ]; then
    echo -e "${CYAN}Generating unique API secret key...${NC}"
    head -c 32 /dev/urandom | base64 > /etc/softrouter/token_secret.key
    chmod 600 /etc/softrouter/token_secret.key
fi

# 4. IDS/IPS Stack (Conditional)
echo -e "${CYAN}[3/10] Integrated Security Stack...${NC}"
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
    
    # Apply configurations using pre-collected USER_LAN
    sed -i "s|HOME_NET:.*|HOME_NET: \"[$USER_LAN]\"|" /etc/suricata/suricata.yaml
    sed -i 's|EXTERNAL_NET:.*|EXTERNAL_NET: "!$HOME_NET"|' /etc/suricata/suricata.yaml
    sed -i "s/interface: eth0/interface: $PRIMARY_IFACE/g" /etc/suricata/suricata.yaml
    
    # Enable eve-log
    sed -i '/- eve-log:/,/enabled:/ { /enabled:/d }' /etc/suricata/suricata.yaml
    sed -i 's/- eve-log:/- eve-log:\n      enabled: yes/' /etc/suricata/suricata.yaml
    
    echo -e "Updating IDS rules..."
    suricata-update || true
    
    # Install CrowdSec
    echo -e "Installing CrowdSec..."
    
    # Check Debian version - skip CrowdSec repo on Trixie (uses Debian packages instead)
    DEBIAN_VERSION=$(cat /etc/debian_version 2>/dev/null || echo "")
    if [[ "$DEBIAN_VERSION" =~ ^13 ]] || grep -q "trixie" /etc/os-release 2>/dev/null; then
        echo -e "${YELLOW}Debian Trixie detected. Using Debian's CrowdSec packages...${NC}"
        # Trixie has CrowdSec in main repos, no need for packagecloud
    else
        # Add CrowdSec repository for stable Debian versions
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    fi
    
    apt install -y crowdsec crowdsec-firewall-bouncer
    
    # Install standard collections
    echo -e "Updating CrowdSec hub..."
    cscli hub update
    echo -e "Installing CrowdSec collections..."
    cscli collections install crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/iptables crowdsecurity/suricata --force
    
    # Start security services
    systemctl enable suricata crowdsec crowdsec-firewall-bouncer
    systemctl restart suricata crowdsec crowdsec-firewall-bouncer
    echo -e "${GREEN}IDS/IPS Stack successfully integrated.${NC}"
else
    echo -e "Skipping IDS/IPS installation (user opted out)."
fi

# 5. DNS Optimization (Conditional)
echo -e "${CYAN}[4/10] DNS Optimization...${NC}"
if [[ "$FREE_PORT_53" =~ ^[Yy]$ ]]; then
    # Check if systemd-resolved is installed
    if systemctl list-unit-files | grep -q systemd-resolved.service; then
        echo -e "Configuring systemd-resolved..."
        mkdir -p /etc/systemd/resolved.conf.d
        echo -e "[Resolve]\nDNSStubListener=no" > /etc/systemd/resolved.conf.d/softrouter.conf
        if [ -L /etc/resolv.conf ]; then
            ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
        fi
        systemctl restart systemd-resolved
        echo -e "${GREEN}Port 53 is now free for custom DNS servers.${NC}"
    else
        echo -e "${YELLOW}systemd-resolved not found. Port 53 should already be free.${NC}"
    fi
else
    echo -e "Keeping default DNS configuration (user opted out)."
fi

# 6. Optional Ad-Blocker (Conditional)
echo -e "${CYAN}[5/10] Ad-Blocking DNS...${NC}"
if [[ "$INSTALL_AGH" =~ ^[Yy]$ ]]; then
    # FIRST: Stop dnsmasq and configure it for DHCP-only mode (before AdGuard takes port 53)
    echo -e "${CYAN}Configuring dnsmasq for DHCP-only mode (AdGuard will handle DNS)...${NC}"
    systemctl stop dnsmasq 2>/dev/null || true
    
    cat > /etc/dnsmasq.d/adguard-compat.conf <<'EOF'
# Disable DNS service on port 53 (AdGuard Home will handle DNS)
port=0

# DHCP Configuration - Adjust these values for your network
# Example DHCP range - CHANGE THIS to match your network!
# dhcp-range=192.168.1.50,192.168.1.150,12h

# Tell DHCP clients to use AdGuard Home for DNS
# dhcp-option=6,192.168.1.1  # CHANGE 192.168.1.1 to your AdGuard IP

# Other useful DHCP options
dhcp-authoritative
EOF
    
    # SECOND: Install AdGuard Home (it will now get port 53)
    echo -e "Installing AdGuard Home..."
    curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
    echo -e "${GREEN}AdGuard Home installed. Complete setup at http://$(hostname -I | awk '{print $1}'):3000${NC}"
    
    # THIRD: Start dnsmasq in DHCP-only mode
    echo -e "${CYAN}Starting dnsmasq in DHCP-only mode...${NC}"
    systemctl restart dnsmasq 2>/dev/null || true
    echo -e "${YELLOW}NOTE: dnsmasq configured for DHCP-only. Edit /etc/dnsmasq.d/adguard-compat.conf to set your DHCP range.${NC}"
else
    echo -e "Skipping AdGuard Home installation (user opted out)."
fi

# 7. Optional UniFi Controller (Conditional)
echo -e "${CYAN}[6/10] UniFi Network Server...${NC}"
if [[ "$INSTALL_UNIFI" =~ ^[Yy]$ ]]; then
    echo -e "Installing UniFi Controller dependencies..."
    
    # Detect available Java version based on Debian version
    # Trixie (testing) has Java 21, Bookworm (stable) has Java 17
    if grep -q "trixie" /etc/os-release 2>/dev/null || [[ "$(cat /etc/debian_version 2>/dev/null)" =~ ^13 ]]; then
        echo -e "${YELLOW}Debian Trixie detected. Using OpenJDK 21...${NC}"
        apt install -y openjdk-21-jre-headless libcap2 gnupg
    else
        apt install -y openjdk-17-jre-headless libcap2 gnupg
    fi

    # Hardware Compatibility Check (AVX)
    HAS_AVX=$(grep -o 'avx' /proc/cpuinfo | head -n1)
    
    echo -e "Adding UniFi Repository..."
    curl -s https://dl.ui.com/unifi/unifi-repo.gpg | tee /usr/share/keyrings/ubiquiti-archive-keyring.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/ubiquiti-archive-keyring.gpg] https://www.ui.com/downloads/unifi/debian stable ubiquiti" | tee /etc/apt/sources.list.d/100-ubnt-unifi.list

    if [[ -z "$HAS_AVX" ]]; then
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}ERROR: AVX CPU instructions not detected${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}UniFi Network Application 8.x requires MongoDB 5.0 or higher.${NC}"
        echo -e "${YELLOW}MongoDB 5.0+ requires AVX CPU instruction set support.${NC}"
        echo -e "${YELLOW}MongoDB 4.4 (last non-AVX version) reached EOL in February 2024.${NC}"
        echo -e "${YELLOW}MongoDB 4.4 repositories have been removed and are no longer available.${NC}"
        echo ""
        echo -e "${CYAN}Skipping UniFi installation on this hardware.${NC}"
        echo ""
        echo -e "${BLUE}Recommendations:${NC}"
        echo -e "  • Use a CPU with AVX support (Intel Sandy Bridge/AMD Bulldozer or newer)"
        echo -e "  • Install UniFi on separate hardware with AVX support"
        echo -e "  • Use UniFi Cloud Key, Dream Machine, or Dream Router instead"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    else
        echo -e "AVX Detected. Installing modern MongoDB 8.0..."
        
        # Add MongoDB GPG key
        curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-8.0.gpg --yes
        
        # Use Debian repository (not Ubuntu)
        echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" | tee /etc/apt/sources.list.d/mongodb-org-8.0.list
        
        apt update
        apt install -y mongodb-org
        
        # Configure MongoDB for UniFi
        echo -e "Configuring MongoDB..."
        cat > /etc/mongod.conf <<'MONGO_EOF'
# mongod.conf
storage:
  dbPath: /var/lib/mongodb
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 127.0.0.1
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
MONGO_EOF
        
        # Configure UniFi service dependencies and timeouts
        mkdir -p /etc/systemd/system/unifi.service.d
        cat > /etc/systemd/system/unifi.service.d/override.conf <<'UNIFI_OVERRIDE'
[Unit]
After=mongod.service
Requires=mongod.service

[Service]
TimeoutStartSec=600
UNIFI_OVERRIDE
        
        systemctl daemon-reload

        # Start and enable MongoDB before UniFi
        echo -e "Starting MongoDB service..."
        systemctl enable mongod
        systemctl start mongod
        
        # Wait for MongoDB to be ready with health check
        echo -e "Waiting for MongoDB to initialize..."
        for i in {1..30}; do
            if mongosh --eval "db.adminCommand('ping')" &>/dev/null 2>&1 || mongo --eval "db.adminCommand('ping')" &>/dev/null 2>&1; then
                echo -e "${GREEN}MongoDB is ready!${NC}"
                break
            fi
            echo -e "Waiting for MongoDB... ($i/30)"
            sleep 2
        done

        # Configure UniFi to use external MongoDB and custom ports
        mkdir -p /usr/lib/unifi/data
        echo -e "Configuring UniFi to use external MongoDB..."
        cat > /usr/lib/unifi/data/system.properties <<'UNIFI_PROPS'
# Use external MongoDB (not embedded)
unifi.db.nojournal=false
db.mongo.local=false
db.mongo.uri=mongodb://127.0.0.1:27017/unifi
statdb.mongo.uri=mongodb://127.0.0.1:27017/unifi_stat
unifi.db.name=unifi

# Custom ports (avoid CrowdSec on 8080)
unifi.http.port=8081
unifi.https.port=8443
UNIFI_PROPS

        # Install libssl1.1 (required by UniFi, not in Debian 13 repos)
        if ! dpkg -l | grep -q 'libssl1.1'; then
            echo -e "Installing libssl1.1 (UniFi dependency)..."
            curl -fsSL "https://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.1_1.1.1w-0+deb11u4_amd64.deb" -o "/tmp/libssl.deb"
            dpkg -i /tmp/libssl.deb
            rm -f /tmp/libssl.deb
            echo -e "${GREEN}libssl1.1 installed.${NC}"
        fi

        # Install UniFi
        echo -e "Installing UniFi Controller..."
        apt install -y unifi
        
        systemctl enable unifi
        systemctl start unifi
        
        echo -e "${GREEN}UniFi Controller installed. Access at https://$(hostname -I | awk '{print $1}'):8443${NC}"
    fi
else
    echo -e "Skipping UniFi Controller installation (user opted out)."
fi

# 8. Build Phase
echo -e "${CYAN}[7/10] Building Software Components...${NC}"

# Free port 80 by disabling conflicting web servers
echo -e "Checking for web server conflicts on port 80..."
if systemctl is-active --quiet apache2 2>/dev/null; then
    echo -e "${YELLOW}Apache2 detected on port 80. Disabling to free port for SoftRouter...${NC}"
    systemctl stop apache2
    systemctl disable apache2
fi
if systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "${YELLOW}Nginx detected on port 80. Disabling to free port for SoftRouter...${NC}"
    systemctl stop nginx
    systemctl disable nginx
fi

# Stop existing service
systemctl stop softrouter 2>/dev/null || true

# Backend
echo -e "Compiling Go Backend..."
cd backend
go build -o softrouter-backend main.go vpn_client_utils.go openvpn_server_utils.go
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
echo -e "${CYAN}[8/10] Applying Firewall Baseline (nftables)...${NC}"
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
echo -e "${CYAN}[9/10] Creating Systemd Service...${NC}"

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

# 11. Finalize
echo -e "${CYAN}[10/10] Launching System...${NC}"
fuser -k 80/tcp 8080/tcp 2>/dev/null || true
systemctl daemon-reload
systemctl enable softrouter
systemctl restart softrouter

# 12. Success Report
CORE_IP=$(hostname -I | awk '{print $1}')
echo ""
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
    echo -e "- AdGuard Setup: http://${CORE_IP}:3000"
fi
if [[ "$INSTALL_UNIFI" =~ ^[Yy]$ ]]; then
    echo -e "- UniFi Controller: https://${CORE_IP}:8443"
fi
echo -e "- Monitor logs: journalctl -u softrouter -f"
echo -e "${BLUE}=========================================${NC}"
