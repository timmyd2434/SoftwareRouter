#!/bin/bash
# setup-internal-tls.sh
# Automates the setup of self-signed TLS for SoftRouter internal access
# Author: Antigravity AI

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

CONFIG_FILE="/etc/softrouter/config.json"
TLS_DIR="/etc/softrouter/tls"
BACKEND_BIN="/usr/local/bin/softrouter-backend"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Please run this script with sudo.${NC}"
    exit 1
fi

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}    SoftRouter Internal TLS Setup      ${NC}"
echo -e "${BLUE}=======================================${NC}"
echo -e "This script will generate a self-signed certificate and enable TLS."
echo -e "${YELLOW}NOTE: Browsers will warn about the self-signed certificate.${NC}"
echo ""

# 2. Dependencies
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl not found. Installing...${NC}"
    apt update && apt install -y openssl
fi
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq not found. Installing...${NC}"
    apt update && apt install -y jq
fi

# 3. Certificate Details
echo -e "${BLUE}[1/4] Certificate Generation${NC}"
read -p "Enter Domain or IP (default: router.local): " DOMAIN_CN
DOMAIN_CN=${DOMAIN_CN:-router.local}

mkdir -p "$TLS_DIR"
chmod 755 "$TLS_DIR"

if [ -f "$TLS_DIR/cert.pem" ]; then
    echo -e "${YELLOW}Existing certificate found at $TLS_DIR/cert.pem${NC}"
    read -p "Overwrite? [y/N]: " OVERWRITE
    if [[ ! "$OVERWRITE" =~ ^[Yy]$ ]]; then
        echo "Using existing certificate."
    else
        echo "Generating new certificate..."
        openssl req -x509 -newkey rsa:4096 -nodes \
          -keyout "$TLS_DIR/key.pem" \
          -out "$TLS_DIR/cert.pem" \
          -days 3650 \
          -subj "/C=US/ST=Internal/L=Home/O=SoftRouter/CN=$DOMAIN_CN"
    fi
else
    echo "Generating new certificate..."
    openssl req -x509 -newkey rsa:4096 -nodes \
      -keyout "$TLS_DIR/key.pem" \
      -out "$TLS_DIR/cert.pem" \
      -days 3650 \
      -subj "/C=US/ST=Internal/L=Home/O=SoftRouter/CN=$DOMAIN_CN"
fi

# Permissions
chmod 600 "$TLS_DIR/key.pem"
chmod 644 "$TLS_DIR/cert.pem"
echo -e "${GREEN}Certificate generated for $DOMAIN_CN${NC}"

# 4. Configure Backend
echo -e "${BLUE}[2/4] updating Configuration${NC}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Config file not found at $CONFIG_FILE${NC}"
    exit 1
fi

# Backup
cp "$CONFIG_FILE" "${CONFIG_FILE}.bak_tls_$(date +%s)"

# Update JSON
# We use a temporary file to ensure atomic write
tmp=$(mktemp)
jq '.tls.enabled = true | .tls.cert_file = "/etc/softrouter/tls/cert.pem" | .tls.key_file = "/etc/softrouter/tls/key.pem" | .tls.port = ":443"' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"

# Fix permissions if jq messed them up (jq usually preserves likely permissions but just in case)
chmod 640 "$CONFIG_FILE"

echo -e "${GREEN}Configuration updated.${NC}"

# 5. Firewall
echo -e "${BLUE}[3/4] Updating Firewall${NC}"
if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
elif command -v ufw &> /dev/null; then
    ufw allow 443/tcp
elif command -v nft &> /dev/null; then
    # Simple check if rule exists, otherwise add it
    if ! nft list ruleset | grep -q "dport 443"; then
        echo "Adding nftables rule for port 443..."
        nft add rule inet filter input tcp dport 443 accept comment "\"Allow HTTPS\"" || echo -e "${YELLOW}Failed to add nftables rule automatically. Please allow port 443 manually.${NC}"
        # Persist if possible
        if [ -f /etc/nftables.conf ]; then
             echo "Info: Please manually ensure port 443 is added to /etc/nftables.conf"
        fi
    fi
else
    echo -e "${YELLOW}No supported firewall manager found. Please manually open TCP 443.${NC}"
fi

# 6. Restart Service
echo -e "${BLUE}[4/4] Restarting SoftRouter${NC}"
systemctl restart softrouter

# Check status
if systemctl is-active --quiet softrouter; then
    echo -e "${GREEN}Success! SoftRouter is running.${NC}"
    
    IP_ADDR=$(hostname -I | awk '{print $1}')
    echo -e "${BLUE}=======================================${NC}"
    echo -e "Access your router securely at:"
    echo -e "  https://$IP_ADDR"
    echo -e "  https://$DOMAIN_CN (if DNS is configured)"
    echo -e ""
    echo -e "${YELLOW}Remember to accept the self-signed certificate warning.${NC}"
    echo -e "${BLUE}=======================================${NC}"
else
    echo -e "${RED}Error: SoftRouter failed to start.${NC}"
    echo "Check logs with: journalctl -u softrouter -n 50"
fi
