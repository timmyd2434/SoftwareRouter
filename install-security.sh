#!/bin/bash
# Suricata + CrowdSec Installation Script for SoftRouter
# Run with sudo

set -e

echo "==================================="
echo "SoftRouter Security Stack Installer"
echo "Installing: Suricata + CrowdSec"
echo "==================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo)"
    exit 1
fi

# Update package list
echo "[1/8] Updating package list..."
apt update

# Install Suricata
echo "[2/8] Installing Suricata..."
apt install -y suricata

# Install jq for JSON parsing
apt install -y jq

# Configure Suricata
echo "[3/8] Configuring Suricata..."

# Backup original config
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

# Set home network (adjust as needed)
read -p "Enter your LAN network in CIDR (e.g., 192.168.1.0/24): " HOME_NET
sed -i "s|HOME_NET:.*|HOME_NET: \"[$HOME_NET]\"|" /etc/suricata/suricata.yaml

# Set external network
sed -i "s|EXTERNAL_NET:.*|EXTERNAL_NET: \"!\\$HOME_NET\"|" /etc/suricata/suricata.yaml

# Enable eve.json logging (JSON format)
sed -i 's/eve-log:/eve-log:\n    enabled: yes/' /etc/suricata/suricata.yaml

# Update Suricata rules
echo "[4/8] Updating Suricata rules (ET Open)..."
suricata-update

# Install CrowdSec
echo "[5/8] Installing CrowdSec..."
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install -y crowdsec

# Install CrowdSec bouncer for nftables
echo "[6/8] Installing CrowdSec nftables bouncer..."
apt install -y crowdsec-firewall-bouncer-nftables

# Install CrowdSec collections
echo "[7/8] Installing CrowdSec collections..."
cscli collections install crowdsecurity/linux
cscli collections install crowdsecurity/sshd
cscli collections install crowdsecurity/http-cve
cscli collections install crowdsecurity/iptables
cscli collections install crowdsecurity/suricata

# Restart services
echo "[8/8] Starting services..."
systemctl enable suricata
systemctl restart suricata
systemctl enable crowdsec
systemctl restart crowdsec
systemctl restart crowdsec-firewall-bouncer

echo ""
echo "==================================="
echo "✅ Installation Complete!"
echo "==================================="
echo ""
echo "Services installed:"
echo "  • Suricata IDS/IPS - Monitoring network traffic"
echo "  • CrowdSec - Behavioral analysis"
echo "  • CrowdSec nftables bouncer - Automatic blocking"
echo ""
echo "Next steps:"
echo "  1. Check Suricata: sudo systemctl status suricata"
echo "  2. Check CrowdSec: sudo systemctl status crowdsec"
echo "  3. View Suricata logs: sudo tail -f /var/log/suricata/eve.json"
echo "  4. View CrowdSec decisions: sudo cscli decisions list"
echo ""
echo "Configuration files:"
echo "  • Suricata: /etc/suricata/suricata.yaml"
echo "  • CrowdSec: /etc/crowdsec/config.yaml"
echo ""
echo "To enable IPS mode (inline blocking):"
echo "  Edit /etc/suricata/suricata.yaml and set 'af-packet' mode"
echo "  Then restart: sudo systemctl restart suricata"
echo ""
