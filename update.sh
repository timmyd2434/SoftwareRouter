#!/bin/bash
set -e  # Exit on error

echo "========================================="
echo "  SoftRouter Update Script"
echo "========================================="
echo ""

# Parse arguments
FORCE_UPDATE=false
if [ "$1" == "--force" ] || [ "$1" == "-f" ]; then
    FORCE_UPDATE=true
    echo "ℹ️  Force mode enabled - will rebuild even if up to date"
    echo ""
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    echo ""
    echo "Usage: sudo ./update.sh [--force]"
    echo "  --force, -f    Force rebuild even if already up to date"
    exit 1
fi

# Store current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Backup configuration files
echo "📦 Backing up configuration files..."
BACKUP_DIR="/tmp/softrouter-backup-$(date +%s)"
mkdir -p "$BACKUP_DIR"

# Backup config.json if it exists
if [ -f "config.json" ]; then
    cp config.json "$BACKUP_DIR/"
    echo "  ✓ Backed up config.json"
fi

# Backup interface metadata if it exists
if [ -f "interface_metadata.json" ]; then
    cp interface_metadata.json "$BACKUP_DIR/"
    echo "  ✓ Backed up interface_metadata.json"
fi

# Backup port forwarding rules if they exist
if [ -f "port_forwarding_rules.json" ]; then
    cp port_forwarding_rules.json "$BACKUP_DIR/"
    echo "  ✓ Backed up port_forwarding_rules.json"
fi

# Backup PBR rules if they exist
if [ -f "pbr_rules.json" ]; then
    cp pbr_rules.json "$BACKUP_DIR/"
    echo "  ✓ Backed up pbr_rules.json"
fi

# Backup DHCP config if it exists
if [ -f "dhcp_config.json" ]; then
    cp dhcp_config.json "$BACKUP_DIR/"
    echo "  ✓ Backed up dhcp_config.json"
fi

echo ""

# Pull latest changes from git
echo "🔄 Pulling latest changes from Git..."
# Run git commands as the calling user (not root) to support SSH key passphrases
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" git fetch origin
    CURRENT_BRANCH=$(sudo -u "$SUDO_USER" git branch --show-current)
else
    git fetch origin
    CURRENT_BRANCH=$(git branch --show-current)
fi
echo "  Current branch: $CURRENT_BRANCH"

# Check if there are updates
if git diff --quiet HEAD origin/$CURRENT_BRANCH; then
    if [ "$FORCE_UPDATE" = false ]; then
        echo "  ℹ️  Already up to date!"
        echo ""
        echo "Cleaning up backup..."
        rm -rf "$BACKUP_DIR"
        echo ""
        echo "💡 Tip: Use 'sudo ./update.sh --force' to rebuild anyway"
        exit 0
    else
        echo "  ℹ️  Already up to date, but continuing due to --force flag"
    fi
fi

if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" git pull origin $CURRENT_BRANCH
else
    git pull origin $CURRENT_BRANCH
fi
echo "  ✓ Updated to latest version"
echo ""

# Stop the backend service
echo "🛑 Stopping SoftRouter backend service..."
if systemctl is-active --quiet softrouter; then
    systemctl stop softrouter
    echo "  ✓ Service stopped"
else
    echo "  ℹ️  Service not running"
fi

# Kill any running softrouter-backend processes (in case it's running outside systemd)
if pgrep -f softrouter-backend > /dev/null; then
    echo "  🔪 Killing running backend processes..."
    pkill -f softrouter-backend
    sleep 2  # Give processes time to terminate
    echo "  ✓ Processes terminated"
fi
echo ""

# Build backend
echo "🔨 Building backend..."
cd backend
go build -o softrouter-backend
if [ $? -eq 0 ]; then
    echo "  ✓ Backend built successfully"
    # Install the new binary
    cp softrouter-backend /usr/local/bin/
    chmod +x /usr/local/bin/softrouter-backend
    echo "  ✓ Backend installed to /usr/local/bin/"
else
    echo "  ❌ Backend build failed!"
    echo "  Restoring configuration from backup..."
    cp -r $BACKUP_DIR/* "$SCRIPT_DIR/"
    exit 1
fi
cd ..

# Create dnsmasq base configuration if it doesn't exist
echo "📡 Configuring dnsmasq..."
if [ ! -f /etc/dnsmasq.d/softrouter-base.conf ]; then
    cat > /tmp/softrouter-dnsmasq-base.conf <<'DNSMASQ_EOF'
# SoftwareRouter dnsmasq base configuration
# This file provides minimal configuration for dnsmasq to start

# Don't read /etc/resolv.conf - we'll configure DNS servers explicitly
no-resolv

# Don't read /etc/hosts
no-hosts

# Listen only on specified interfaces (none by default, configured per-DHCP network)
# bind-interfaces will be added per-network config

# Log DHCP transactions for debugging
log-dhcp

# Enable authoritative mode for faster DHCP
dhcp-authoritative

# Cache size
cache-size=1000
DNSMASQ_EOF
    mv /tmp/softrouter-dnsmasq-base.conf /etc/dnsmasq.d/softrouter-base.conf
    echo "  ✓ Created /etc/dnsmasq.d/softrouter-base.conf"
else
    echo "  ✓ dnsmasq base config already exists"
fi
echo ""

# Build frontend
echo "🎨 Building frontend..."
cd frontend

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "  📦 Installing npm dependencies..."
    npm install
fi

npm run build
if [ $? -eq 0 ]; then
    echo "  ✓ Frontend built successfully"
    
    # Copy to web directory
    echo "  📋 Deploying frontend to web directory..."
    mkdir -p /var/www/softrouter/html
    cp -r dist/* /var/www/softrouter/html/
    echo "  ✓ Frontend deployed"
else
    echo "  ❌ Frontend build failed!"
    cd ..
    echo "  Restoring configuration from backup..."
    cp -r $BACKUP_DIR/* "$SCRIPT_DIR/"
    exit 1
fi
cd ..
echo ""

# Restore configuration files
echo "📥 Restoring configuration files..."
if [ -d "$BACKUP_DIR" ]; then
    for file in "$BACKUP_DIR"/*; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            cp "$file" "./$filename"
            echo "  ✓ Restored $filename"
        fi
    done
fi
echo ""

# Clean up backup
echo "🧹 Cleaning up backup..."
rm -rf "$BACKUP_DIR"
echo "  ✓ Backup cleaned"
echo ""

# SECURITY CHECK: Verify token_secret.key exists (required as of Tier 3 fixes)
echo "🔐 Security pre-flight checks..."
if [ ! -f "/etc/softrouter/token_secret.key" ]; then
    echo "  ⚠️  WARNING: token_secret.key not found!"
    echo ""
    echo "  The backend now requires /etc/softrouter/token_secret.key for security."
    echo "  Generating a new secret key..."
    mkdir -p /etc/softrouter
    head -c 32 /dev/urandom | base64 > /etc/softrouter/token_secret.key
    chmod 600 /etc/softrouter/token_secret.key
    echo "  ✓ New token_secret.key generated"
    echo ""
    echo "  ⚠️  IMPORTANT: All existing sessions will be invalidated."
    echo "     You will need to log in again after the update."
else
    echo "  ✓ token_secret.key exists"
fi
echo ""

# Restart the backend service
echo "🚀 Starting SoftRouter backend service..."
if systemctl list-unit-files | grep -q "^softrouter.service"; then
    systemctl start softrouter
    if systemctl is-active --quiet softrouter; then
        echo "  ✓ Service started successfully"
    else
        echo "  ❌ Failed to start service!"
        echo "  Check logs: journalctl -u softrouter -n 50"
        exit 1
    fi
else
    echo "  ℹ️  systemd service not found - start manually if needed"
    echo "  Run: sudo /usr/local/bin/softrouter-backend &"
fi
echo ""

# Display service status
echo "========================================="
echo "  Update Complete!"
echo "========================================="
echo ""
if systemctl list-unit-files | grep -q "^softrouter.service"; then
    echo "Service Status:"
    systemctl status softrouter --no-pager -l | head -n 10
else
    echo "Service not configured. Running in manual mode."
fi
echo ""
echo "✅ SoftRouter has been updated successfully!"
echo ""
echo "Your firewall rules and configuration have been preserved."
echo "The backend service is now running with the latest code."
echo ""
