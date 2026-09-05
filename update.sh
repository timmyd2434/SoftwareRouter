#!/bin/bash
set -e  # Exit on error

echo "========================================="
echo "  SoftRouter Update Script"
echo "========================================="
echo ""

# Parse arguments
FORCE_UPDATE=false
TARGET_BRANCH=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE_UPDATE=true
            echo "ℹ️  Force mode enabled - will rebuild even if up to date"
            shift
            ;;
        --branch|-b)
            TARGET_BRANCH="$2"
            if [ -z "$TARGET_BRANCH" ]; then
                echo "Error: --branch requires an argument (main or Dev)"
                exit 1
            fi
            echo "ℹ️  Target branch: $TARGET_BRANCH"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: sudo ./update.sh [--branch main|Dev] [--force]"
            exit 1
            ;;
    esac
done
echo ""

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

# Backup configuration files from /etc/softrouter/ (authoritative runtime location)
echo "📦 Backing up configuration files..."
BACKUP_DIR="/tmp/softrouter-backup-$(date +%s)"
mkdir -p "$BACKUP_DIR/etc_softrouter"

# Back up the entire /etc/softrouter/ directory (all runtime configs)
if [ -d "/etc/softrouter" ]; then
    cp -a /etc/softrouter/. "$BACKUP_DIR/etc_softrouter/"
    echo "  ✓ Backed up /etc/softrouter/ ($(ls "$BACKUP_DIR/etc_softrouter" | wc -l) files)"
else
    echo "  ⚠️  /etc/softrouter/ not found – nothing to back up"
fi

echo ""

# Ensure .git object database permissions allow fetching/unpacking
if [ -d ".git" ]; then
    chmod -R u+rw,g+rw .git 2>/dev/null || true
    if [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER" .git 2>/dev/null || true
    fi
fi

# Pull latest changes from git
echo "🔄 Pulling latest changes from Git..."
if [ -n "$SUDO_USER" ]; then
    if ! sudo -u "$SUDO_USER" git -c safe.directory=* fetch origin 2>/dev/null; then
        if ! git -c safe.directory=* fetch origin 2>/dev/null; then
            git -c safe.directory=* fetch https://github.com/timmyd2434/SoftwareRouter.git ${TARGET_BRANCH:-Dev} 2>/dev/null || true
        fi
    fi
    CURRENT_BRANCH=$(sudo -u "$SUDO_USER" git -c safe.directory=* branch --show-current 2>/dev/null || git -c safe.directory=* branch --show-current)
else
    if ! git -c safe.directory=* fetch origin 2>/dev/null; then
        git -c safe.directory=* fetch https://github.com/timmyd2434/SoftwareRouter.git ${TARGET_BRANCH:-Dev} 2>/dev/null || true
    fi
    CURRENT_BRANCH=$(git -c safe.directory=* branch --show-current)
fi
echo "  Current branch: $CURRENT_BRANCH"

# Switch branch if requested
if [ -n "$TARGET_BRANCH" ] && [ "$TARGET_BRANCH" != "$CURRENT_BRANCH" ]; then
    echo "  🔀 Switching from $CURRENT_BRANCH to $TARGET_BRANCH..."
    if [ -n "$SUDO_USER" ]; then
        if ! sudo -u "$SUDO_USER" git -c safe.directory=* checkout "$TARGET_BRANCH" 2>/dev/null; then
            git -c safe.directory=* checkout "$TARGET_BRANCH"
        fi
    else
        git -c safe.directory=* checkout "$TARGET_BRANCH"
    fi
    CURRENT_BRANCH="$TARGET_BRANCH"
    echo "  ✓ Now on branch: $CURRENT_BRANCH"
fi

# Check if there are updates
if git -c safe.directory=* diff --quiet HEAD origin/$CURRENT_BRANCH; then
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
    if ! sudo -u "$SUDO_USER" git -c safe.directory=* pull origin $CURRENT_BRANCH 2>/dev/null; then
        git -c safe.directory=* pull origin $CURRENT_BRANCH
    fi
else
    git -c safe.directory=* pull origin $CURRENT_BRANCH
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

# Ensure WireGuard packages are installed
if ! command -v wg &> /dev/null || ! systemctl list-unit-files | grep -q "^wg-quick@"; then
    echo "📦 Checking WireGuard packages..."
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -y -qq wireguard wireguard-tools || true
        echo "  ✓ WireGuard packages verified"
    fi
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

# Restore configuration files back to /etc/softrouter/
echo "📥 Restoring configuration files..."
if [ -d "$BACKUP_DIR/etc_softrouter" ] && [ -n "$(ls -A "$BACKUP_DIR/etc_softrouter" 2>/dev/null)" ]; then
    mkdir -p /etc/softrouter
    chmod 700 /etc/softrouter
    # Restore all backed-up files, preserving permissions where possible
    cp -a "$BACKUP_DIR/etc_softrouter/." /etc/softrouter/
    # Enforce secure permissions on sensitive files
    find /etc/softrouter -maxdepth 1 -type f \( -name "*.json" -o -name "*.key" -o -name "*.nft" \) -exec chmod 600 {} \;
    echo "  ✓ Restored /etc/softrouter/ ($(ls /etc/softrouter | wc -l) files)"
else
    echo "  ℹ️  No /etc/softrouter/ backup to restore"
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

# FIREWALL CLEANUP: Purge legacy/stale nftables tables before starting the service.
# install.sh used to write a static "table inet filter" to /etc/nftables.conf;
# the backend manages "table inet softrouter" exclusively. Any leftover legacy
# tables at priority 0 can shadow or duplicate the managed ruleset.
echo "🔥 Purging legacy nftables tables..."
nft delete table inet filter 2>/dev/null && echo "  ✓ Removed legacy table inet filter" || echo "  ✓ No legacy table inet filter present"
nft delete table ip filter   2>/dev/null && echo "  ✓ Removed legacy table ip filter"   || true
nft delete table ip6 filter  2>/dev/null && echo "  ✓ Removed legacy table ip6 filter"  || true
echo ""

# Load nf_conntrack and enable byte accounting for device bandwidth monitoring.
# Without nf_conntrack_acct=1 the bytes= fields in /proc/net/nf_conntrack are 0.
echo "📊 Enabling conntrack byte accounting..."
modprobe nf_conntrack 2>/dev/null || true
sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null && echo "  ✓ nf_conntrack_acct enabled" || echo "  ⚠️  nf_conntrack_acct not available (module may not be loaded yet)"
# Persist the setting
if ! grep -q "nf_conntrack_acct" /etc/sysctl.d/99-softrouter.conf 2>/dev/null; then
    echo "net.netfilter.nf_conntrack_acct=1" >> /etc/sysctl.d/99-softrouter.conf 2>/dev/null || true
fi
# Add nf_conntrack to module autoload
if ! grep -q "nf_conntrack" /etc/modules-load.d/softrouter.conf 2>/dev/null; then
    echo "nf_conntrack" >> /etc/modules-load.d/softrouter.conf
fi
echo ""


# Install/Update systemd service
echo "⚙️  Configuring systemd service..."
if [ -f "softrouter.service" ]; then
    cp softrouter.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable softrouter
    echo "  ✓ Installed softrouter.service"
else
    echo "  ⚠️  softrouter.service file not found in repo"
fi
echo ""

# Ensure DHCP and DNS services are enabled and active
echo "📡 Ensuring DHCP (dnsmasq) and DNS services are active..."
systemctl enable dnsmasq 2>/dev/null || true
if ! systemctl is-active --quiet dnsmasq; then
    systemctl start dnsmasq 2>/dev/null || true
    echo "  ✓ Started dnsmasq (DHCP server)"
else
    echo "  ✓ dnsmasq is running"
fi

if systemctl list-unit-files | grep -q "^unbound.service"; then
    systemctl enable unbound 2>/dev/null || true
fi

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
