#!/bin/bash
# SoftRouter Update Script (Robust Execution)

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

# Ensure PATH and environment variables are set for non-interactive / systemd execution
export GOTOOLCHAIN="local"
export PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
for extra_path in /usr/local/go/bin /snap/bin; do
    if [ -d "$extra_path" ]; then
        export PATH="$extra_path:$PATH"
    fi
done
export HOME="${HOME:-/root}"
export GOCACHE="${HOME}/.cache/go-build"
export GOPATH="${HOME}/go"

# Clean any broken or partial Go toolchain downloads in /tmp/go
rm -rf /tmp/go/pkg/mod/golang.org/toolchain* 2>/dev/null || true

# Store current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Persist the repo location so the backend binary can find it at runtime.
mkdir -p /etc/softrouter
echo "$SCRIPT_DIR" > /etc/softrouter/repo_path
chmod 644 /etc/softrouter/repo_path

# Determine the real user who owns the repository directory
REAL_USER="${SUDO_USER:-$(stat -c "%U" "$SCRIPT_DIR" 2>/dev/null || echo "root")}"
if [ "$REAL_USER" = "UNKNOWN" ] || [ -z "$REAL_USER" ]; then
    REAL_USER="root"
fi
echo "ℹ️  Update running as root, repo owned by: $REAL_USER"

# Safety Trap: Guarantee that softrouter-backend is restarted under all circumstances
ensure_service_running() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "⚠️  Update script exited with code $exit_code"
    fi

    # Fix permissions so REAL_USER still owns the repo
    if [ -d "$SCRIPT_DIR/.git" ] && [ "$REAL_USER" != "root" ] && id "$REAL_USER" &>/dev/null; then
        chmod -R a+rw "$SCRIPT_DIR/.git" 2>/dev/null || true
        chown -R "$REAL_USER:$REAL_USER" "$SCRIPT_DIR" 2>/dev/null || true
    fi

    # Ensure backend process is running
    echo "🔄 Guaranteeing SoftRouter service is running..."
    if systemctl list-unit-files 2>/dev/null | grep -q "softrouter.service"; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl restart softrouter 2>/dev/null || systemctl start softrouter 2>/dev/null || true
        sleep 2
    fi

    if ! pgrep -f softrouter-backend > /dev/null 2>&1; then
        if [ -x /usr/local/bin/softrouter-backend ]; then
            nohup /usr/local/bin/softrouter-backend > /var/log/softrouter-backend.log 2>&1 &
        elif [ -x "$SCRIPT_DIR/backend/softrouter-backend" ]; then
            nohup "$SCRIPT_DIR/backend/softrouter-backend" > /var/log/softrouter-backend.log 2>&1 &
        fi
    fi
}
trap ensure_service_running EXIT

# Backup configuration files from /etc/softrouter/
echo "📦 Backing up configuration files..."
BACKUP_DIR="/tmp/softrouter-backup-$(date +%s)"
mkdir -p "$BACKUP_DIR/etc_softrouter"

if [ -d "/etc/softrouter" ]; then
    cp -a /etc/softrouter/. "$BACKUP_DIR/etc_softrouter/"
    echo "  ✓ Backed up /etc/softrouter/"
fi
echo ""

# Ensure git safe.directory is configured
git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true
git config --global --add safe.directory '*' 2>/dev/null || true
if [ "$REAL_USER" != "root" ] && id "$REAL_USER" &>/dev/null; then
    sudo -u "$REAL_USER" git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true
    sudo -u "$REAL_USER" git config --global --add safe.directory '*' 2>/dev/null || true
fi

# Ensure .git directory is accessible
if [ -d ".git" ]; then
    chmod -R a+rw .git 2>/dev/null || true
    if [ "$REAL_USER" != "root" ] && id "$REAL_USER" &>/dev/null; then
        chown -R "$REAL_USER:$REAL_USER" .git 2>/dev/null || true
    fi
fi

# Helper function to execute git commands safely without triggering bash set -e aborts
run_git() {
    if [ "$REAL_USER" != "root" ] && id "$REAL_USER" &>/dev/null; then
        sudo -u "$REAL_USER" git -c safe.directory=* "$@" 2>/dev/null || git -c safe.directory=* "$@"
    else
        git -c safe.directory=* "$@"
    fi
}

# Pull latest changes from git
echo "🔄 Pulling latest changes from Git..."
TARGET="${TARGET_BRANCH:-Dev}"
FETCH_URL="origin"

run_git fetch origin || true

CURRENT_BRANCH=$(run_git branch --show-current 2>/dev/null || echo "$TARGET")
if [ -z "$CURRENT_BRANCH" ]; then
    CURRENT_BRANCH="$TARGET"
fi
echo "  Current branch: $CURRENT_BRANCH"

# Switch branch if requested
if [ -n "$TARGET_BRANCH" ] && [ "$TARGET_BRANCH" != "$CURRENT_BRANCH" ]; then
    echo "  🔀 Switching from $CURRENT_BRANCH to $TARGET_BRANCH..."
    run_git checkout "$TARGET_BRANCH" || true
    CURRENT_BRANCH="$TARGET_BRANCH"
    echo "  ✓ Now on branch: $CURRENT_BRANCH"
fi

# Check if there are updates using explicit exit status handling
run_git diff --quiet HEAD "origin/$CURRENT_BRANCH" 2>/dev/null
HAS_DIFFS=$?

if [ $HAS_DIFFS -eq 0 ]; then
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

echo "  📥 Pulling changes for $CURRENT_BRANCH..."
PULL_SUCCESS=false

if run_git pull "$FETCH_URL" "$CURRENT_BRANCH"; then
    PULL_SUCCESS=true
elif run_git pull https://github.com/timmyd2434/SoftwareRouter.git "$CURRENT_BRANCH"; then
    PULL_SUCCESS=true
fi

if [ "$PULL_SUCCESS" = true ]; then
    echo "  ✓ Updated to latest version"
else
    echo "  ⚠️  Git pull failed; attempting git reset to origin/$CURRENT_BRANCH..."
    if run_git reset --hard "origin/$CURRENT_BRANCH"; then
        echo "  ✓ Reset to origin/$CURRENT_BRANCH"
    else
        echo "  ⚠️  Could not reset branch, proceeding with build..."
    fi
fi
echo ""

# Stop the backend service
echo "🛑 Stopping SoftRouter backend service..."
if systemctl is-active --quiet softrouter 2>/dev/null; then
    systemctl stop softrouter 2>/dev/null || true
    echo "  ✓ Service stopped"
else
    echo "  ℹ️  Service not running"
fi

# Kill any running softrouter-backend processes
if pgrep -f softrouter-backend > /dev/null 2>&1; then
    echo "  🔪 Killing running backend processes..."
    pkill -f softrouter-backend || true
    sleep 2
    echo "  ✓ Processes terminated"
fi
echo ""

# Ensure WireGuard packages are installed
if ! command -v wg &> /dev/null || ! systemctl list-unit-files 2>/dev/null | grep -q "^wg-quick@"; then
    echo "📦 Checking WireGuard packages..."
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -y -qq wireguard wireguard-tools || true
        echo "  ✓ WireGuard packages verified"
    fi
fi
echo ""

# Build backend
echo "🔨 Building backend..."
cd "$SCRIPT_DIR/backend"
if go build -o softrouter-backend; then
    echo "  ✓ Backend built successfully"
    cp softrouter-backend /usr/local/bin/
    chmod +x /usr/local/bin/softrouter-backend
    echo "  ✓ Backend installed to /usr/local/bin/"
else
    echo "  ❌ Backend build failed!"
    echo "  Restoring configuration from backup..."
    if [ -d "$BACKUP_DIR" ]; then
        cp -r "$BACKUP_DIR"/* "$SCRIPT_DIR/" 2>/dev/null || true
    fi
    exit 1
fi
cd "$SCRIPT_DIR"

# Create dnsmasq base configuration if it doesn't exist
echo "📡 Configuring dnsmasq..."
if [ ! -f /etc/dnsmasq.d/softrouter-base.conf ]; then
    cat > /tmp/softrouter-dnsmasq-base.conf <<'DNSMASQ_EOF'
# SoftwareRouter dnsmasq base configuration
no-resolv
no-hosts
log-dhcp
dhcp-authoritative
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
cd "$SCRIPT_DIR/frontend"

if [ ! -d "node_modules" ]; then
    echo "  📦 Installing npm dependencies..."
    npm install
fi

if npm run build; then
    echo "  ✓ Frontend built successfully"
    mkdir -p /var/www/softrouter/html
    cp -r dist/* /var/www/softrouter/html/
    echo "  ✓ Frontend deployed"
else
    echo "  ❌ Frontend build failed!"
    cd "$SCRIPT_DIR"
    if [ -d "$BACKUP_DIR" ]; then
        cp -r "$BACKUP_DIR"/* "$SCRIPT_DIR/" 2>/dev/null || true
    fi
    exit 1
fi
cd "$SCRIPT_DIR"
echo ""

# Restore configuration files back to /etc/softrouter/
echo "📥 Restoring configuration files..."
if [ -d "$BACKUP_DIR/etc_softrouter" ] && [ -n "$(ls -A "$BACKUP_DIR/etc_softrouter" 2>/dev/null)" ]; then
    mkdir -p /etc/softrouter
    chmod 700 /etc/softrouter
    cp -a "$BACKUP_DIR/etc_softrouter/." /etc/softrouter/
    find /etc/softrouter -maxdepth 1 -type f \( -name "*.json" -o -name "*.key" -o -name "*.nft" \) -exec chmod 600 {} \;
    echo "  ✓ Restored /etc/softrouter/"
fi
echo ""

# Clean up backup
rm -rf "$BACKUP_DIR"

# Security check
echo "🔐 Security pre-flight checks..."
if [ ! -f "/etc/softrouter/token_secret.key" ]; then
    mkdir -p /etc/softrouter
    head -c 32 /dev/urandom | base64 > /etc/softrouter/token_secret.key
    chmod 600 /etc/softrouter/token_secret.key
    echo "  ✓ Generated token_secret.key"
else
    echo "  ✓ token_secret.key exists"
fi

# Load nf_conntrack and enable byte accounting
echo "📊 Enabling conntrack byte accounting..."
modprobe nf_conntrack 2>/dev/null || true
sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null || true

# Install/Update systemd service
echo "⚙️  Configuring systemd service..."
if [ -f "$SCRIPT_DIR/softrouter.service" ]; then
    cp "$SCRIPT_DIR/softrouter.service" /etc/systemd/system/
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable softrouter 2>/dev/null || true
    echo "  ✓ Installed softrouter.service"
fi
echo ""

# Ensure DHCP and DNS services are enabled and active
echo "📡 Ensuring DHCP (dnsmasq) and DNS services are active..."
systemctl enable dnsmasq 2>/dev/null || true
systemctl start dnsmasq 2>/dev/null || true

# Restart the backend service
echo "🚀 Starting SoftRouter backend service..."
systemctl daemon-reload 2>/dev/null || true
systemctl restart softrouter 2>/dev/null || systemctl start softrouter 2>/dev/null || true
sleep 2

# Load nf_conntrack and enable byte accounting
echo "📊 Enabling conntrack byte accounting..."
modprobe nf_conntrack 2>/dev/null || true
sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null || true
if ! grep -q "nf_conntrack_acct" /etc/sysctl.d/99-softrouter.conf 2>/dev/null; then
    echo "net.netfilter.nf_conntrack_acct=1" >> /etc/sysctl.d/99-softrouter.conf 2>/dev/null || true
fi

# Install/Update systemd service
echo "⚙️  Configuring systemd service..."
if [ -f "$SCRIPT_DIR/softrouter.service" ]; then
    cp "$SCRIPT_DIR/softrouter.service" /etc/systemd/system/
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable softrouter 2>/dev/null || true
    echo "  ✓ Installed softrouter.service"
fi
echo ""

# Ensure DHCP and DNS services are active
echo "📡 Ensuring DHCP (dnsmasq) and DNS services are active..."
systemctl enable dnsmasq 2>/dev/null || true
systemctl start dnsmasq 2>/dev/null || true

# Restart backend service
echo "🚀 Starting SoftRouter backend service..."
systemctl daemon-reload 2>/dev/null || true
if systemctl list-unit-files 2>/dev/null | grep -q "softrouter.service"; then
    systemctl restart softrouter 2>/dev/null || systemctl start softrouter 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet softrouter 2>/dev/null || pgrep -f softrouter-backend > /dev/null 2>&1; then
        echo "  ✓ Service started successfully"
    else
        echo "  ⚠️ systemd restart failed, starting binary directly..."
        nohup /usr/local/bin/softrouter-backend > /var/log/softrouter-backend.log 2>&1 &
    fi
else
    echo "  ℹ️  systemd service not found - starting binary directly"
    nohup /usr/local/bin/softrouter-backend > /var/log/softrouter-backend.log 2>&1 &
fi
echo ""

echo "========================================="
echo "  Update Complete!"
echo "========================================="
echo "✅ SoftRouter has been updated successfully!"
echo ""
