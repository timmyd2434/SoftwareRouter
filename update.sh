#!/bin/bash
set -e  # Exit on error

echo "========================================="
echo "  SoftRouter Update Script"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
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
git fetch origin
CURRENT_BRANCH=$(git branch --show-current)
echo "  Current branch: $CURRENT_BRANCH"

# Check if there are updates
if git diff --quiet HEAD origin/$CURRENT_BRANCH; then
    echo "  ℹ️  Already up to date!"
    echo ""
    echo "Cleaning up backup..."
    rm -rf "$BACKUP_DIR"
    exit 0
fi

git pull origin $CURRENT_BRANCH
echo "  ✓ Updated to latest version"
echo ""

# Stop the backend service
echo "🛑 Stopping SoftRouter backend service..."
if systemctl is-active --quiet softrouter-backend; then
    systemctl stop softrouter-backend
    echo "  ✓ Service stopped"
else
    echo "  ℹ️  Service not running"
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
echo ""

# Build frontend
echo "🎨 Building frontend..."
cd frontend
if [ -d "node_modules" ]; then
    npm run build
    if [ $? -eq 0 ]; then
        echo "  ✓ Frontend built successfully"
    else
        echo "  ❌ Frontend build failed!"
        cd ..
        echo "  Restoring configuration from backup..."
        cp -r $BACKUP_DIR/* "$SCRIPT_DIR/"
        exit 1
    fi
else
    echo "  ⚠️  node_modules not found, skipping frontend build"
    echo "  Run 'npm install' in the frontend directory first"
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

# Restart the backend service
echo "🚀 Starting SoftRouter backend service..."
systemctl start softrouter-backend
if systemctl is-active --quiet softrouter-backend; then
    echo "  ✓ Service started successfully"
else
    echo "  ❌ Failed to start service!"
    echo "  Check logs: journalctl -u softrouter-backend -n 50"
    exit 1
fi
echo ""

# Display service status
echo "========================================="
echo "  Update Complete!"
echo "========================================="
echo ""
echo "Service Status:"
systemctl status softrouter-backend --no-pager -l | head -n 10
echo ""
echo "✅ SoftRouter has been updated successfully!"
echo ""
echo "Your firewall rules and configuration have been preserved."
echo "The backend service is now running with the latest code."
echo ""
