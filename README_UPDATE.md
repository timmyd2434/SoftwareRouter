# SoftRouter Update Guide

## Quick Update

To update SoftRouter to the latest version while preserving all your settings:

```bash
cd /home/tim/Documents/SoftwareRouter
sudo ./update.sh
```

That's it! The script will:
- ✅ Pull the latest changes from Git
- ✅ Backup your configuration files
- ✅ Rebuild backend and frontend
- ✅ Restore your settings
- ✅ Restart the service

## What Gets Preserved

The update script automatically backs up and restores:
- `config.json` - Main configuration
- `interface_metadata.json` - WAN/LAN interface labels
- `port_forwarding_rules.json` - Port forwarding rules
- `pbr_rules.json` - Policy-based routing rules
- `dhcp_config.json` - DHCP configurations

**Your firewall rules are NOT lost** - They're stored directly in nftables and persist across updates.

## Manual Update (Alternative)

If you prefer to update manually:

```bash
cd /home/tim/Documents/SoftwareRouter

# Pull latest changes
git pull origin Dev  # or 'main' depending on your branch

# Stop service
sudo systemctl stop softrouter-backend

# Rebuild backend
cd backend
go build -o softrouter-backend
sudo cp softrouter-backend /usr/local/bin/
cd ..

# Rebuild frontend (optional if UI changed)
cd frontend
npm run build
cd ..

# Restart service
sudo systemctl start softrouter-backend
```

## Troubleshooting

### Update script fails
```bash
# Check the error message
# Your config is backed up to /tmp/softrouter-backup-*

# Restore manually if needed:
sudo cp /tmp/softrouter-backup-*/* /home/tim/Documents/SoftwareRouter/
```

### Service won't start
```bash
# Check logs
sudo journalctl -u softrouter-backend -n 50

# Check service status
sudo systemctl status softrouter-backend
```

### Frontend build fails
This usually means `node_modules` is missing:
```bash
cd frontend
npm install
npm run build
```

## Automated Updates

Want to automatically update on a schedule? Add to crontab:

```bash
# Edit crontab
sudo crontab -e

# Add this line to update daily at 3 AM:
0 3 * * * cd /home/tim/Documents/SoftwareRouter && ./update.sh >> /var/log/softrouter-update.log 2>&1
```

## What Happens During Update

1. **Backup Phase** - All config files copied to `/tmp/softrouter-backup-*`
2. **Git Pull** - Latest code downloaded from GitHub
3. **Service Stop** - Backend service gracefully stopped
4. **Build Phase** - Backend and frontend rebuilt
5. **Install Phase** - New binary installed to `/usr/local/bin/`
6. **Restore Phase** - Config files restored from backup
7. **Service Start** - Backend service restarted
8. **Cleanup** - Temporary backup removed

## Important Notes

- ✅ **Firewall rules persist** - Stored in nftables kernel space
- ✅ **Port forwards persist** - Saved in JSON, restored automatically
- ✅ **Interface labels persist** - WAN/LAN labels preserved
- ⚠️ **Requires sudo** - Script needs root to restart service
- ⚠️ **Brief downtime** - Service restarts (usually < 10 seconds)
