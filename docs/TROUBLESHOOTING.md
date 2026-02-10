# SoftRouter Troubleshooting Guide

Quick reference for diagnosing and fixing common issues with SoftRouter.

---

## 🔴 Critical Issues

### Service Won't Start

**Symptoms**: `softrouter-backend` service fails to start or crashes immediately.

**Diagnosis**:
```bash
# Check service status
sudo systemctl status softrouter-backend

# View recent logs
sudo journalctl -u softrouter-backend -n 100 --no-pager

# Check if port is already in use
sudo lsof -i :80
```

**Solutions**:
1. **Port conflict**: Another service using port 80/443
   ```bash
   # Stop conflicting service (e.g., apache2)
   sudo systemctl stop apache2
   sudo systemctl disable apache2
   sudo systemctl start softrouter-backend
   ```

2. **Permission issues**: Binary needs root access
   ```bash
   sudo chmod +x /usr/local/bin/softrouter-backend
   sudo chown root:root /usr/local/bin/softrouter-backend
   ```

3. **Missing config files**:
   ```bash
   # Restore from backup or reinstall
   sudo mkdir -p /etc/softrouter
   # Run installer to regenerate configs
   ```

---

### Cannot Login / Authentication Fails

**Symptoms**: Login page accepts credentials but returns error or "Unauthorized".

**Diagnosis**:
```bash
# Check credentials file
sudo cat /etc/softrouter/user_credentials.json

# Check token secret
sudo cat /etc/softrouter/token_secret.key

# View auth-related logs
sudo journalctl -u softrouter-backend | grep -i "login\|auth"
```

**Solutions**:

1. **Forgot password**: Reset via config file
   ```bash
   # Generate new password hash (use bcrypt online tool or Python)
   python3 -c "import bcrypt; print(bcrypt.hashpw(b'newpassword', bcrypt.gensalt()).decode())"
   
   # Edit credentials file
   sudo nano /etc/softrouter/user_credentials.json
   # Set password to generated hash
   
   sudo systemctl restart softrouter-backend
   ```

2. **Token secret missing**: Regenerate
   ```bash
   # Backend auto-generates on startup if missing
   sudo rm /etc/softrouter/token_secret.key
   sudo systemctl restart softrouter-backend
   ```

3. **Rate limiting**: Too many failed attempts
   ```bash
   # Wait 15 minutes or restart service to clear
   sudo systemctl restart softrouter-backend
   ```

4. **CSRF token issues**: Clear browser cache/cookies
   - Open browser DevTools (F12)
   - Clear all site data for router IP
   - Refresh page

---

### Web Interface Not Loading

**Symptoms**: Browser shows "Connection refused" or blank page.

**Diagnosis**:
```bash
# Is service running?
sudo systemctl status softrouter-backend

# Is frontend built?
ls -la /home/*/SoftwareRouter/frontend/dist/

# Check network connectivity
ping <router-ip>

# Check firewall rules
sudo nft list ruleset | grep -A5 "tcp dport 80"
```

**Solutions**:

1. **Frontend not built**:
   ```bash
   cd /path/to/SoftwareRouter/frontend
   npm install
   npm run build
   ```

2. **Wrong IP/Port**: Verify access URL
   - localhost: `http://127.0.0.1`
   - LAN: `http://<router-lan-ip>`
   - Check port in browser (default: 80)

3. **Firewall blocking**: Allow HTTP traffic
   ```bash
   sudo nft add rule inet filter input tcp dport 80 accept
   ```

4. **CORS issues** (development mode):
   - Check allowed origins in config.json
   - Ensure frontend dev server uses correct proxy

---

## ⚠️ Network Issues

### Port 53 Conflict (DNS)

**Symptoms**: Cannot install AdGuard/Pi-hole, DNS not working.

**Solution**:
```bash
# Disable systemd-resolved stub
echo -e "[Resolve]\nDNSStubListener=no" | sudo tee /etc/systemd/resolved.conf.d/softrouter.conf

# Update resolv.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

# Restart
sudo systemctl restart systemd-resolved

# Verify port 53 is free
sudo lsof -i :53
```

---

### Port Forwarding Not Working

**Symptoms**: External connections to forwarded ports fail or timeout.

**Diagnosis**:
```bash
# Check nftables rules
sudo nft list ruleset | grep -A10 dnat

# Test from internal network
curl http://<lan-ip>:<forwarded-port>

# Test from external (using mobile data)
curl http://<wan-ip>:<external-port>
```

**Solutions**:

1. **Verify rule exists**: Check Firewall → Port Forwarding in UI

2. **Hairpin NAT for internal testing**:
   - Rules auto-created by SoftRouter
   - If not working, check masquerade rules

3. **WAN firewall blocking**:
   ```bash
   # Check if WAN allows incoming on port
   sudo nft list ruleset | grep "iifname <wan-interface>"
   ```

4. **ISP blocking**: Some ISPs block common ports (80, 25, etc.)
   - Use alternate ports (e.g., 8080 instead of 80)
   - Contact ISP about port blocking

---

### VLAN Not Working

**Symptoms**: VLAN interface created but no connectivity.

**Diagnosis**:
```bash
# Check VLAN interfaces
ip link show | grep @

# Check VLAN routing
ip route show

# Verify switch supports 802.1Q
# (requires managed switch)
```

**Solutions**:

1. **Switch not configured**: Enable VLAN tagging
   - Access switch admin interface
   - Create VLAN with matching ID
   - Tag appropriate ports

2. **VLAN interface down**:
   ```bash
   sudo ip link set <interface>.10 up
   ```

3. **No IP assigned**:
   - Go to Network → Interfaces
   - Assign IP to VLAN interface
   - Configure DHCP or static IP

---

## 🔧 Configuration Issues

### Changes Not Persisting

**Symptoms**: Settings reset after reboot or service restart.

**Diagnosis**:
```bash
# Check config file permissions
ls -la /etc/softrouter/

# Verify write access
sudo touch /etc/softrouter/test.txt
```

**Solutions**:

1. **Permission issues**:
   ```bash
   sudo chown -R root:root /etc/softrouter
   sudo chmod 755 /etc/softrouter
   sudo chmod 644 /etc/softrouter/*.json
   ```

2. **Config file corruption**:
   ```bash
   # Validate JSON
   sudo cat /etc/softrouter/config.json | jq .
   
   # If invalid, restore from backup
   sudo cp /tmp/softrouter-backup-*/config.json /etc/softrouter/
   ```

3. **Running development binary**: Ensure systemd uses production binary
   ```bash
   sudo systemctl cat softrouter-backend | grep ExecStart
   # Should point to /usr/local/bin/softrouter-backend
   ```

---

### Firewall Rules Disappear or Duplicate

**Symptoms**: nftables rules lost after reboot, or duplicate rules appearing.

**Solution**:

SoftRouter automatically syncs firewall rules to `/etc/nftables.conf` after successful application. This ensures:
- Rules persist across reboots via the `nftables.service`
- No duplication occurs (SoftRouter uses `flush ruleset` before applying)
- Boot-time firewall protection even if SoftwareRouter fails to start

**Manual verification**:
```bash
# View saved ruleset (will be loaded at boot)
sudo cat /etc/nftables.conf

# Verify nftables.service is enabled
sudo systemctl status nftables
```

**Important Notes**:
- **Do NOT manually edit `/etc/nftables.conf`** - it will be overwritten on the next firewall apply
- Use the SoftRouter WebUI to manage firewall rules
- Manual `nft` commands will be lost on the next rule application
- A backup of the previous ruleset is saved to `/etc/nftables.conf.backup`

**If experiencing duplication issues**:
```bash
# Check for duplicate rules
sudo nft list ruleset | grep -A3 "chain input"

# Purge and reapply (via WebUI or manual restart)
sudo systemctl restart softrouter
```


---

## 🚀 Performance Issues

### High CPU Usage

**Diagnosis**:
```bash
# Check CPU usage by process
top -bn1 | grep softrouter
htop

# Check running services
sudo systemctl status suricata
sudo systemctl status crowdsec
```

**Solutions**:

1. **Suricata consuming CPU**: Normal for IDS/IPS
   - Disable if not needed: `sudo systemctl stop suricata`
   - Tune Suricata rules for lower CPU usage

2. **CrowdSec high usage**: Reduce polling frequency
   - Edit CrowdSec config
   - Increase intervals between updates

3. **Too many firewall rules**: Optimize nftables rules
   - Combine similar rules
   - Use sets for multiple IPs/ports

---

### Slow Web Interface

**Diagnosis**:
```bash
# Check backend response times
curl -w "@-" -o /dev/null -s http://localhost/api/status <<'EOF'
    time_total:  %{time_total}s\n
EOF

# Check system load
uptime
free -h
```

**Solutions**:

1. **Enable caching**: Already enabled for status endpoints

2. **Reduce polling frequency** (frontend):
   - Edit dashboard polling interval
   - Default: 5 seconds (can increase)

3. **System overloaded**: Add more RAM or reduce services

---

## 📦 Update & Build Issues

### Update Script Fails

**Symptoms**: `update.sh` exits with errors.

**Diagnosis**:
```bash
# Check git status
cd /path/to/SoftwareRouter
git status

# Check for conflicts
git diff
```

**Solutions**:

1. **Merge conflicts**:
   ```bash
   git stash  # Save local changes
   git pull origin Dev
   git stash pop  # Restore changes
   # Resolve conflicts manually
   ```

2. **Uncommitted changes**:
   ```bash
   git add .
   git commit -m "Local changes before update"
   git pull origin Dev
   ```

3. **Manual restore from backup**:
   ```bash
   # Configs saved to /tmp/softrouter-backup-*
   sudo cp -r /tmp/softrouter-backup-*/* /path/to/SoftwareRouter/
   ```

---

### Build Errors

**Backend build fails**:
```bash
cd backend

# Missing dependencies
go mod tidy
go mod download

# Rebuild
go build -o softrouter-backend *.go
```

**Frontend build fails**:
```bash
cd frontend

# Clear cache
rm -rf node_modules package-lock.json

# Reinstall
npm install

# Rebuild
npm run build
```

---

## 🔍 Debugging Tips

### Enable Verbose Logging

**Temporary** (current session):
```bash
# Stop service
sudo systemctl stop softrouter-backend

# Run manually with debug
cd /home/*/SoftwareRouter/backend
sudo ./softrouter-backend --verbose
```

**Permanent**:
Edit service file to add debug flags, then reload and restart.

---

### Check All Logs

**Service logs**:
```bash
sudo journalctl -u softrouter-backend -f
```

**Audit logs**:
```bash
sudo cat /var/log/softrouter/audit.log | jq
```

**System logs**:
```bash
dmesg | tail -50
/var/log/syslog | grep softrouter
```

---

### Network Diagnostics

**Test connectivity**:
```bash
# From router
ping 8.8.8.8
curl https://www.google.com

# DNS resolution
nslookup google.com

# Routing table
ip route show

# NAT status
sudo nft list table inet nat
```

---

## 🆘 Getting Help

If you can't resolve your issue:

1. **Collect information**:
   ```bash
   # System info
   cat /etc/os-release
   uname -a
   
   # Service status
   sudo systemctl status softrouter-backend
   
   # Recent logs
   sudo journalctl -u softrouter-backend -n 200 > softrouter-logs.txt
   ```

2. **Create GitHub issue**: https://github.com/timmyd2434/SoftwareRouter/issues
   - Include collected information
   - Describe expected vs actual behavior
   - List steps to reproduce

3. **Check existing issues**: Your problem may already be solved

---

## 🔄 Complete Reinstall

**Last resort** - Nuclear option:
```bash
# Backup configs
sudo cp -r /etc/softrouter /tmp/softrouter-backup-final

# Remove service
sudo systemctl stop softrouter-backend
sudo systemctl disable softrouter-backend
sudo rm /etc/systemd/system/softrouter-backend.service

# Clean install
cd /path/to/SoftwareRouter
git pull origin Dev
sudo ./install.sh

# Restore configs (optional)
sudo cp /tmp/softrouter-backup-final/* /etc/softrouter/
sudo systemctl restart softrouter-backend
```

---

**Remember**: Most issues are config or permission related. Check logs first! 📋
