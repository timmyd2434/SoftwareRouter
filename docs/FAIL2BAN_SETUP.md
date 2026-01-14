# Fail2Ban Integration Guide for SoftRouter

## Overview
Fail2Ban monitors log files and automatically bans IP addresses that show malicious behavior (e.g., too many failed login attempts). This guide integrates Fail2Ban with SoftRouter's login system for enhanced brute-force protection.

> **Note**: SoftRouter already includes built-in rate limiting (5 failed attempts = 15-minute ban). Fail2Ban adds an additional layer using system-level firewall bans that persist across backend restarts.

---

## Installation

### 1. Install Fail2Ban

```bash
sudo apt update
sudo apt install fail2ban -y
```

### 2. Enable and Start Service

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## Configuration for SoftRouter

### 1. Create Log File Directory

SoftRouter logs to syslog by default. We'll configure it to also log to a dedicated file:

```bash
sudo mkdir -p /var/log/softrouter
sudo touch /var/log/softrouter/auth.log
sudo chown $USER:$USER /var/log/softrouter/auth.log
```

### 2. Update SoftRouter Backend Logging

> **Future Enhancement**: The backend should log failed login attempts to `/var/log/softrouter/auth.log`.  
> For now, we'll use syslog monitoring.

### 3. Create Fail2Ban Filter

Create `/etc/fail2ban/filter.d/softrouter.conf`:

```ini
[Definition]
# Fail2Ban filter for SoftRouter login failures

failregex = ^.*Banned IP <HOST> due to excessive login failures.*$
            ^.*Invalid credentials.*from.*<HOST>.*$

ignoreregex =

# Example log line:
# 2026/01/14 17:45:23 Banned IP 192.168.1.100 due to excessive login failures
```

### 4. Create Fail2Ban Jail

Create `/etc/fail2ban/jail.d/softrouter.conf`:

```ini
[softrouter]
enabled = true
port = 80,443
protocol = tcp
filter = softrouter
logpath = /var/log/syslog
           /var/log/softrouter/auth.log
maxretry = 3
findtime = 600
bantime = 3600
action = nftables-multiport[name=softrouter, port="80,443", protocol=tcp]

# Optional: Send email notifications
#action = %(action_mw)s
#destemail = admin@example.com
#sender = fail2ban@router.local
```

**Configuration Explained**:
- `maxretry = 3`: Ban after 3 offenses detected by Fail2Ban
- `findtime = 600`: Look for failures within 10 minutes
- `bantime = 3600`: Ban for 1 hour (3600 seconds)
- `action = nftables-multiport`: Use nftables for banning (compatible with SoftRouter)

### 5. Test the Configuration

```bash
# Test the filter against sample log
sudo fail2ban-regex /var/log/syslog /etc/fail2ban/filter.d/softrouter.conf

# Restart Fail2Ban
sudo systemctl restart fail2ban
```

---

## Verification

### Check Fail2Ban Status

```bash
# Overall status
sudo fail2ban-client status

# SoftRouter jail status
sudo fail2ban-client status softrouter
```

**Example Output**:
```
Status for the jail: softrouter
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     5
|  `- File list:        /var/log/syslog
`- Actions
   |- Currently banned: 1
   |- Total banned:     1
   `- Banned IP list:   192.168.1.100
```

### View Banned IPs

```bash
sudo fail2ban-client get softrouter banned
```

### View nftables Ban Rules

```bash
sudo nft list table inet f2b-softrouter
```

---

## Manual Ban/Unban

### Ban an IP Manually

```bash
sudo fail2ban-client set softrouter banip 203.0.113.42
```

### Unban an IP

```bash
sudo fail2ban-client set softrouter unbanip 203.0.113.42
```

### Whitelist Your Own IP (Important!)

To prevent accidentally locking yourself out, whitelist your management IP:

Edit `/etc/fail2ban/jail.d/softrouter.conf` and add:

```ini
ignoreip = 127.0.0.1/8 ::1
           192.168.1.0/24        # Your LAN network
           10.0.0.5              # Your specific admin workstation
```

Restart Fail2Ban:
```bash
sudo systemctl restart fail2ban
```

---

## Integration with CrowdSec

If you're using both Fail2Ban and CrowdSec (from SECURITY.md), they work together:

1. **CrowdSec**: Community-driven threat intelligence, behavioral analysis
2. **Fail2Ban**: Log-based reactive banning

They can coexist. Both use nftables, so bans are additive.

### Avoid Conflicts

Ensure they use different nftables table names:
- CrowdSec: `inet crowdsec-firewall-bouncer`
- Fail2Ban: `inet f2b-*`

---

## Advanced Configuration

### Email Notifications on Ban

Install mail utilities:
```bash
sudo apt install mailutils -y
```

Update `/etc/fail2ban/jail.d/softrouter.conf`:

```ini
[softrouter]
# ...existing config...
destemail = admin@example.com
sender = fail2ban@router.local
action = %(action_mwl)s
```

`%(action_mwl)s` sends email with logs at ban/unban.

### Persistent Bans Across Reboots

By default, Fail2Ban forgets bans on restart. To persist:

Edit `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
dbfile = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage = 86400
```

This stores bans in a database for 24 hours even after reboot.

---

## Monitoring and Logs

### View Fail2Ban Logs

```bash
sudo tail -f /var/log/fail2ban.log
```

**Example entries**:
```
2026-01-14 18:00:15,123 fail2ban.actions [12345]: NOTICE [softrouter] Ban 192.168.1.100
2026-01-14 19:00:15,456 fail2ban.actions [12345]: NOTICE [softrouter] Unban 192.168.1.100
```

### Real-Time Ban Notifications

Use `systemd-journalctl` with filtering:

```bash
journalctl -u fail2ban -f | grep softrouter
```

---

## Troubleshooting

### Fail2Ban Not Detecting Failures

**Check filter regex**:
```bash
sudo fail2ban-regex systemd-journal /etc/fail2ban/filter.d/softrouter.conf
```

**Verify log path**:
```bash
sudo ls -la /var/log/softrouter/auth.log
```

**Increase verbosity** (temporary):
```bash
sudo fail2ban-client set loglevel DEBUG
sudo systemctl restart fail2ban
```

### IPs Not Getting Banned

1. **Check SoftRouter logs** are being written:
   ```bash
   sudo tail -f /var/log/syslog | grep "login"
   ```

2. **Verify nftables is enabled**:
   ```bash
   sudo nft list ruleset | grep fail2ban
   ```

3. **Test manually**:
   ```bash
   sudo fail2ban-client set softrouter banip 1.2.3.4
   sudo nft list ruleset | grep 1.2.3.4
   ```

### Can't Access Router After Banned

If you're locked out:

1. **Access via console/SSH** (not through web UI)
2. **Unban your IP**:
   ```bash
   sudo fail2ban-client set softrouter unbanip YOUR.IP.ADDRESS
   ```
3. **Add your IP to whitelist** (see above)

---

## Best Practices

1. **Whitelist trusted IPs first** - Before enabling Fail2Ban in production
2. **Start with longer findtime** (e.g., 1800s) to reduce false positives
3. **Monitor logs daily** especially in the first week
4. **Use `maxretry = 3`** instead of 1-2 to avoid accidental lockouts
5. **Set reasonable bantime** - 1 hour is sufficient, lifetime bans can cause issues
6. **Test from external IP** before relying on it

---

## Performance Impact

- **RAM**: ~20-50MB
- **CPU**: <1% average
- **Disk I/O**: Minimal (only reads logs on events)

---

## See Also

- [TLS Setup Guide](./TLS_SETUP.md)
- [Main Security Documentation](../SECURITY.md)
- [Fail2Ban Official Docs](https://fail2ban.readthedocs.io/)

---

**Quick Reference Commands**:

```bash
# Status
sudo fail2ban-client status softrouter

# Ban IP
sudo fail2ban-client set softrouter banip 1.2.3.4

# Unban IP  
sudo fail2ban-client set softrouter unbanip 1.2.3.4

# Reload config
sudo systemctl reload fail2ban

# View logs
sudo tail -f /var/log/fail2ban.log
```
