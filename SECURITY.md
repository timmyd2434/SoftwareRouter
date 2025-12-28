# Security Stack Integration Guide

## 🛡️ Overview

This router now includes a comprehensive security stack combining:
- **Suricata** - Signature-based IDS/IPS
- **CrowdSec** - Behavioral analysis and community threat intelligence

Both systems work together to provide layered defense against network threats.

---

## 📦 Installation

### Quick Install (Recommended)

Run the automated installation script:

```bash
cd /home/tim/Documents/SoftwareRouter
sudo ./install-security.sh
```

This script will:
1. Install Suricata IDS/IPS
2. Install CrowdSec security engine
3. Install CrowdSec nftables bouncer
4. Configure home network settings
5. Update Suricata rulesets (ET Open)
6. Install CrowdSec collections for Linux, SSH, HTTP-CVE, and Suricata
7. Start and enable all services

### Manual Installation

If you prefer manual installation:

#### 1. Install Suricata
```bash
sudo apt update
sudo apt install suricata jq -y
```

#### 2. Configure Suricata
Edit `/etc/suricata/suricata.yaml`:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"  # Your LAN network
    EXTERNAL_NET: "!$HOME_NET"
```

Update rules:
```bash
sudo suricata-update
```

#### 3. Install CrowdSec
```bash
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt install crowdsec
sudo apt install crowdsec-firewall-bouncer-nftables
```

#### 4. Install CrowdSec Collections
```bash
sudo cscli collections install crowdsecurity/linux
sudo cscli collections install crowdsecurity/sshd
sudo cscli collections install crowdsecurity/http-cve
sudo cscli collections install crowdsecurity/iptables
sudo cscli collections install crowdsecurity/suricata
```

#### 5. Start Services
```bash
sudo systemctl enable --now suricata
sudo systemctl enable --now crowdsec
sudo systemctl restart crowdsec-firewall-bouncer
```

---

## ⚙️ Configuration

### Suricata Configuration

**Main Config:** `/etc/suricata/suricata.yaml`

**Key Settings:**

1. **Network Interface** - Set the interface to monitor:
```yaml
af-packet:
  - interface: eth0  # Change to your WAN interface
```

2. **IDS vs IPS Mode:**
   - **IDS (Default)** - Passive monitoring, logs only
   - **IPS Mode** - Active blocking
   
For IPS mode, set:
```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

3. **Rule Sources:**
```bash
sudo suricata-update list-sources        # List available sources
sudo suricata-update enable-source et/pro  # Enable ET Pro (requires subscription)
sudo suricata-update                     # Apply changes
```

**Logs Location:** `/var/log/suricata/eve.json`

### CrowdSec Configuration

**Main Config:** `/etc/crowdsec/config.yaml`

**Common Commands:**
```bash
# View active blocks
sudo cscli decisions list

# View alerts
sudo cscli alerts list

# Add IP to whitelist
sudo cscli decisions add --ip 192.168.1.100 --type whitelist

# Remove a decision
sudo cscli decisions delete --ip 1.2.3.4

# View metrics
sudo cscli metrics

# View installed collections
sudo cscli collections list
```

**Bouncer Config:** `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`

---

## 🔍 Verification

### Check Service Status

```bash
# Suricata
sudo systemctl status suricata
sudo tail -f /var/log/suricata/eve.json

# CrowdSec
sudo systemctl status crowdsec
sudo cscli metrics

# Bouncer
sudo systemctl status crowdsec-firewall-bouncer
```

### Test Detection

**Test Suricata:**
```bash
# Trigger a test alert (from another machine)
curl http://YOUR_ROUTER_IP/test-alert

# View alerts
sudo tail -f /var/log/suricata/fast.log
```

**Test CrowdSec:**
```bash
# Simulate failed SSH attempts (will trigger blocking)
# From another machine, try failed SSH logins

# Check if IP was blocked
sudo cscli decisions list
```

---

## 📊 Web Interface

The router web UI now includes a **Security** page showing:

### Real-Time Features
- ✅ Suricata alert feed with severity filtering
- ✅ CrowdSec active blocks list
- ✅ Top attack signatures
- ✅ Security statistics dashboard
- ✅ Alert severity breakdown (High/Medium/Low)
- ✅ Blocked IPs count
- ✅ Auto-refresh every 5 seconds

### Accessing the Security Page
1. Open web interface: `http://localhost:5173`
2. Click **"Security"** in the sidebar
3. View real-time alerts and blocks

---

## 🎯 Use Cases

### Home Network Protection
**Scenario:** Protect home network from internet threats

**Configuration:**
- Suricata in IDS mode monitoring WAN interface
- CrowdSec blocking brute force attempts
- Alerts accessible via web UI

### Small Business Router
**Scenario:** Multi-interface router with DMZ

**Configuration:**
- Suricata monitoring all interfaces
- Custom rules for web servers in DMZ
- CrowdSec protecting SSH and web services
- Whitelist office IPs

### Development/Testing
**Scenario:** Learn about network security

**Configuration:**
- IDS mode only (no blocking)
- Review alerts to understand traffic
- Experiment with custom rules

---

## 🚀 Performance Tuning

### Suricata Performance

**For Gigabit Networks:**
```yaml
# /etc/suricata/suricata.yaml
af-packet:
  - interface: eth0
    threads: 4           # Match CPU cores
    cluster-id: 99
    cluster-type: cluster_flow
    ring-size: 32768     # Increase buffer
```

**Rule Optimization:**
```bash
# Disable unnecessary rulesets
sudo suricata-update disable-source et/activex
sudo suricata-update
```

### CrowdSec Performance

CrowdSec is lightweight by design. For better performance:

```bash
# Reduce log parsing frequency (if needed)
sudo nano /etc/crowdsec/config.yaml

# Adjust parsers if certain logs aren't needed
sudo cscli parsers list
```

---

## 🔧 Troubleshooting

### Suricata Not Starting

**Check logs:**
```bash
sudo journalctl -xeu suricata
```

**Common issues:**
- Invalid interface name in config
- Syntax error in suricata.yaml
- Insufficient permissions

**Fix:**
```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Check interface names
ip addr show
```

### No Alerts Showing

**Verify Suricata is capturing:**
```bash
# Check if eve.json is being written
sudo tail -f /var/log/suricata/eve.json

# Check stats
sudo tail -f /var/log/suricata/stats.log
```

**Generate test traffic:**
```bash
# From another machine
curl http://testmynids.org/uid/index.html
```

### CrowdSec Not Blocking

**Check bouncer status:**
```bash
sudo systemctl status crowdsec-firewall-bouncer
sudo cscli bouncers list
```

**Verify decisions exist:**
```bash
sudo cscli decisions list
```

**Check nftables:**
```bash
sudo nft list ruleset | grep -A 10 crowdsec
```

### Web UI Shows "Not Detected"

**Possible causes:**
1. Services not installed
2. Backend doesn't have permissions to read logs
3. Log files in non-standard location

**Fix:**
```bash
# Grant read permissions
sudo chmod 644 /var/log/suricata/eve.json
sudo usermod -aG suricata tim  # Add user to suricata group

# Restart backend
cd /home/tim/Documents/SoftwareRouter/backend
sudo kill -9 $(sudo lsof -t -i:8080)
echo "09_SEPT_1982td" | sudo -S go run main.go >> backend.log 2>&1 &
```

---

## 📝 Custom Rules

### Adding Suricata Rules

**Create custom rules file:**
```bash
sudo nano /etc/suricata/rules/custom.rules
```

**Example rules:**
```
# Alert on SSH brute force
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH-"; detection_filter:track by_src, count 5, seconds 60; sid:1000001;)

# Block specific domain
drop dns any any -> any any (msg:"Malicious Domain Blocked"; content:"evil.com"; nocase; sid:1000002;)
```

**Enable in suricata.yaml:**
```yaml
rule-files:
  - suricata.rules
  - custom.rules  # Add this line
```

**Reload rules:**
```bash
sudo systemctl reload suricata
```

### Adding CrowdSec Scenarios

**Custom scenario location:** `/etc/crowdsec/scenarios/`

**Example - Block port scanners:**
```yaml
# /etc/crowdsec/scenarios/portscan-detection.yaml
type: trigger
name: crowdsecurity/portscan-detection
description: "Detect port scanning attempts"
filter: "evt.Meta.log_type == 'tcp_connection'"
groupby: "evt.Meta.source_ip"
distinct: "evt.Meta.dest_port"
capacity: 5
leakspeed: "10s"
blackhole: 1m
labels:
 service: network
 type: scan
 remediation: ban
```

**Reload CrowdSec:**
```bash
sudo systemctl reload crowdsec
```

---

## 🌐 Integration with Router Features

### NFTables Integration

CrowdSec automatically integrates with nftables via the bouncer. Blocked IPs are added to nftables drop rules.

**View CrowdSec nftables rules:**
```bash
sudo nft list table inet crowdsec-firewall-bouncer
```

### Traffic Monitoring Integration

The Traffic page and Security page complement each other:
- **Traffic page** - Shows bandwidth and connections
- **Security page** - Shows which connections triggered alerts

### Firewall Integration

Suricata can work alongside your NFTables firewall rules:
- NFTables provides basic port/protocol filtering
- Suricata provides deep packet inspection
- CrowdSec provides behavioral blocking

---

## 📈 Best Practices

1. **Start in IDS Mode**
   - Monitor for false positives first
   - Enable IPS mode once confident

2. **Regular Updates**
   ```bash
   sudo suricata-update  # Weekly
   sudo cscli hub update && sudo cscli hub upgrade  # Weekly
   ```

3. **Review Alerts Weekly**
   - Check Security page regularly
   - Investigate high-severity alerts
   - Whitelist known-good IPs

4. **Tune for Your Environment**
   - Disable irrelevant rules
   - Whitelist internal services
   - Adjust thresholds

5. **Backup Configuration**
   ```bash
   sudo tar -czf ~/suricata-backup.tar.gz /etc/suricata/
   sudo tar -czf ~/crowdsec-backup.tar.gz /etc/crowdsec/
   ```

---

## 🆘 Support Resources

### Suricata
- Documentation: https://suricata.io/documentation/
- Rules: https://rules.emergingthreats.net/
- Community: https://forum.suricata.io/

### CrowdSec
- Documentation: https://doc.crowdsec.net/
- Hub (Collections/Scenarios): https://hub.crowdsec.net/
- Discord: https://discord.gg/crowdsec

---

## 📊 Expected Resource Usage

### Suricata
- **RAM:** 200-500MB (depends on rules)
- **CPU:** 10-30% on 1 core during traffic spikes
- **Disk:** ~100MB for logs (rotate regularly)

### CrowdSec
- **RAM:** 50-100MB
- **CPU:** <5% average
- **Disk:** ~50MB for database

**Total:** Plan for ~1GB RAM and spare CPU capacity for optimal performance.

---

**Installation script created:** `/home/tim/Documents/SoftwareRouter/install-security.sh`

**Run with:** `sudo ./install-security.sh`
