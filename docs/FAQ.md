# SoftRouter FAQ (Frequently Asked Questions)

## General Questions

### What is SoftRouter?
SoftRouter is a web-based router management interface that turns any Debian/Ubuntu server into a powerful, security-hardened network appliance with features like IDS/IPS, firewall management, VPN, and more.

### What are the system requirements?
- **OS**: Debian 12+, Ubuntu 22.04+ LTS
- **RAM**: Minimum 2GB (4GB+ recommended)
- **CPU**: x86_64 (AVX support required for UniFi Controller)
- **Storage**: 10GB minimum for base system
- **Network**: At least 2 network interfaces (1 WAN, 1+ LAN)

### Is SoftRouter suitable for production use?
Not Really, yet. SoftRouter is designed for home and small business networks. It includes enterprise-grade security features like IDS/IPS, audit logging, and session management. It is still new any my have holes that still need patched. 

---

## Installation & Setup

### How do I install SoftRouter?
```bash
git clone -b Dev https://github.com/timmyd2434/SoftwareRouter.git
cd SoftwareRouter
sudo ./install.sh
```

The installer guides you through the complete setup process.

### Can I install on existing router hardware?
Yes! SoftRouter works on any x86_64 system including:
- Mini PCs (Intel NUC, etc.)
- Repurposed desktops/servers
- Cloud VMs (for VPN/proxy use cases)
- Protectli Vault devices

### What credentials should I use during installation?
Choose strong credentials (combine Uppercase, lowecase, numbers, and symbols) during Step 2 of installation. These will be your admin username and password for the web interface. You can change them later via **Settings** → **Administrative Credentials**.

### How do I access the web interface after installation?
Navigate to `http://<ROUTER_IP>`, ie. 192.168.0.x, from any device on your LAN. Use the credentials you set during installation.

---

## Network Configuration

### How do I assign WAN/LAN labels to interfaces?
1. Go to **Network** → **Interfaces**
2. Click the label icon next to each interface
3. Select WAN, LAN, DMZ, Guest, or custom labels
4. Interface zones automatically update firewall rules

### Can I create VLANs?
Yes! Navigate to **Network** → **VLANs** and create 802.1Q tagged VLANs on any physical interface. Each VLAN gets its own subnet and firewall zone.

### How does port forwarding work?
Go to **Firewall** → **Port Forwarding** to create rules. SoftRouter includes:
- Hairpin NAT for internal access
- Protocol selection (TCP/UDP/Both)
- Custom port translation
- Automatic firewall integration

### Can I run multiple DHCP servers on different interfaces?
Yes! Each interface (including VLANs) can have its own DHCP scope. Configure via **Network** → **DHCP Server**.

---

## Security Features

### How does authentication work?
- **Password Hashing**: Bcrypt with automatic migration from legacy SHA-256
- **Session Tokens**: Secure 7-day tokens with automatic renewal
- **CSRF Protection**: Required for all state-changing operations
- **Rate Limiting**: Prevents brute force attacks (10 login attempts/minute)

### What is the audit log?
The audit log tracks all security-sensitive operations:
- Firewall changes
- Credential updates
- Configuration changes
- Session activity
- Backup/restore operations

Access via **Settings** → **Audit Logs** or `/var/log/softrouter/audit.log`

### How do I enable WAN access to the web interface?
> ⚠️ **Security Warning**: Only enable if you understand the risks!

1. Go to **Settings** → **Access Control**
2. Enable "Allow WAN Access"
3. Set custom ports (default: HTTP 980, HTTPS 9443)
4. Use strong credentials and enable HTTPS/TLS

**Recommended**: Use Cloudflare Tunnel or VPN instead of direct WAN exposure.

### Should I enable Suricata IDS/IPS?
Recommended for:
- ✅ Networks with advanced threat detection needs
- ✅ Systems with CPU headroom (Suricata uses 10-20% CPU)
- ✅ Compliance requirements (logging, intrusion detection)

Skip if:
- ❌ Low-powered hardware (Raspberry Pi, etc.)
- ❌ Very high-bandwidth connections (>1Gbps)

---

## VPN Configuration

### How do I create VPN clients?
1. Go to **VPN** → **WireGuard Clients**
2. Click **Add Client**
3. Enter a name (e.g., "phone", "laptop")
4. Download the `.conf` file
5. Import to WireGuard app on your device

### Where do VPN configs get stored?
Client configs: `/etc/softrouter/vpn_clients/`  
Server config: `/etc/wireguard/wg0.conf`

### Can I use OpenVPN instead of WireGuard?
WireGuard is the primary VPN solution. OpenVPN support is experimental and requires manual configuration.

---

## Ad-Blocking & DNS

### How do I set up AdGuard Home?
The installer can set up AdGuard Home automatically. If you need to configure manually:

1. Visit `http://<ROUTER_IP>:3000`
2. Complete AdGuard Home setup wizard
3. In SoftRouter **Settings** → **AdGuard Integration**:
   - URL: `http://localhost:3000`
   - Enter your AdGuard credentials
   - Click Save

### Can I use Pi-hole instead?
Yes! Either choose Pi-hole during installation or install manually. Configure similarly to AdGuard Home.

### Why can't I install AdGuard/Pi-hole?
**Port 53 conflict** - Ubuntu's systemd-resolved uses port 53 by default. Run:
```bash
echo -e "[Resolve]\nDNSStubListener=no" | sudo tee /etc/systemd/resolved.conf.d/softrouter.conf
sudo systemctl restart systemd-resolved
```

Or let the installer handle this automatically.

---

## Backup & Restore

### What gets backed up?
- Configuration files (`config.json`)
- Interface labels and metadata
- Port forwarding rules
- DHCP configurations
- Policy-based routing rules
- User credentials

**Note**: Firewall rules live in nftables kernel space - they persist automatically.

### How do I create a backup?
**Via Web UI**: Settings → Backup & Restore → Create Backup

**Via CLI**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost/api/backup/create > backup-$(date +%Y%m%d).json
```

### How do I restore from backup?
1. Go to **Settings** → **Backup & Restore**
2. Click **Upload Backup**
3. Select your backup file
4. Click **Restore**

SoftRouter automatically creates a pre-restore backup for safety.

---

## Updates & Maintenance

### How do I update SoftRouter?
```bash
cd /path/to/SoftwareRouter
sudo ./update.sh
```

The update script:
- Backs up configs automatically
- Pulls latest code
- Rebuilds backend/frontend
- Restores your settings
- Restarts the service

### Do updates wipe my configuration?
No! The update script preserves:
- All configuration files
- Interface labels
- Firewall rules
- Port forwarding
- DHCP settings

### Can I roll back an update?
Yes! Backups are stored in `/tmp/softrouter-backup-*` during updates. You can:
1. Restore from backup via web UI
2. Manually copy files from backup directory
3. Use git to revert code: `git checkout <previous-commit>`

---

## Performance & Optimization

### What's the expected throughput?
Depends on enabled features:
- **Routing only**: Near line rate (1-10 Gbps)
- **With firewall**: 1-5 Gbps
- **With IDS/IPS**: 500 Mbps - 2 Gbps (Suricata is CPU-intensive)
**Note**: much of the speed depends on the hardware

### How do I optimize for gigabit speeds?
1. Disable Suricata if not needed
2. Use hardware offloading where available
3. Consider multi-core CPU for traffic processing
4. Optimize nftables rules (specific matches before general)

### Does SoftRouter support IPv6?
Yes! IPv6 is fully supported for:
- Interface configuration
- Firewall rules
- DHCP (via DHCPv6)
- Port forwarding

---

## Development & Customization

### How do I run in development mode?
**Backend**:
```bash
cd backend
sudo go run *.go
```

**Frontend**:
```bash
cd frontend
npm install
npm run dev -- --host
```

### Can I customize the UI?
Yes! The frontend is React + Vite. Source files are in `frontend/src/`. After changes:
```bash
cd frontend
npm run build
```

### Where are the API endpoints defined?
All HTTP routes are defined in `backend/main.go`. Handler functions are organized across:
- `auth_handlers.go` - Authentication
- `config_handlers.go` - Configuration
- `interface_handlers.go` - Network interfaces
- `vpn_handlers.go` - VPN management
- `main.go` - Core routing and utilities

---

## Common Issues

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed solutions to common problems.

### Quick fixes:
- **Can't login**: Check credentials in `/etc/softrouter/user_credentials.json`
- **Service won't start**: `sudo journalctl -u softrouter-backend -n 50`
- **Port 53 conflict**: Disable systemd-resolved stub listener
- **Build fails**: Run `go mod tidy` in backend directory

---

## Getting Help

- **GitHub Issues**: https://github.com/timmyd2434/SoftwareRouter/issues
- **Documentation**: Check `/docs` directory
- **Logs**: `/var/log/softrouter/` and `journalctl -u softrouter-backend`

---

## Contributing

SoftRouter is open source! Contributions welcome:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

See [SECURITY.md](SECURITY.md) for security-related contributions.
