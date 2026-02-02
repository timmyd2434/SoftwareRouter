# HTTPS/TLS Setup for SoftwareRouter

## Overview

SoftwareRouter now supports native HTTPS/TLS encryption alongside your existing nginx proxy manager setup. This provides defense-in-depth security and allows direct HTTPS access to your router.

## Quick Start

### Option 1: Self-Signed Certificate (Testing/Local)

**Generate Certificate:**
```bash
sudo mkdir -p /etc/softrouter/tls
sudo openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/softrouter/tls/key.pem \
  -out /etc/softrouter/tls/cert.pem \
  -days 365 \
  -subj "/C=US/ST=State/L=City/O=Home/CN=router.local"
```

**Enable TLS in Config:**
```bash
sudo nano /etc/softrouter/config.json
```

Set:
```json
{
  "tls": {
    "enabled": true,
    "cert_file": "/etc/softrouter/tls/cert.pem",
    "key_file": "/etc/softrouter/tls/key.pem",
    "port": ":443"
  }
}
```

**Restart Service:**
```bash
sudo systemctl restart softrouter
```

Access: `https://your-router-ip` (accept self-signed certificate warning)

---

### Option 2: Let's Encrypt (Production)

**Install Certbot:**
```bash
sudo apt install certbot
```

**Obtain Certificate:**
```bash
sudo certbot certonly --standalone -d router.yourdomain.com
```

**Update Config:**
```json
{
  "tls": {
    "enabled": true,
    "cert_file": "/etc/letsencrypt/live/router.yourdomain.com/fullchain.pem",
    "key_file": "/etc/letsencrypt/live/router.yourdomain.com/privkey.pem",
    "port": ":443"
  }
}
```

**Auto-Renewal:**
```bash
sudo crontab -e
```

Add:
```
0 3 * * * certbot renew --quiet && systemctl restart softrouter
```

---

## Dual Mode (HTTP + HTTPS)

When TLS is enabled:
- **HTTPS**: Listens on port 443 (configurable)
- **HTTP**: Automatically redirects to HTTPS (port 80)
- **Nginx Proxy**: Continue using for external access

---

## CORS Configuration

Update allowed origins for production:

```json
{
  "cors": {
    "allowed_origins": [
      "https://router.yourdomain.com",
      "http://localhost:5173"
    ]
  }
}
```

---

## Security Notes

1. **Certificate Permissions:**
   ```bash
   sudo chmod 600 /etc/softrouter/tls/key.pem
   sudo chmod 644 /etc/softrouter/tls/cert.pem
   ```

2. **Firewall Rules:**
   ```bash
   sudo nft add rule inet filter input tcp dport 443 accept comment "Allow HTTPS"
   ```

3. **Test Configuration:**
   ```bash
   # Check certificate
   openssl x509 -in /etc/softrouter/tls/cert.pem -text -noout
   
   # Test HTTPS
   curl -k https://localhost
   ```

---

## Troubleshooting

**TLS Not Starting:**
- Check logs: `sudo journalctl -u softrouter -f`
- Verify cert files exist and have correct permissions
- Ensure port 443 not in use: `sudo lsof -i :443`

**HTTP Still Works:**
- This is normal behavior
- HTTP redirects to HTTPS automatically when TLS enabled

**Certificate Errors:**
- Ensure certificate Common Name matches your hostname
- Check certificate expiry: `openssl x509 -enddate -noout -in cert.pem`

---

## Disabling TLS

Set in config.json:
```json
{
  "tls": {
    "enabled": false
  }
}
```

Restart service:
```bash
sudo systemctl restart softrouter
```
