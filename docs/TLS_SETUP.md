# HTTPS/TLS Setup Guide for SoftRouter

## Overview

SoftRouter **automatically enables HTTPS** on every installation. A self-signed TLS certificate is generated during the install process, and the backend serves exclusively over HTTPS on port 443.

> **Note**: Browsers will display a "Your connection is not private" warning for the self-signed certificate. This is normal and safe for your local network. Accept the warning to proceed.

## Default TLS Configuration

| Setting | Value |
|---------|-------|
| Certificate | `/etc/softrouter/tls/cert.pem` |
| Private Key | `/etc/softrouter/tls/key.pem` |
| HTTPS Port (LAN) | 443 |
| HTTPS Port (WAN) | 9443 |
| HTTP Port 80 | Redirect → HTTPS only |
| Validity | 10 years |
| Algorithm | ECDSA P-256 |

## Replacing with Let's Encrypt

To use a proper CA-signed certificate instead of the self-signed one:

### 1. Install Certbot

```bash
sudo apt update && sudo apt install certbot -y
```

### 2. Obtain Certificate

```bash
# Temporarily stop SoftRouter to free port 443
sudo systemctl stop softrouter

# Get certificate (replace with your domain)
sudo certbot certonly --standalone -d router.example.com

# Start SoftRouter again
sudo systemctl start softrouter
```

### 3. Replace Certificate Files

```bash
# Backup existing self-signed cert
sudo cp /etc/softrouter/tls/cert.pem /etc/softrouter/tls/cert.pem.bak
sudo cp /etc/softrouter/tls/key.pem /etc/softrouter/tls/key.pem.bak

# Link Let's Encrypt certs
sudo ln -sf /etc/letsencrypt/live/router.example.com/fullchain.pem /etc/softrouter/tls/cert.pem
sudo ln -sf /etc/letsencrypt/live/router.example.com/privkey.pem /etc/softrouter/tls/key.pem

sudo systemctl restart softrouter
```

### 4. Auto-Renewal

Create renewal hook at `/etc/letsencrypt/renewal-hooks/deploy/reload-softrouter.sh`:

```bash
#!/bin/bash
systemctl restart softrouter
```

```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-softrouter.sh
sudo certbot renew --dry-run  # Test renewal
```

## Replacing with a Custom Certificate

Place your certificate and key files at:
- `/etc/softrouter/tls/cert.pem` (full chain)
- `/etc/softrouter/tls/key.pem` (private key, `chmod 600`)

Then restart: `sudo systemctl restart softrouter`

## Troubleshooting

### Certificate Warning in Browser
**Expected behavior** with self-signed certificates. Click "Advanced" → "Proceed" to accept.

### Permission Denied
```bash
sudo chmod 644 /etc/softrouter/tls/cert.pem
sudo chmod 600 /etc/softrouter/tls/key.pem
```

### Auto-Generated Certificate Missing SANs
If you change the server's IP address, delete the old cert to regenerate:
```bash
sudo rm /etc/softrouter/tls/cert.pem /etc/softrouter/tls/key.pem
sudo systemctl restart softrouter  # Will auto-generate new cert with current IP
```
