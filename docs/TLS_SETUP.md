# HTTPS/TLS Setup Guide for SoftRouter

## Overview
This guide explains how to secure your SoftRouter web interface with HTTPS using Let's Encrypt free SSL/TLS certificates.

## Prerequisites
- SoftRouter installation complete
- Domain name pointing to your router's public IP (required for Let's Encrypt)
- Ports 80 and 443 accessible from the internet (for certificate validation)

---

## Quick Setup with Let's Encrypt

### 1. Install Certbot

```bash
sudo apt update
sudo apt install certbot -y
```

### 2. Stop the SoftRouter Backend Temporarily

Since certbot needs to bind to port 80 for validation:

```bash
sudo systemctl stop softrouter
```

### 3. Obtain SSL Certificate

Replace `router.example.com` with your actual domain:

```bash
sudo certbot certonly --standalone -d router.example.com
```

Follow the prompts:
- Enter your email address (for renewal notifications)
- Agree to terms of service
- Optionally share your email with EFF

Certificates will be saved to:
- **Certificate**: `/etc/letsencrypt/live/router.example.com/fullchain.pem`
- **Private Key**: `/etc/letsencrypt/live/router.example.com/privkey.pem`

### 4. Configure SoftRouter for HTTPS

Create symbolic links for easy access:

```bash
sudo mkdir -p /etc/softrouter/tls
sudo ln -s /etc/letsencrypt/live/router.example.com/fullchain.pem /etc/softrouter/tls/cert.pem
sudo ln -s /etc/letsencrypt/live/router.example.com/privkey.pem /etc/softrouter/tls/key.pem
```

### 5. Update Backend to Enable TLS

Edit `/usr/local/bin/softrouter-backend` or rebuild with TLS support enabled.

**For now**, you can use a reverse proxy (Nginx/Caddy) to handle TLS:

```bash
sudo apt install nginx -y
```

Create Nginx config `/etc/nginx/sites-available/softrouter`:

```nginx
server {
    listen 443 ssl http2;
    server_name router.example.com;

    ssl_certificate /etc/softrouter/tls/cert.pem;
    ssl_certificate_key /etc/softrouter/tls/key.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    # TLS Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;

    # Proxy to SoftRouter backend
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name router.example.com;
    return 301 https://$server_name$request_uri;
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/softrouter /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl restart softrouter
```

### 6. Test Your HTTPS Setup

Visit `https://router.example.com` and verify:
- ✅ Green padlock in browser
- ✅ Certificate is valid
- ✅ HTTP redirects to HTTPS

---

## Automatic Certificate Renewal

Let's Encrypt certificates expire every 90 days. Set up automatic renewal:

### Create Renewal Hook

Create `/etc/letsencrypt/renewal-hooks/deploy/reload-softrouter.sh`:

```bash
#!/bin/bash
# Reload Nginx after certificate renewal
systemctl reload nginx
```

Make it executable:

```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-softrouter.sh
```

### Test Renewal

```bash
sudo certbot renew --dry-run
```

### Automatic Renewal (Already Configured)

Certbot installs a systemd timer that runs twice daily. Check status:

```bash
sudo systemctl status certbot.timer
```

---

## Alternative: Self-Signed Certificate (Local/Testing)

For internal networks where Let's Encrypt is not feasible:

### Generate Self-Signed Certificate

```bash
sudo mkdir -p /etc/softrouter/tls
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/softrouter/tls/key.pem \
  -out /etc/softrouter/tls/cert.pem \
  -subj "/C=US/ST=State/L=City/O=SoftRouter/CN=router.local"
```

⚠️ **Warning**: Browsers will show security warnings for self-signed certificates. You must manually accept them.

---

## Firewall Configuration

Allow HTTPS traffic through your firewall:

```bash
sudo nft add rule inet filter input tcp dport 443 accept comment "\"Allow HTTPS\""
```

If using external access, ensure your ISP router forwards port 443 to your SoftRouter's LAN IP.

---

## Security Best Practices

1. **Disable TLS 1.0 and 1.1** (already done in Nginx config)
2. **Use Strong Ciphers** (configured above)
3. **Enable HSTS** (configured above - forces HTTPS)
4. **Monitor Certificate Expiration**: Check `/var/log/letsencrypt/letsencrypt.log`
5. **Restrict Access**: Consider using firewall rules to limit HTTPS access to specific IP ranges

### IP-Based Access Restriction (Optional)

In Nginx config, add:

```nginx
# Only allow access from local network
allow 192.168.1.0/24;
deny all;
```

---

## Troubleshooting

### Certificate Validation Fails

**Error**: `Failed to connect to host for ACME validation`

**Solution**:
- Ensure port 80 is open on your firewall
- Verify DNS A record points to the correct public IP: `dig router.example.com`
- Check ISP port forwarding rules

### Permission Denied Reading Certificate

**Error**: `Permission denied: /etc/letsencrypt/live/...`

**Solution**:
```bash
sudo chown -R root:root /etc/letsencrypt
sudo chmod -R 755 /etc/letsencrypt/live
sudo chmod -R 755 /etc/letsencrypt/archive
```

### Nginx Won't Start

**Check logs**:
```bash
sudo journalctl -xeu nginx
sudo nginx -t  # Test configuration
```

---

## Next Steps

- Configure automatic backups of `/etc/letsencrypt`
- Set up monitoring for certificate expiration
- Review TLS configuration with tools like [SSL Labs](https://www.ssllabs.com/ssltest/)

---

**Related Documentation**:
- [Fail2Ban Setup](./FAIL2BAN_SETUP.md)
- [Main Security Guide](../SECURITY.md)
