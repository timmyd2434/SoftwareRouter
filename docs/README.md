# SoftRouter Documentation Index

Welcome to the SoftRouter documentation! This directory contains guides and references for installation, configuration, security, and troubleshooting.

---

## 📚 Core Documentation

### [Main README](../README.md)
Complete overview of SoftRouter features, installation, and quick start guide.
- Features overview
- Installation instructions
- Post-installation configuration
- Project structure

### [FAQ - Frequently Asked Questions](FAQ.md)
Answers to common questions about SoftRouter.
- Installation & Setup
- Network Configuration
- Security Features  
- VPN Configuration
- Ad-Blocking & DNS
- Backup & Restore
- Updates & Maintenance

### [Troubleshooting Guide](TROUBLESHOOTING.md)
Step-by-step solutions for common issues.
- Authentication problems
- Network issues
- Configuration problems
- Performance optimization
- Build & update errors

---

## 🔒 Security Documentation

### [SECURITY.md](../SECURITY.md)
Security features, best practices, and vulnerability reporting.
- Security architecture
- Audit logging
- Session management
- Vulnerability disclosure

---

## 📖 Setup Guides

### [HTTPS/TLS Setup](HTTPS_SETUP.md)
Configure SSL/TLS encryption for secure web access.
- Self-signed certificates
- Let's Encrypt integration
- Certificate management

### [TLS Setup](TLS_SETUP.md)
Additional TLS configuration and advanced options.

### [Fail2Ban Setup](FAIL2BAN_SETUP.md)
Configure brute-force protection and IP banning.
- Installation
- Configuration
- Integration with SoftRouter

---

## 🔄 Update & Maintenance

### [Update Guide](../README_UPDATE.md)
How to update SoftRouter while preserving configuration.
- Automatic updates via script
- Manual update process
- Troubleshooting updates
- Backup & restore during updates

---

## 🏗️ For Developers

### [Frontend README](../frontend/README.md)
Frontend development setup and architecture.
- React + Vite stack
- Development server
- Build process

### Backend Reference
Backend code is organized in modular handlers:
- `auth_handlers.go` - Authentication & security
- `config_handlers.go` - Configuration management
- `interface_handlers.go` - Network interfaces & VLANs
- `vpn_handlers.go` - VPN client management
- `main.go` - Core server & routing

---

## 🆘 Quick Help

**Can't access web interface?**
→ See [Troubleshooting Guide](TROUBLESHOOTING.md#web-interface-not-loading)

**Installation failed?**
→ See [FAQ - Installation](FAQ.md#installation--setup)

**Forgot password?**
→ See [Troubleshooting Guide](TROUBLESHOOTING.md#cannot-login--authentication-fails)

**Port 53 conflict?**
→ See [Troubleshooting Guide](TROUBLESHOOTING.md#port-53-conflict-dns)

---

## 📝 Contributing to Documentation

Found an issue or want to improve the docs?

1. Fork the repository
2. Edit markdown files in `/docs`
3. Submit a pull request

### Documentation Standards
- Use clear, concise language
- Include code examples where relevant
- Add cross-references to related docs
- Test all commands before documenting

---

## 🔗 External Resources

- **GitHub Repository**: https://github.com/timmyd2434/SoftwareRouter
- **Issue Tracker**: https://github.com/timmyd2434/SoftwareRouter/issues
- **Releases**: https://github.com/timmyd2434/SoftwareRouter/releases

---

## 📊 Documentation Coverage

| Topic | Documentation | Status |
|-------|---------------|--------|
| Installation | README.md, FAQ.md | ✅ Complete |
| Configuration | README.md, FAQ.md | ✅ Complete |
| Security | SECURITY.md, FAQ.md | ✅ Complete |
| HTTPS/TLS | HTTPS_SETUP.md, TLS_SETUP.md | ✅ Complete |
| Troubleshooting | TROUBLESHOOTING.md | ✅ Complete |
| Updates | README_UPDATE.md | ✅ Complete |
| Network Setup | FAQ.md, TROUBLESHOOTING.md | ✅ Complete |
| VPN | FAQ.md | ✅ Complete |
| Development | frontend/README.md | ✅ Complete |
| Fail2Ban | FAIL2BAN_SETUP.md | ✅ Complete |

---

**Last Updated**: February 2026  
**Version**: Current (Dev branch)
