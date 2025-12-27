# SoftRouter - Web-Based Software Router

A modern, feature-rich web-based router management interface built with React (frontend) and Go (backend) for Debian-based Linux systems.

## 🌟 Features

### ✅ Firewall Management (NFTables)
- **Full CRUD operations** for firewall rules
- **Human-readable rule display** - automatically parses complex NFTables JSON into readable format
- **Add/Edit/Delete rules** with real-time validation
- **Live rule status** from `nft -j list ruleset`
- **Status log** in modal for debugging rule submission
- Intelligent default selection for Family/Table/Chain

### ✅ Network Interface Management
- **VLAN Creation & Deletion** - Create VLANs on any physical interface (e.g., eth0.10, eth0.20)
- **IP Address Configuration** - Add/remove IP addresses with CIDR notation
- **Interface State Control** - Bring interfaces up/down
- **Interface Labeling** - Label interfaces as WAN, LAN, DMZ, Guest, Management, or Trunk
- **Color-coded labels** with optional descriptions
- **Physical and VLAN separation** - Organized display of interface types
- **Real-time status** - Live MAC, MTU, and IP address display

### ✅ System Services Management
- **Start/Stop/Restart** systemd services (dnsmasq, WireGuard, etc.)
- **Real-time status updates** - Auto-refresh every 10 seconds
- **Service version detection**
- **Loading indicators** during service operations
- **Error handling** with helpful debug suggestions

### ✅ Dashboard
- **System status overview**
- **Network statistics**
- **Quick access** to all features

## 📋 Requirements

### System Requirements
- **Operating System**: Debian-based Linux (Debian, Ubuntu, etc.)
- **Privileges**: Root/sudo access for network operations
- **Network Tools**:
  - `nftables` - For firewall management
  - `iproute2` - For interface/VLAN/IP management
  - `systemd` - For service management

### Software Dependencies

**Backend (Go)**:
- Go 1.21 or higher
- Standard library packages (no external dependencies)

**Frontend (React + Vite)**:
- Node.js 18+ and npm
- React 18.3
- React Router 7
- Lucide React (icons)
- Vite (development server)

## 🚀 Installation

### Simplified Setup (Recommended)
The easiest way to get started on a new machine or headless server is to use the master installation script:

```bash
cd /home/tim/Documents/SoftwareRouter
sudo ./install.sh
```
This script handles all system dependencies, frontend packages, and backend compilation.

### Manual Installation (Optional)

#### 1. Install System Dependencies

```bash
# Update package list
sudo apt update

# Install required tools
sudo apt install -y nftables iproute2 golang-go nodejs npm

# Verify installations
nft --version
ip -V
go version
node --version
```

### 2. Clone/Setup Project

```bash
cd /home/tim/Documents/SoftwareRouter
```

### 3. Setup Frontend

```bash
cd frontend
npm install
```

### 4. Setup Backend

The backend uses Go standard library only - no additional dependencies needed.

```bash
cd backend
# Test compilation
go build main.go
```

## ⚙️ Configuration

### Backend Configuration

The backend requires **sudo privileges** to execute system commands. You have two options:

#### Option 1: Run with sudo password (Current Setup)
```bash
cd backend
echo "YOUR_SUDO_PASSWORD" | sudo -S go run main.go >> backend.log 2>&1 &
```

#### Option 2: Configure Passwordless Sudo (Recommended for Production)

Create a sudoers rule for specific commands:

```bash
sudo visudo -f /etc/sudoers.d/softrouter
```

Add these lines (replace `tim` with your username):
```
tim ALL=(ALL) NOPASSWD: /usr/sbin/nft
tim ALL=(ALL) NOPASSWD: /usr/sbin/ip
tim ALL=(ALL) NOPASSWD: /usr/bin/systemctl
```

Then run backend without password:
```bash
sudo go run main.go >> backend.log 2>&1 &
```

### Frontend Configuration

The frontend is configured to connect to `localhost:8080` for the backend API. If you need to change this:

1. Edit API endpoints in each page component (Dashboard.jsx, Firewall.jsx, etc.)
2. Change `http://localhost:8080` to your backend URL

### CORS Configuration

**Development**: CORS is set to allow all origins (`*`)  
**Production**: Update `enableCORS()` in `backend/main.go` to restrict origins:

```go
w.Header().Set("Access-Control-Allow-Origin", "https://yourdomain.com")
```

## 🎯 Usage

### Starting the Application

**Terminal 1 - Backend:**
```bash
cd backend
echo "09_SEPT_1982td" | sudo -S go run main.go >> backend.log 2>&1 &

# Monitor logs
tail -f backend.log
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev -- --host
```

**Access the Web Interface:**
- Local: `http://localhost:5173`
- Network: `http://YOUR_IP:5173`

### Using Features

#### Creating a VLAN
1. Navigate to **Interfaces** page
2. Click **"Create VLAN"** button
3. Select parent interface (e.g., `eth0`)
4. Enter VLAN ID (1-4094)
5. Click **"Create VLAN"**
6. Result: `eth0.10` interface created

#### Configuring IP Address/Subnet
1. On any interface card, click **"IP"** button
2. Select **"Add IP Address"**
3. Enter IP with CIDR notation: `192.168.10.1/24`
4. Click **"Apply"**

#### Labeling Interfaces
1. Click **"Label"** button on interface
2. Select label type (WAN, LAN, DMZ, etc.)
3. Optional: Add description
4. Click **"Set Label"**

#### Managing Firewall Rules
1. Navigate to **Firewall** page
2. Click **"Add Rule"** button
3. Select Family, Table, and Chain
4. Enter rule statement (e.g., `tcp dport 8080 accept`)
5. Click **"CONFIRM ADD"**

#### Managing Services
1. Navigate to **Settings** page
2. Click **Start/Stop/Restart** buttons on service cards

## 📁 Project Structure

```
SoftwareRouter/
├── backend/
│   ├── main.go              # Go backend server
│   └── backend.log          # Backend logs
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   └── layout/      # Sidebar, MainLayout
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Interfaces.jsx
│   │   │   ├── Firewall.jsx
│   │   │   └── Services.jsx
│   │   ├── App.jsx
│   │   └── index.css        # Global styles
│   ├── package.json
│   └── vite.config.js
└── README.md
```

## 🔒 Security Considerations

### ⚠️ Important Security Notes

1. **Sudo Access**: The backend requires root privileges to modify network configuration and firewall rules.
   - **Testing**: Running with sudo password is acceptable
   - **Production**: Use passwordless sudo with specific command whitelisting

2. **CORS**: Currently set to allow all origins (`*`)
   - **Development**: This is fine
   - **Production**: Restrict to your domain only

3. **Authentication**: 
   - **Current**: No authentication implemented
   - **Production**: Implement authentication/authorization before deploying

4. **Firewall Rule Validation**: The backend performs basic validation but accepts raw `nft` commands
   - Be careful with rule syntax
   - Test rules in a safe environment first

5. **Network Access**: 
   - Backend runs on `:8080`
   - Frontend runs on `:5173`
   - Consider firewall rules to restrict access

## 🐛 Troubleshooting

### Backend Issues

**"Permission denied" errors:**
- Ensure backend is running with sudo
- Check sudoers configuration for passwordless sudo

**NFTables errors:**
```bash
# Check if nft Tables are initialized
sudo nft list ruleset

# If empty, create basic structure
sudo nft add table inet filter
sudo nft add chain inet filter INPUT
```

**Service control failures:**
- Check if service exists: `systemctl status dnsmasq`
- View service logs: `sudo journalctl -xeu dnsmasq`

### Frontend Issues

**"Network Error" or "Failed to fetch":**
- Ensure backend is running on port 8080
- Check browser console for CORS errors
- Verify backend logs for errors

**Interfaces not showing:**
- Backend needs root access to read interface info
- Check that backend is running with sudo

### DHCP/DNS Service Won't Start

This is normal in a laptop testing environment:
- **Reason**: Conflicts with NetworkManager or other network services
- **Solution**: For testing, use WireGuard or create minimal dnsmasq config
- **Production**: Disable conflicting services

## 📝 File Locations

### Data Storage
- **Interface Metadata**: `/tmp/router_interface_metadata.json`
  - Stores interface labels and descriptions
  - **Note**: `/tmp` is cleared on reboot
  - For persistent storage, move to `/etc/softrouter/` or similar

### Logs
- **Backend**: `backend/backend.log`
- **Systemd Services**: `journalctl -xeu <service-name>`
- **NFTables**: Check with `sudo nft list ruleset`

## 🔮 Known Limitations

1. **No Authentication**: Anyone with network access can control the router
2. **Temporary Metadata Storage**: Interface labels stored in `/tmp` (lost on reboot)
3. **IPv4 Focus**: IPv6 support exists but not extensively tested
4. **Basic Error Handling**: Some edge cases may not be handled gracefully
5. **No Rollback**: Changes to firewall/network are immediate with no undo

## 🚧 Future Enhancements

Potential features for future development:
- [ ] User authentication and authorization
- [ ] DHCP server configuration UI
- [ ] DNS server configuration UI
- [ ] Routing table management
- [ ] NAT/Masquerade configuration
- [ ] Traffic monitoring and graphs
- [ ] Configuration backup/restore
- [ ] Rule templates and presets
- [ ] Persistent interface metadata storage
- [ ] IPv6 firewall management
- [ ] WireGuard tunnel configuration UI
- [ ] System logs viewer

## 🤝 Contributing

This is a personal project, but suggestions and improvements are welcome!

## 📄 License

This project is for personal/educational use.

## ⚡ Quick Reference

### Default Ports
- **Frontend**: `http://localhost:5173`
- **Backend API**: `http://localhost:8080`

### Common Commands

**Start Backend:**
```bash
cd backend && echo "YOUR_PASSWORD" | sudo -S go run main.go >> backend.log 2>&1 &
```

**Start Frontend:**
```bash
cd frontend && npm run dev -- --host
```

**View Backend Logs:**
```bash
tail -f backend/backend.log
```

**Stop Backend:**
```bash
sudo kill -9 $(sudo lsof -t -i:8080)
```

**Check NFTables:**
```bash
sudo nft list ruleset
```

**Check Interfaces:**
```bash
ip addr show
```

---

**Built with ❤️ using React, Go, and modern web technologies**
