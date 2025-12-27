#!/bin/bash
# SoftRouter - Master Installation Script
# Designed for Debian/Ubuntu headless servers

set -e

# Colors for output
RED='\033[0-1;31m'
GREEN='\033[0-2;32m'
BLUE='\033[0-4;34m'
NC='\033[0m'

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}    SoftRouter System Installation       ${NC}"
echo -e "${BLUE}=========================================${NC}"

# 1. Check for root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# 2. Update and Install System Dependencies
echo -e "${GREEN}[1/5] Installing System Dependencies...${NC}"
apt update
apt install -y curl git golang-go nftables iproute2 systemd

# Check if Node.js is installed, if not install LTS
if ! command -v node &> /dev/null; then
    echo -e "${GREEN}Installing Node.js via NodeSource...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

# 3. Setup Frontend
echo -e "${GREEN}[2/5] Setting up Frontend...${NC}"
cd frontend
if [ -f "package.json" ]; then
    npm install
else
    echo -e "${RED}Error: frontend/package.json not found!${NC}"
    exit 1
fi
cd ..

# 4. Setup Backend
echo -e "${GREEN}[3/5] Setting up Backend...${NC}"
cd backend
if [ -f "main.go" ]; then
    go build -o softrouter-backend main.go
    echo -e "${GREEN}Backend binary compiled successfully.${NC}"
else
    echo -e "${RED}Error: backend/main.go not found!${NC}"
    exit 1
fi
cd ..

# 5. Setup Administrative Access
echo -e "${GREEN}[4/5] Configuring Administrative Access...${NC}"
mkdir -p /etc/softrouter

if [ ! -f "/etc/softrouter/user_credentials.json" ]; then
    echo -e "${BLUE}Please set up your initial administrative credentials:${NC}"
    read -p "Username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    # Securely read password
    read -sp "Password: " ADMIN_PASS
    echo ""
    read -sp "Confirm Password: " ADMIN_PASS_CONFIRM
    echo ""
    
    if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
        echo -e "${RED}Error: Passwords do not match. Manual configuration required.${NC}"
        # We'll create a dummy but locked config
        echo '{"username":"admin","password":""}' > /etc/softrouter/user_credentials.json
    else
        # Hash the password using SHA256 (compatible with Go backend)
        HASHED_PASS=$(echo -n "$ADMIN_PASS" | sha256sum | awk '{print $1}')
        echo "{\"username\":\"$ADMIN_USER\",\"password\":\"$HASHED_PASS\"}" > /etc/softrouter/user_credentials.json
        echo -e "${GREEN}Credentials set successfully.${NC}"
    fi
else
    echo -e "Credentials already exist, skipping setup."
fi

# 6. Generate Secret Key for API Security
if [ ! -f "/etc/softrouter/token_secret.key" ]; then
    echo -e "${GREEN}Generating secure token secret...${NC}"
    head -c 32 /dev/urandom | base64 > /etc/softrouter/token_secret.key
    chmod 600 /etc/softrouter/token_secret.key
fi

# 7. Set Permissions
echo -e "${GREEN}[5/5] Configuring Script Permissions...${NC}"
chmod +x install-security.sh
chmod +x github-upload-guide.sh
chmod +x PUSH-TO-GITHUB.sh

# 6. Final Instructions
echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}✅ SoftRouter Installation Complete!${NC}"
echo -e "${BLUE}=========================================${NC}"
echo -e "To start the application on your headless server:"
echo ""
echo -e "${BLUE}Terminal 1 (Backend):${NC}"
echo -e "  cd backend && sudo ./softrouter-backend"
echo ""
echo -e "${BLUE}Terminal 2 (Frontend):${NC}"
echo -e "  cd frontend && npm run dev -- --host"
echo ""
echo -e "Access the UI via: ${GREEN}http://<SERVER_IP>:5173${NC}"
echo -e "-----------------------------------------"
echo -e "If you want to install IDS/IPS (Suricata/CrowdSec):"
echo -e "  sudo ./install-security.sh"
echo -e "${BLUE}=========================================${NC}"
