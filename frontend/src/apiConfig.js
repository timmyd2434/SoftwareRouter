// frontend/src/apiConfig.js

// This helper automatically determines the backend API URL.
// If you are accessing the UI via http://192.168.1.50:5173, 
// it will set the API base to http://192.168.1.50:8080.

const getApiBaseUrl = () => {
    if (typeof window !== 'undefined') {
        const hostname = window.location.hostname;
        const port = window.location.port;

        // If we are running on port 5173 (Vite dev), use the backend port 80/8080
        // Otherwise, use the same port as the UI (for production)
        if (port === '5173') {
            return `http://${hostname}:80`;
        }

        // Return blank for relative paths or current origin
        return `${window.location.protocol}//${window.location.host}`;
    }
    return 'http://localhost:80';
};

export const API_BASE_URL = getApiBaseUrl();

export const authFetch = async (url, options = {}) => {
    const token = localStorage.getItem('sr_token');
    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
    };

    const response = await fetch(url, { ...options, headers });

    if (response.status === 401) {
        localStorage.removeItem('sr_token');
        localStorage.removeItem('sr_user');
        window.location.reload(); // Force redirect to login
    }

    return response;
};

export const API_ENDPOINTS = {
    LOGIN: `${API_BASE_URL}/api/login`,
    UPDATE_CREDS: `${API_BASE_URL}/api/auth/update-credentials`,
    CONFIG: `${API_BASE_URL}/api/config`,
    STATUS: `${API_BASE_URL}/api/status`,
    INTERFACES: `${API_BASE_URL}/api/interfaces`,
    INTERFACE_STATE: `${API_BASE_URL}/api/interfaces/state`,
    INTERFACE_IP: `${API_BASE_URL}/api/interfaces/ip`,
    INTERFACE_VLAN: `${API_BASE_URL}/api/interfaces/vlan`,
    INTERFACE_METADATA: `${API_BASE_URL}/api/interfaces/metadata`,
    INTERFACE_LABEL: `${API_BASE_URL}/api/interfaces/label`,
    FIREWALL: `${API_BASE_URL}/api/firewall`,
    SERVICES: `${API_BASE_URL}/api/services`,
    SERVICES_CONTROL: `${API_BASE_URL}/api/services/control`,
    TRAFFIC_STATS: `${API_BASE_URL}/api/traffic/stats`,
    TRAFFIC_HISTORY: `${API_BASE_URL}/api/traffic/history`,
    TRAFFIC_CONNECTIONS: `${API_BASE_URL}/api/traffic/connections`,
    SECURITY_ALERTS: `${API_BASE_URL}/api/security/suricata/alerts`,
    SECURITY_DECISIONS: `${API_BASE_URL}/api/security/crowdsec/decisions`,
    SECURITY_STATS: `${API_BASE_URL}/api/security/stats`,
    VPN_CLIENTS: `${API_BASE_URL}/api/vpn/clients`,
    VPN_DOWNLOAD: `${API_BASE_URL}/api/vpn/download`,
    DNS_STATS: `${API_BASE_URL}/api/dns/stats`,
    DHCP_CONFIG: `${API_BASE_URL}/api/dhcp/config`,
    DHCP_LEASES: `${API_BASE_URL}/api/dhcp/leases`,
    VPN_CLIENT_STATUS: `${API_BASE_URL}/api/vpn/client/status`,
    VPN_CLIENT_CONFIG: `${API_BASE_URL}/api/vpn/client/config`,
    VPN_CLIENT_CONTROL: `${API_BASE_URL}/api/vpn/client/control`,
    VPN_CLIENT_POLICIES: `${API_BASE_URL}/api/vpn/client/policies`,
    OVPN_SERVER_STATUS: `${API_BASE_URL}/api/vpn/server-openvpn/status`,
    OVPN_SERVER_SETUP: `${API_BASE_URL}/api/vpn/server-openvpn/setup`,
    OVPN_SERVER_CLIENTS: `${API_BASE_URL}/api/vpn/server-openvpn/clients`,
    OVPN_SERVER_DOWNLOAD: `${API_BASE_URL}/api/vpn/server-openvpn/download`,
    SETTINGS: `${API_BASE_URL}/api/settings`,
};

