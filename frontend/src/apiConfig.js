// frontend/src/apiConfig.js

// This helper automatically determines the backend API URL.
// If you are accessing the UI via http://192.168.1.50:5173, 
// it will set the API base to http://192.168.1.50:8080.

const getApiBaseUrl = () => {
    // Check if we are in a browser environment
    if (typeof window !== 'undefined') {
        const hostname = window.location.hostname;
        // Port 8080 is where our Go backend is running
        return `http://${hostname}:8080`;
    }
    // Fallback for non-browser environments
    return 'http://localhost:8080';
};

export const API_BASE_URL = getApiBaseUrl();
export const API_ENDPOINTS = {
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
    TRAFFIC_CONNECTIONS: `${API_BASE_URL}/api/traffic/connections`,
    SECURITY_ALERTS: `${API_BASE_URL}/api/security/suricata/alerts`,
    SECURITY_DECISIONS: `${API_BASE_URL}/api/security/crowdsec/decisions`,
    SECURITY_STATS: `${API_BASE_URL}/api/security/stats`,
};
