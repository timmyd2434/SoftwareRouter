import React, { useState, useEffect } from 'react';
import {
    Globe, Plus, Download, Trash2, Calendar, User, Shield,
    RefreshCw, AlertCircle, CheckCircle, Loader2, X, Copy,
    Upload, Power, Network, Lock
} from 'lucide-react';
import QRCode from 'react-qr-code';
import { API_ENDPOINTS, authFetch } from '../apiConfig';
import './RemoteAccess.css';

const RemoteAccess = () => {
    const [activeTab, setActiveTab] = useState('server');

    // --- Server (WireGuard) State ---
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [showQR, setShowQR] = useState(null);
    const [newClientName, setNewClientName] = useState('');
    const [message, setMessage] = useState({ type: '', text: '' });
    const [generating, setGenerating] = useState(false);

    // --- Client (OpenVPN/PIA) State ---
    const [clientStatus, setClientStatus] = useState({ connected: false, ip_address: '---', uptime: '---' });
    const [policies, setPolicies] = useState([]);
    const [configUpload, setConfigUpload] = useState({ username: '', password: '', file: null });
    const [newPolicyIP, setNewPolicyIP] = useState('');
    const [uploading, setUploading] = useState(false);
    const [refreshingClient, setRefreshingClient] = useState(false);

    // --- OpenVPN Server State ---
    const [ovpnStatus, setOvpnStatus] = useState({ installed: false, running: false, client_count: 0 });
    const [ovpnClients, setOvpnClients] = useState([]);
    const [loadingOvpn, setLoadingOvpn] = useState(false);
    const [newOvpnClientName, setNewOvpnClientName] = useState('');
    const [showOvpnModal, setShowOvpnModal] = useState(false);

    // --- VPN Endpoint Configuration State ---
    const [vpnEndpoint, setVpnEndpoint] = useState({ endpoint: '', endpoint_type: 'auto' });
    const [testingEndpoint, setTestingEndpoint] = useState(false);
    const [endpointResult, setEndpointResult] = useState(null);
    const [savingConfig, setSavingConfig] = useState(false);

    useEffect(() => {
        if (activeTab === 'server') {
            fetchClients();
        } else if (activeTab === 'openvpn-server') {
            fetchOvpnServerData();
        } else {
            fetchClientStatus();
            fetchPolicies();
            const interval = setInterval(fetchClientStatus, 5000);
            return () => clearInterval(interval);
        }
    }, [activeTab]);

    // --- OpenVPN Server Handlers ---
    const fetchOvpnServerData = async () => {
        setLoadingOvpn(true);
        try {
            const res = await authFetch(API_ENDPOINTS.OVPN_SERVER_STATUS);
            if (res.ok) {
                const status = await res.json();
                setOvpnStatus(status);
                if (status.installed) {
                    fetchOvpnClients();
                }
            }
        } catch (err) { console.error(err); }
        finally { setLoadingOvpn(false); }
    };

    const fetchOvpnClients = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.OVPN_SERVER_CLIENTS);
            if (res.ok) setOvpnClients(await res.json() || []);
        } catch (err) { console.error(err); }
    };

    const handleSetupOvpn = async () => {
        if (!confirm("This will initialize the PKI and generate certificates. It may take a minute. Continue?")) return;
        setLoadingOvpn(true);
        try {
            const res = await authFetch(API_ENDPOINTS.OVPN_SERVER_SETUP, { method: 'POST' });
            if (res.ok) {
                alert("OpenVPN Server Setup Complete!");
                fetchOvpnServerData();
            } else {
                alert("Setup Failed. Check logs.");
            }
        } catch (err) { alert("Network Error"); }
        finally { setLoadingOvpn(false); }
    };

    const handleAddOvpnClient = async (e) => {
        e.preventDefault();
        setGenerating(true);
        try {
            const res = await authFetch(API_ENDPOINTS.OVPN_SERVER_CLIENTS, {
                method: 'POST',
                body: JSON.stringify({ name: newOvpnClientName })
            });
            if (res.ok) {
                setShowOvpnModal(false);
                setNewOvpnClientName('');
                fetchOvpnClients();
                fetchOvpnServerData(); // Update count
                alert("Client Generated Successfully!");
            } else { alert("Failed to generate client"); }
        } catch (err) { alert("Error"); }
        finally { setGenerating(false); }
    };

    const handleRevokeOvpnClient = async (name) => {
        if (!confirm(`Revoke certificate for ${name}?`)) return;
        try {
            await authFetch(`${API_ENDPOINTS.OVPN_SERVER_CLIENTS}?name=${name}`, { method: 'DELETE' });
            fetchOvpnClients();
        } catch (err) { alert("Error revoking"); }
    };

    const handleDownloadOvpn = (name) => {
        const token = localStorage.getItem('sr_token');
        window.open(`${API_ENDPOINTS.OVPN_SERVER_DOWNLOAD}?name=${name}&token=${token}`, '_blank');
    };

    const handleTestEndpoint = async () => {
        setTestingEndpoint(true);
        setEndpointResult(null);
        try {
            const res = await authFetch('/api/vpn/endpoint');
            if (res.ok) {
                const data = await res.json();
                setEndpointResult(data);
            }
        } catch (err) {
            setEndpointResult({ success: false, error: 'Network error' });
        } finally {
            setTestingEndpoint(false);
        }
    };

    const handleSaveEndpointConfig = async () => {
        setSavingConfig(true);
        try {
            const configRes = await authFetch('/api/config');
            const config = await configRes.json();

            // Update VPN endpoint configuration
            config.vpn_server = {
                endpoint: vpnEndpoint.endpoint,
                endpoint_type: vpnEndpoint.endpoint_type,
                port: 1194,
                protocol: 'udp'
            };

            const res = await authFetch('/api/config', {
                method: 'POST',
                body: JSON.stringify(config)
            });

            if (res.ok) {
                alert('VPN endpoint configuration saved successfully!');
                handleTestEndpoint(); // Test the new configuration
            } else {
                alert('Failed to save configuration');
            }
        } catch (err) {
            alert('Error saving: ' + err.message);
        } finally {
            setSavingConfig(false);
        }
    };

    // Load current VPN endpoint configuration
    useEffect(() => {
        if (activeTab === 'openvpn-server') {
            authFetch('/api/config')
                .then(r => r.json())
                .then(config => {
                    if (config.vpn_server) {
                        setVpnEndpoint({
                            endpoint: config.vpn_server.endpoint || '',
                            endpoint_type: config.vpn_server.endpoint_type || 'auto'
                        });
                    }
                })
                .catch(err => console.error('Failed to load config:', err));
        }
    }, [activeTab]);

    // --- Server Handlers ---
    const fetchClients = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.VPN_CLIENTS);
            if (res.ok) setClients(await res.json() || []);
        } catch (err) { console.error(err); }
        finally { setLoading(false); }
    };

    const handleAddClient = async (e) => {
        e.preventDefault();
        setGenerating(true);
        setMessage({ type: '', text: '' });
        try {
            const res = await authFetch(API_ENDPOINTS.VPN_CLIENTS, {
                method: 'POST',
                body: JSON.stringify({ name: newClientName })
            });
            if (res.ok) {
                const result = await res.json();
                setMessage({ type: 'success', text: `Profile for ${newClientName} generated.` });
                setNewClientName('');
                setShowModal(false);
                setShowQR({ name: newClientName, config: result.config });
                fetchClients();
            } else {
                setMessage({ type: 'error', text: 'Failed to generate profile.' });
            }
        } catch (err) { setMessage({ type: 'error', text: 'Network error' }); }
        finally { setGenerating(false); }
    };

    const handleDeleteClient = async (name) => {
        if (!confirm(`Revoke access for ${name}?`)) return;
        try {
            const res = await authFetch(`${API_ENDPOINTS.VPN_CLIENTS}?name=${name}`, { method: 'DELETE' });
            if (res.ok) { fetchClients(); setMessage({ type: 'success', text: 'Access revoked.' }); }
        } catch (err) { setMessage({ type: 'error', text: 'Failed to delete.' }); }
    };

    const handleDownload = (name) => {
        const token = localStorage.getItem('sr_token');
        window.open(`${API_ENDPOINTS.VPN_DOWNLOAD}?name=${name}&token=${token}`, '_blank');
    };

    // --- Client Handlers ---
    const fetchClientStatus = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.VPN_CLIENT_STATUS);
            if (res.ok) setClientStatus(await res.json());
        } catch (err) { console.error(err); }
    };

    const fetchPolicies = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.VPN_CLIENT_POLICIES);
            if (res.ok) setPolicies(await res.json() || []);
        } catch (err) { console.error(err); }
    };

    const handleClientControl = async (action) => {
        setRefreshingClient(true);
        try {
            await authFetch(API_ENDPOINTS.VPN_CLIENT_CONTROL, {
                method: 'POST',
                body: JSON.stringify({ action })
            });
            setTimeout(fetchClientStatus, 2000); // Wait for service to react
        } catch (err) { alert('Action failed'); }
        finally { setRefreshingClient(false); }
    };

    const handleConfigUpload = async (e) => {
        e.preventDefault();
        if (!configUpload.file || !configUpload.username || !configUpload.password) {
            alert("Please fill in all fields");
            return;
        }

        setUploading(true);
        const formData = new FormData();
        formData.append('username', configUpload.username);
        formData.append('password', configUpload.password);
        formData.append('config', configUpload.file);

        try {
            const res = await authFetch(API_ENDPOINTS.VPN_CLIENT_CONFIG, {
                method: 'POST',
                // Don't set Content-Type, browser sets it for FormData
                headers: {},
                body: formData
            });
            if (res.ok) {
                alert("Configuration uploaded successfully!");
                setConfigUpload({ username: '', password: '', file: null });
            } else {
                alert("Upload failed.");
            }
        } catch (err) { alert("Upload error"); }
        finally { setUploading(false); }
    };

    const handleAddPolicy = async (e) => {
        e.preventDefault();
        try {
            const res = await authFetch(API_ENDPOINTS.VPN_CLIENT_POLICIES, {
                method: 'POST',
                body: JSON.stringify({ source_ip: newPolicyIP, description: 'Manual Rule' })
            });
            if (res.ok) {
                setPolicies(await res.json());
                setNewPolicyIP('');
            } else {
                alert("Failed to add policy (duplicate?)");
            }
        } catch (err) { alert("Error adding policy"); }
    };

    const handleDeletePolicy = async (ip) => {
        if (!confirm(`Remove routing rule for ${ip}?`)) return;
        try {
            const res = await authFetch(`${API_ENDPOINTS.VPN_CLIENT_POLICIES}?ip=${ip}`, { method: 'DELETE' });
            if (res.ok) setPolicies(await res.json());
        } catch (err) { alert("Error deleting policy"); }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        alert('Copied!');
    };

    return (
        <div className="vpn-container">
            <div className="section-header">
                <div>
                    <h2>Remote Access Hub 🌐</h2>
                    <span className="subtitle">Manage secure connections (Server & Client)</span>
                </div>
            </div>

            <div className="tabs-container">
                <button
                    className={`tab-btn ${activeTab === 'server' ? 'active' : ''}`}
                    onClick={() => setActiveTab('server')}
                >
                    <Shield size={18} /> WireGuard Server
                </button>
                <button
                    className={`tab-btn ${activeTab === 'openvpn-server' ? 'active' : ''}`}
                    onClick={() => setActiveTab('openvpn-server')}
                >
                    <Shield size={18} /> OpenVPN Server
                </button>
                <button
                    className={`tab-btn ${activeTab === 'client' ? 'active' : ''}`}
                    onClick={() => setActiveTab('client')}
                >
                    <Globe size={18} /> OpenVPN Client
                </button>
            </div>

            {message.text && (
                <div className={`status-banner ${message.type}`}>
                    {message.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
                    {message.text}
                </div>
            )}

            {activeTab === 'server' ? (
                // --- SERVER TAB CONTENT ---
                <div className="vpn-grid">
                    <div className="clients-section glass-panel">
                        <div className="card-header">
                            <h3>Connected Peers</h3>
                            <button className="sm-btn" onClick={() => setShowModal(true)}>
                                <Plus size={16} /> Add Peer
                            </button>
                        </div>

                        {loading ? <div className="loading-state"><Loader2 className="spin" /></div> :
                            clients.length === 0 ? (
                                <div className="empty-state">
                                    <Shield size={48} />
                                    <p>No active peers.</p>
                                </div>
                            ) : (
                                <div className="client-list">
                                    {clients.map(client => (
                                        <div key={client.name} className="client-item">
                                            <div className="client-info">
                                                <div className="client-avatar">{client.name.charAt(0).toUpperCase()}</div>
                                                <div className="client-details">
                                                    <strong>{client.name}</strong>
                                                    <span>{new Date(client.created_at).toLocaleDateString()}</span>
                                                </div>
                                            </div>
                                            <div className="client-actions">
                                                <button className="action-btn download" onClick={() => handleDownload(client.name)}><Download size={18} /></button>
                                                <button className="action-btn delete" onClick={() => handleDeleteClient(client.name)}><Trash2 size={18} /></button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                    </div>

                    <div className="vpn-info-section">
                        <div className="info-card glass-panel status-card">
                            <h3>Server Status</h3>
                            <div className="status-stats">
                                <div className="stat-row"><span>State</span><span className="badge online">Active</span></div>
                                <div className="stat-row"><span>Port</span><strong>51820 (UDP)</strong></div>
                            </div>
                        </div>
                    </div>
                </div>
            ) : activeTab === 'openvpn-server' ? (
                // --- OPENVPN SERVER TAB CONTENT ---
                <div className="vpn-grid">
                    {!ovpnStatus.installed ? (
                        <div className="empty-state glass-panel">
                            <Shield size={64} className="icon-blue" />
                            <h3>OpenVPN Server Setup</h3>
                            <p>Initialize the PKI (Public Key Infrastructure) and CA to start.</p>
                            <button className="primary-btn lg-btn" onClick={handleSetupOvpn} disabled={loadingOvpn}>
                                {loadingOvpn ? <Loader2 className="spin" /> : 'Initialize Server & PKI'}
                            </button>
                        </div>
                    ) : (
                        <>
                            <div className="clients-section glass-panel">
                                <div className="card-header">
                                    <h3>OpenVPN Clients</h3>
                                    <button className="sm-btn" onClick={() => setShowOvpnModal(true)}>
                                        <Plus size={16} /> New Client
                                    </button>
                                </div>

                                {ovpnClients.length === 0 ? (
                                    <div className="empty-state">
                                        <p>No certificates issued.</p>
                                    </div>
                                ) : (
                                    <div className="client-list">
                                        {ovpnClients.map(c => (
                                            <div key={c.name} className="client-item">
                                                <div className="client-info">
                                                    <div className="client-avatar">{c.name.charAt(0).toUpperCase()}</div>
                                                    <div className="client-details">
                                                        <strong>{c.name}</strong>
                                                        <span>Expires: {c.expires_at}</span>
                                                    </div>
                                                </div>
                                                <div className="client-actions">
                                                    <button className="action-btn download" onClick={() => handleDownloadOvpn(c.name)} title="Download .ovpn">
                                                        <Download size={18} />
                                                    </button>
                                                    <button className="action-btn delete" onClick={() => handleRevokeOvpnClient(c.name)} title="Revoke">
                                                        <Trash2 size={18} />
                                                    </button>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>

                            <div className="vpn-info-section">
                                <div className="info-card glass-panel status-card">
                                    <h3>Server Status</h3>
                                    <div className="status-stats">
                                        <div className="stat-row">
                                            <span>State</span>
                                            <span className={`badge ${ovpnStatus.running ? 'online' : 'offline'}`}>
                                                {ovpnStatus.running ? 'Running' : 'Stopped'}
                                            </span>
                                        </div>
                                        <div className="stat-row"><span>Port</span><strong>{ovpnStatus.port} ({ovpnStatus.protocol})</strong></div>
                                        <div className="stat-row"><span>Active Certs</span><strong>{ovpnStatus.client_count}</strong></div>
                                    </div>
                                </div>

                                {/* VPN Endpoint Configuration */}
                                <div className="info-card glass-panel">
                                    <h3>VPN Endpoint Configuration</h3>
                                    <div className="config-form">
                                        <div className="form-group">
                                            <label>Endpoint Type</label>
                                            <select
                                                value={vpnEndpoint.endpoint_type}
                                                onChange={e => setVpnEndpoint({ ...vpnEndpoint, endpoint_type: e.target.value })}
                                                className="form-select"
                                            >
                                                <option value="auto">Auto-detect (ifconfig.me)</option>
                                                <option value="ip">Static IP Address</option>
                                                <option value="hostname">Hostname/DDNS</option>
                                            </select>
                                        </div>

                                        {vpnEndpoint.endpoint_type !== 'auto' && (
                                            <div className="form-group">
                                                <label>
                                                    {vpnEndpoint.endpoint_type === 'ip' ? 'Static IP Address' : 'Hostname (DDNS)'}
                                                </label>
                                                <input
                                                    type="text"
                                                    placeholder={vpnEndpoint.endpoint_type === 'ip' ? '203.0.113.42' : 'vpn.example.com'}
                                                    value={vpnEndpoint.endpoint}
                                                    onChange={e => setVpnEndpoint({ ...vpnEndpoint, endpoint: e.target.value })}
                                                />
                                            </div>
                                        )}

                                        <div className="endpoint-actions">
                                            <button
                                                className="secondary-btn"
                                                onClick={handleTestEndpoint}
                                                disabled={testingEndpoint}
                                            >
                                                {testingEndpoint ? <Loader2 className="spin" size={14} /> : <RefreshCw size={14} />}
                                                Test Endpoint
                                            </button>
                                            <button
                                                className="primary-btn"
                                                onClick={handleSaveEndpointConfig}
                                                disabled={savingConfig}
                                            >
                                                {savingConfig ? <Loader2 className="spin" size={14} /> : <CheckCircle size={14} />}
                                                Save Configuration
                                            </button>
                                        </div>

                                        {endpointResult && (
                                            <div className={`endpoint-result ${endpointResult.success ? 'success' : 'error'}`}>
                                                {endpointResult.success ? (
                                                    <>
                                                        <CheckCircle size={16} />
                                                        <span><strong>Resolved:</strong> {endpointResult.endpoint}</span>
                                                    </>
                                                ) : (
                                                    <>
                                                        <AlertCircle size={16} />
                                                        <span><strong>Error:</strong> {endpointResult.error}</span>
                                                    </>
                                                )}
                                            </div>
                                        )}

                                        <p className="help-text">
                                            <small>
                                                This endpoint will be used in generated .ovpn client configurations.
                                                {vpnEndpoint.endpoint_type === 'auto' && ' Auto-detect may take up to 10 seconds.'}
                                            </small>
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </>
                    )}
                </div>
            ) : (
                // --- CLIENT TAB CONTENT ---
                <div className="vpn-grid">
                    <div className="vpn-info-section">
                        {/* Status Card */}
                        <div className={`info-card glass-panel status-card ${clientStatus.connected ? 'connected' : ''}`}>
                            <div className="card-header">
                                <h3>Connection Status</h3>
                                {refreshingClient && <Loader2 className="spin" size={16} />}
                            </div>
                            <div className="status-stats">
                                <div className="stat-row">
                                    <span>State</span>
                                    <span className={`badge ${clientStatus.connected ? 'online' : 'offline'}`}>
                                        {clientStatus.connected ? 'Connected' : 'Disconnected'}
                                    </span>
                                </div>
                                <div className="stat-row"><span>Public IP</span><strong>{clientStatus.ip_address}</strong></div>
                                <div className="stat-row"><span>Uptime</span><strong>{clientStatus.uptime}</strong></div>
                            </div>
                            <div className="card-actions">
                                {clientStatus.connected ? (
                                    <button className="control-btn stop" onClick={() => handleClientControl('stop')}>
                                        <Power size={16} /> Disconnect
                                    </button>
                                ) : (
                                    <button className="control-btn start" onClick={() => handleClientControl('start')}>
                                        <Power size={16} /> Connect VPN
                                    </button>
                                )}
                            </div>
                        </div>

                        {/* Configuration Upload */}
                        <div className="info-card glass-panel">
                            <h3>Configuration (PIA)</h3>
                            <form onSubmit={handleConfigUpload} className="config-form">
                                <div className="form-group">
                                    <label><User size={14} /> Username</label>
                                    <input type="text" placeholder="p1234567" value={configUpload.username} onChange={e => setConfigUpload({ ...configUpload, username: e.target.value })} required />
                                </div>
                                <div className="form-group">
                                    <label><Lock size={14} /> Password</label>
                                    <input type="password" placeholder="••••••••" value={configUpload.password} onChange={e => setConfigUpload({ ...configUpload, password: e.target.value })} required />
                                </div>
                                <div className="form-group">
                                    <label><Upload size={14} /> .ovpn Config</label>
                                    <input type="file" accept=".ovpn" onChange={e => setConfigUpload({ ...configUpload, file: e.target.files[0] })} required />
                                </div>
                                <button type="submit" className="primary-btn full-width" disabled={uploading}>
                                    {uploading ? <Loader2 className="spin" /> : 'Save & Upload'}
                                </button>
                            </form>
                        </div>
                    </div>

                    {/* Policy Routing */}
                    <div className="clients-section glass-panel">
                        <div className="card-header">
                            <div>
                                <h3>Split Tunnel Policies</h3>
                                <p className="description">Only these IPs connect via VPN</p>
                            </div>
                        </div>

                        <div className="policy-add-row">
                            <input
                                type="text"
                                placeholder="Device IP (e.g. 192.168.1.55)"
                                value={newPolicyIP}
                                onChange={e => setNewPolicyIP(e.target.value)}
                            />
                            <button className="add-btn" onClick={handleAddPolicy}>Add Rule</button>
                        </div>

                        <div className="policy-list">
                            {policies.length === 0 && <p className="empty-text">No rules active. Traffic uses default ISP gateway.</p>}
                            {policies.map((p, idx) => (
                                <div key={idx} className="client-item policy-item">
                                    <div className="client-info">
                                        <Network size={20} className="icon-blue" />
                                        <div className="client-details">
                                            <strong>{p.source_ip}</strong>
                                            <span>Routed via VPN</span>
                                        </div>
                                    </div>
                                    <button className="action-btn delete" onClick={() => handleDeletePolicy(p.source_ip)}>
                                        <Trash2 size={16} />
                                    </button>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {/* Modals (Server Only) */}
            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content glass-panel">
                        <h3>Authorize New Peer</h3>
                        <form onSubmit={handleAddClient}>
                            <div className="input-group">
                                <label>Device Name</label>
                                <input type="text" autoFocus value={newClientName} onChange={e => setNewClientName(e.target.value)} required />
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="cancel-btn" onClick={() => setShowModal(false)}>Cancel</button>
                                <button type="submit" className="confirm-btn" disabled={generating}>{generating ? <Loader2 className="spin" /> : 'Generate'}</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
            {showQR && (
                <div className="modal-overlay">
                    <div className="modal-content glass-panel qr-modal">
                        <button className="close-btn" onClick={() => setShowQR(null)}><X size={20} /></button>
                        <h3>Scan to Connect 📱</h3>
                        <div className="qr-container">
                            <QRCode value={showQR.config} size={256} />
                        </div>
                        <div className="qr-actions">
                            <button className="secondary-btn" onClick={() => copyToClipboard(showQR.config)}><Copy size={16} /> Copy</button>
                            <button className="primary-btn" onClick={() => handleDownload(showQR.name)}><Download size={16} /> Download</button>
                        </div>
                    </div>
                </div>
            )}
            {showOvpnModal && (
                <div className="modal-overlay">
                    <div className="modal-content glass-panel">
                        <h3>Create OpenVPN Peer</h3>
                        <form onSubmit={handleAddOvpnClient}>
                            <div className="input-group">
                                <label>Client Name (No spaces)</label>
                                <input
                                    type="text"
                                    autoFocus
                                    placeholder="laptop-user"
                                    value={newOvpnClientName}
                                    onChange={e => setNewOvpnClientName(e.target.value.replace(/\s/g, ''))}
                                    required
                                />
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="cancel-btn" onClick={() => setShowOvpnModal(false)}>Cancel</button>
                                <button type="submit" className="confirm-btn" disabled={generating}>{generating ? <Loader2 className="spin" /> : 'Generate Cert'}</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default RemoteAccess;
