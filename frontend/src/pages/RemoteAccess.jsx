import React, { useState, useEffect } from 'react';
import { Globe, Plus, Download, Trash2, Calendar, User, Shield, RefreshCw, AlertCircle, CheckCircle, Loader2, QrCode, X, Copy } from 'lucide-react';
import QRCode from 'react-qr-code';
import { API_ENDPOINTS, authFetch } from '../apiConfig';
import './RemoteAccess.css';

const RemoteAccess = () => {
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [showQR, setShowQR] = useState(null); // stores { name, config }
    const [newClientName, setNewClientName] = useState('');
    const [message, setMessage] = useState({ type: '', text: '' });
    const [generating, setGenerating] = useState(false);

    useEffect(() => {
        fetchClients();
    }, []);

    const fetchClients = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.VPN_CLIENTS);
            if (res.ok) {
                const data = await res.json();
                setClients(data || []);
            }
        } catch (err) {
            console.error('Failed to fetch WireGuard clients', err);
        } finally {
            setLoading(false);
        }
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
                setMessage({ type: 'success', text: `WireGuard profile for ${newClientName} generated.` });
                setNewClientName('');
                setShowModal(false);
                // Prompt user with QR code immediately
                setShowQR({ name: newClientName, config: result.config });
                fetchClients();
            } else {
                setMessage({ type: 'error', text: 'Failed to generate profile.' });
            }
        } catch (err) {
            setMessage({ type: 'error', text: 'Network error' });
        } finally {
            setGenerating(false);
        }
    };

    const handleDeleteClient = async (name) => {
        if (!confirm(`Revoke access for ${name}?`)) return;

        try {
            const res = await authFetch(`${API_ENDPOINTS.VPN_CLIENTS}?name=${name}`, {
                method: 'DELETE'
            });

            if (res.ok) {
                setMessage({ type: 'success', text: 'Access revoked.' });
                fetchClients();
            }
        } catch (err) {
            setMessage({ type: 'error', text: 'Failed to delete profile.' });
        }
    };

    const handleDownload = (name) => {
        const token = localStorage.getItem('sr_token');
        const url = `${API_ENDPOINTS.VPN_DOWNLOAD}?name=${name}&token=${token}`;
        window.open(url, '_blank');
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        alert('Configuration copied to clipboard!');
    };

    return (
        <div className="vpn-container">
            <div className="section-header">
                <div>
                    <h2>Hybrid WireGuard VPN 🔐</h2>
                    <span className="subtitle">High-speed, encrypted tunnel for your mobile and remote devices</span>
                </div>
                <button className="add-btn" onClick={() => setShowModal(true)}>
                    <Plus size={20} />
                    Add Peer
                </button>
            </div>

            {message.text && (
                <div className={`status-banner ${message.type}`}>
                    {message.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
                    {message.text}
                </div>
            )}

            <div className="vpn-grid">
                <div className="clients-section glass-panel">
                    <div className="card-header">
                        <User size={20} className="header-icon" />
                        <h3>Connected Peers</h3>
                    </div>

                    {loading ? (
                        <div className="loading-state"><Loader2 className="spin" /></div>
                    ) : clients.length === 0 ? (
                        <div className="empty-state">
                            <Shield size={48} />
                            <p>No active VPN peers found.</p>
                            <span>Add a peer to start your secure remote access journey.</span>
                        </div>
                    ) : (
                        <div className="client-list">
                            {clients.map(client => (
                                <div key={client.name} className="client-item">
                                    <div className="client-info">
                                        <div className="client-avatar">
                                            {client.name.charAt(0).toUpperCase()}
                                        </div>
                                        <div className="client-details">
                                            <strong>{client.name}</strong>
                                            <span>
                                                <Calendar size={12} />
                                                {new Date(client.created_at).toLocaleDateString()}
                                            </span>
                                        </div>
                                    </div>
                                    <div className="client-actions">
                                        <button className="action-btn download" title="Download Config" onClick={() => handleDownload(client.name)}>
                                            <Download size={18} />
                                        </button>
                                        <button className="action-btn delete" title="Revoke Access" onClick={() => handleDeleteClient(client.name)}>
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
                        <div className="card-header">
                            <Globe size={20} className="header-icon" />
                            <h3>Server Engine</h3>
                        </div>
                        <div className="status-stats">
                            <div className="stat-row">
                                <span>Status</span>
                                <span className="badge online">Active</span>
                            </div>
                            <div className="stat-row">
                                <span>Encapsulation</span>
                                <strong className="text-secondary">UDP (WireGuard)</strong>
                            </div>
                            <div className="stat-row">
                                <span>Port</span>
                                <strong>51820</strong>
                            </div>
                            <div className="stat-row">
                                <span>Subnet</span>
                                <strong>10.8.0.0/24</strong>
                            </div>
                        </div>
                    </div>

                    <div className="info-card glass-panel instruction-card">
                        <h3>Connect in Seconds</h3>
                        <ol>
                            <li>Download the <strong>WireGuard App</strong>.</li>
                            <li>Add a new Peer above to get a <strong>QR Code</strong>.</li>
                            <li>Scan the QR from the mobile app and flip the switch!</li>
                        </ol>
                    </div>
                </div>
            </div>

            {/* Modal: New Client */}
            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content glass-panel">
                        <h3>Authorize New Peer</h3>
                        <form onSubmit={handleAddClient}>
                            <div className="input-group">
                                <label>Device Name</label>
                                <input
                                    type="text"
                                    placeholder="e.g. My-iPhone-16"
                                    value={newClientName}
                                    onChange={e => setNewClientName(e.target.value)}
                                    required
                                    autoFocus
                                />
                                <span className="hint">Identifies this device in the peer list.</span>
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="cancel-btn" onClick={() => setShowModal(false)}>Cancel</button>
                                <button type="submit" className="confirm-btn" disabled={generating}>
                                    {generating ? <Loader2 className="spin" size={18} /> : 'Generate Secure Link'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Modal: QR Code Display */}
            {showQR && (
                <div className="modal-overlay">
                    <div className="modal-content glass-panel qr-modal">
                        <button className="close-btn" onClick={() => setShowQR(null)}><X size={20} /></button>
                        <h3>Scan to Connect 📱</h3>
                        <p className="subtitle">Scan this with the WireGuard app on your phone</p>

                        <div className="qr-container">
                            <QRCode
                                value={showQR.config}
                                size={256}
                                bgColor="white"
                                fgColor="black"
                                level="M"
                            />
                        </div>

                        <div className="qr-actions">
                            <button className="secondary-btn" onClick={() => copyToClipboard(showQR.config)}>
                                <Copy size={16} /> Copy Config
                            </button>
                            <button className="primary-btn" onClick={() => handleDownload(showQR.name)}>
                                <Download size={16} /> Download .conf
                            </button>
                        </div>

                        <div className="qr-footer">
                            <Shield size={16} />
                            <span>This config contains your private keys. Keep it safe!</span>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default RemoteAccess;
