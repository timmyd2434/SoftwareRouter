import React, { useState, useEffect } from 'react';
import { Globe, Plus, Download, Trash2, Calendar, User, Shield, RefreshCw, AlertCircle, CheckCircle, Loader2 } from 'lucide-react';
import { API_ENDPOINTS, authFetch } from '../apiConfig';
import './RemoteAccess.css';

const RemoteAccess = () => {
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
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
            console.error('Failed to fetch VPN clients', err);
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
                setMessage({ type: 'success', text: `Profile for ${newClientName} generated successfully.` });
                setNewClientName('');
                setShowModal(false);
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
        if (!confirm(`Permanently delete VPN profile for ${name}?`)) return;

        try {
            const res = await authFetch(`${API_ENDPOINTS.VPN_CLIENTS}?name=${name}`, {
                method: 'DELETE'
            });

            if (res.ok) {
                setMessage({ type: 'success', text: 'Profile deleted.' });
                fetchClients();
            }
        } catch (err) {
            setMessage({ type: 'error', text: 'Failed to delete profile.' });
        }
    };

    const handleDownload = (name) => {
        const token = localStorage.getItem('sr_token');
        const url = `${API_ENDPOINTS.VPN_DOWNLOAD}?name=${name}&token=${token}`;
        // Since it's a file download, we use a hidden link or window.open
        // Note: authFetch doesn't work for direct browser downloads easily, 
        // we'll use the token in query param or handle it in backend.
        window.open(url, '_blank');
    };

    return (
        <div className="vpn-container">
            <div className="section-header">
                <div>
                    <h2>Remote Access (OpenVPN)</h2>
                    <span className="subtitle">Manage secure tunnel profiles for external devices</span>
                </div>
                <button className="add-btn" onClick={() => setShowModal(true)}>
                    <Plus size={20} />
                    Generate Profile
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
                        <h3>Authorized Client Profiles</h3>
                    </div>

                    {loading ? (
                        <div className="loading-state"><Loader2 className="spin" /></div>
                    ) : clients.length === 0 ? (
                        <div className="empty-state">
                            <Shield size={48} />
                            <p>No active remote profiles found.</p>
                            <span>Generate a profile to allow secure external access.</span>
                        </div>
                    ) : (
                        <div className="client-list">
                            {clients.map(client => (
                                <div key={client.client_name} className="client-item">
                                    <div className="client-info">
                                        <div className="client-avatar">
                                            {client.client_name.charAt(0).toUpperCase()}
                                        </div>
                                        <div className="client-details">
                                            <strong>{client.client_name}</strong>
                                            <span><Calendar size={12} /> Created: {new Date(client.created_at).toLocaleDateString()}</span>
                                        </div>
                                    </div>
                                    <div className="client-actions">
                                        <button className="action-btn download" title="Download .ovpn" onClick={() => handleDownload(client.client_name)}>
                                            <Download size={18} />
                                        </button>
                                        <button className="action-btn delete" title="Revoke Access" onClick={() => handleDeleteClient(client.client_name)}>
                                            <Trash2 size={18} />
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                <div className="vpn-info-section">
                    <div className="info-card glass-panel">
                        <div className="card-header">
                            <Globe size={20} className="header-icon" />
                            <h3>Server Status</h3>
                        </div>
                        <div className="status-stats">
                            <div className="stat-row">
                                <span>Protocol</span>
                                <strong>UDP (Port 1194)</strong>
                            </div>
                            <div className="stat-row">
                                <span>Encryption</span>
                                <strong>AES-256-GCM</strong>
                            </div>
                            <div className="stat-row">
                                <span>Virtual IP Pool</span>
                                <strong>10.8.0.0/24</strong>
                            </div>
                        </div>
                    </div>

                    <div className="info-card glass-panel instruction-card">
                        <h3>How to Connect</h3>
                        <ol>
                            <li>Download the <strong>.ovpn</strong> profile above.</li>
                            <li>Install the OpenVPN client on your device.</li>
                            <li>Import the profile and connect using your server's public IP.</li>
                        </ol>
                    </div>
                </div>
            </div>

            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content glass-panel">
                        <h3>Generate New Client Profile</h3>
                        <form onSubmit={handleAddClient}>
                            <div className="input-group">
                                <label>Client Identifier</label>
                                <input
                                    type="text"
                                    placeholder="e.g. MacBook-Pro, iPhone-Tim"
                                    value={newClientName}
                                    onChange={e => setNewClientName(e.target.value)}
                                    required
                                    autoFocus
                                />
                                <span className="hint">A unique name to identify this device.</span>
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="cancel-btn" onClick={() => setShowModal(false)}>Cancel</button>
                                <button type="submit" className="confirm-btn" disabled={generating}>
                                    {generating ? <Loader2 className="spin" size={18} /> : 'Generate OVPN'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default RemoteAccess;
