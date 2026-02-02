import React, { useEffect, useState } from 'react';
import { Smartphone, Monitor, Printer, Server, Laptop, Network, Search, LayoutGrid, List as ListIcon, Shield, Anchor, Trash2, RefreshCw, X, Save } from 'lucide-react';
import './Clients.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const Clients = () => {
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'
    const [searchQuery, setSearchQuery] = useState('');
    const [showStaticModal, setShowStaticModal] = useState(false);
    const [selectedClient, setSelectedClient] = useState(null);
    const [staticForm, setStaticForm] = useState({
        mac: '',
        ip: '',
        hostname: ''
    });

    const fetchClients = () => {
        setLoading(true);
        authFetch(API_ENDPOINTS.NETWORK_CLIENTS)
            .then(res => res.json())
            .then(data => {
                setClients(data);
                setLoading(false);
            })
            .catch(err => {
                console.error("Failed to fetch clients", err);
                setLoading(false);
            });
    };

    useEffect(() => {
        fetchClients();
        const interval = setInterval(fetchClients, 10000); // Auto refresh every 10s
        return () => clearInterval(interval);
    }, []);

    const handleMakeStatic = (client) => {
        setSelectedClient(client);
        setStaticForm({
            mac: client.mac,
            ip: client.ip,
            hostname: client.hostname || 'New-Device'
        });
        setShowStaticModal(true);
    };

    const handleSaveStatic = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.DHCP_STATIC, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(staticForm)
            });

            if (res.ok) {
                setShowStaticModal(false);
                fetchClients(); // Refresh list to show change
            } else {
                alert("Failed to save static lease.");
            }
        } catch (err) {
            console.error(err);
        }
    };

    const handleRemoveStatic = async (mac) => {
        if (!confirm("Are you sure you want to remove this static reservation? The device may get a different IP next time.")) return;

        try {
            const res = await authFetch(`${API_ENDPOINTS.DHCP_STATIC}?mac=${mac}`, {
                method: 'DELETE'
            });

            if (res.ok) {
                fetchClients();
            } else {
                alert("Failed to remove static lease.");
            }
        } catch (err) {
            console.error(err);
        }
    };

    const getDeviceIcon = (hostname) => {
        const h = (hostname || "").toLowerCase();
        if (h.includes("iphone") || h.includes("android") || h.includes("phone")) return Smartphone;
        if (h.includes("macbook") || h.includes("laptop")) return Laptop;
        if (h.includes("printer")) return Printer;
        if (h.includes("server") || h.includes("nas") || h.includes("unifi")) return Server;
        if (h.includes("tv")) return Monitor;
        return Network; // Default
    };

    const filteredClients = clients.filter(c =>
        (c.hostname || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.ip.includes(searchQuery) ||
        c.mac.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
        <div className="clients-container">
            <div className="section-header">
                <div>
                    <h2>Network Devices</h2>
                    <span className="subtitle">Manage connected clients and static reservations</span>
                </div>
                <div className="header-actions">
                    <div className="search-box">
                        <Search size={18} className="search-icon" />
                        <input
                            type="text"
                            placeholder="Search devices..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                        />
                    </div>
                    <div className="view-toggles">
                        <button
                            className={`view-toggle ${viewMode === 'grid' ? 'active' : ''}`}
                            onClick={() => setViewMode('grid')}
                        >
                            <LayoutGrid size={18} />
                        </button>
                        <button
                            className={`view-toggle ${viewMode === 'list' ? 'active' : ''}`}
                            onClick={() => setViewMode('list')}
                        >
                            <ListIcon size={18} />
                        </button>
                    </div>
                    <button className="icon-btn" onClick={fetchClients}>
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                </div>
            </div>

            {viewMode === 'grid' ? (
                <div className="clients-grid">
                    {filteredClients.map((client, idx) => {
                        const Icon = getDeviceIcon(client.hostname);
                        return (
                            <div key={idx} className={`client-card glass-panel ${client.is_active ? 'active' : ''}`}>
                                <div className="client-header">
                                    <div className="client-icon">
                                        <Icon size={24} />
                                    </div>
                                    <div className={`client-status-indicator`} title={client.is_active ? "Online" : "Offline"}></div>
                                </div>
                                <div className="client-info">
                                    <h3>{client.hostname || "Unknown Device"}</h3>
                                    <div className="client-ip">{client.ip}</div>
                                </div>
                                <div className="client-details">
                                    <div className="detail-row">
                                        <span className="label">MAC</span>
                                        <span className="value">{client.mac}</span>
                                    </div>
                                    <div className="detail-row">
                                        <span className="label">Type</span>
                                        <span className={`client-badge ${client.is_static ? 'static' : 'dynamic'}`}>
                                            {client.is_static ? 'Static' : 'Dynamic'}
                                        </span>
                                    </div>
                                </div>
                                <div className="client-actions">
                                    {client.is_static ? (
                                        <button className="action-btn danger w-full" onClick={() => handleRemoveStatic(client.mac)}>
                                            <Trash2 size={16} /> Unpin IP
                                        </button>
                                    ) : (
                                        <button className="action-btn w-full" onClick={() => handleMakeStatic(client)}>
                                            <Anchor size={16} /> Make Static
                                        </button>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                </div>
            ) : (
                <div className="glass-panel mt-4">
                    <div className="leases-table-container">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Status</th>
                                    <th>Hostname</th>
                                    <th>IP Address</th>
                                    <th>MAC Address</th>
                                    <th>Type</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredClients.map((client, idx) => (
                                    <tr key={idx}>
                                        <td>
                                            <div className={`status-dot ${client.is_active ? 'active' : ''}`}></div>
                                        </td>
                                        <td>{client.hostname || "Unknown"}</td>
                                        <td>{client.ip}</td>
                                        <td>{client.mac}</td>
                                        <td>
                                            <span className={`client-badge ${client.is_static ? 'static' : 'dynamic'}`}>
                                                {client.is_static ? 'Static' : 'Dynamic'}
                                            </span>
                                        </td>
                                        <td>
                                            {client.is_static ? (
                                                <button className="icon-btn danger" title="Unpin IP" onClick={() => handleRemoveStatic(client.mac)}>
                                                    <Trash2 size={16} />
                                                </button>
                                            ) : (
                                                <button className="icon-btn" title="Make Static" onClick={() => handleMakeStatic(client)}>
                                                    <Anchor size={16} />
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {showStaticModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Static DHCP Reservation</h3>
                            <button className="close-btn" onClick={() => setShowStaticModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Hostname</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={staticForm.hostname}
                                    onChange={e => setStaticForm({ ...staticForm, hostname: e.target.value })}
                                />
                            </div>
                            <div className="form-group">
                                <label>IP Address</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={staticForm.ip}
                                    onChange={e => setStaticForm({ ...staticForm, ip: e.target.value })}
                                />
                            </div>
                            <div className="form-group">
                                <label>MAC Address</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={staticForm.mac}
                                    disabled
                                    style={{ opacity: 0.7 }}
                                />
                            </div>
                            <div className="info-box">
                                <Anchor size={16} />
                                <span>This device will always receive the IP <strong>{staticForm.ip}</strong> from the router.</span>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowStaticModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleSaveStatic}>
                                <Save size={16} /> Save Reservation
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Clients;
