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
    const [staticForm, setStaticForm] = useState({
        mac: '',
        ip: '',
        hostname: ''
    });

    const [showMetaModal, setShowMetaModal] = useState(false);
    const [metaForm, setMetaForm] = useState({
        mac: '',
        name: '',
        type: 'unknown'
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
        fetchClients(); // eslint-disable-line react-hooks/set-state-in-effect
        const interval = setInterval(fetchClients, 10000); // Auto refresh every 10s
        return () => clearInterval(interval);
    }, []);

    const handleMakeStatic = (client) => {
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

    const getDeviceIcon = (client) => {
        const type = client.device_type;
        const h = (client.device_name || client.hostname || "").toLowerCase();
        
        if (type === 'mobile') return Smartphone;
        if (type === 'laptop') return Laptop;
        if (type === 'desktop') return Monitor;
        if (type === 'printer') return Printer;
        if (type === 'server') return Server;
        if (type === 'tv') return Monitor;

        if (h.includes("iphone") || h.includes("android") || h.includes("phone")) return Smartphone;
        if (h.includes("macbook") || h.includes("laptop")) return Laptop;
        if (h.includes("printer")) return Printer;
        if (h.includes("server") || h.includes("nas") || h.includes("unifi")) return Server;
        if (h.includes("tv")) return Monitor;
        
        return Network; // Default
    };

    const handleEditMeta = (client) => {
        setMetaForm({
            mac: client.mac,
            name: client.device_name || '',
            type: client.device_type || 'unknown'
        });
        setShowMetaModal(true);
    };

    const handleSaveMeta = async () => {
        try {
            const res = await authFetch('/api/devices/meta', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(metaForm)
            });

            if (res.ok) {
                setShowMetaModal(false);
                fetchClients();
            } else {
                alert("Failed to save device details.");
            }
        } catch (err) {
            console.error(err);
        }
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
                        const Icon = getDeviceIcon(client);
                        return (
                            <div key={idx} className={`client-card glass-panel ${client.is_active ? 'active' : ''}`}>
                                <div className="client-header">
                                    <div className="client-icon">
                                        <Icon size={24} />
                                    </div>
                                    <div className={`client-status-indicator`} title={client.is_active ? "Online" : "Offline"}></div>
                                </div>
                                <div className="client-info" onClick={() => handleEditMeta(client)} style={{ cursor: 'pointer' }} title="Click to edit device details">
                                    <h3>{client.device_name || client.hostname || "Unknown Device"}</h3>
                                    <div className="client-ip">{client.ip}</div>
                                </div>
                                <div className="client-details">
                                    <div className="detail-row">
                                        <span className="label">MAC</span>
                                        <span className="value">{client.mac}</span>
                                    </div>
                                    <div className="detail-row">
                                        <span className="label">Vendor</span>
                                        <span className="value" style={{ fontSize: '0.75rem', maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={client.vendor}>
                                            {client.vendor || 'Unknown'}
                                        </span>
                                    </div>
                                    <div className="detail-row">
                                        <span className="label">IP Type</span>
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
                                {filteredClients.map((client, idx) => {
                                    const Icon = getDeviceIcon(client);
                                    return (
                                    <tr key={idx}>
                                        <td>
                                            <div className={`status-dot ${client.is_active ? 'active' : ''}`}></div>
                                        </td>
                                        <td onClick={() => handleEditMeta(client)} style={{ cursor: 'pointer', color: 'var(--primary-color)' }} title="Edit device details">
                                            {client.device_name || client.hostname || "Unknown"}
                                        </td>
                                        <td>{client.ip}</td>
                                        <td>{client.mac}</td>
                                        <td>
                                            <span className="value" style={{ fontSize: '0.85rem', display: 'block', maxWidth: '150px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={client.vendor}>
                                                {client.vendor || 'Unknown'}
                                            </span>
                                        </td>
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
                                    );
                                })}
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

            {showMetaModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Edit Device Details</h3>
                            <button className="close-btn" onClick={() => setShowMetaModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Custom Name</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={metaForm.name}
                                    placeholder="e.g. Tim's iPhone"
                                    onChange={e => setMetaForm({ ...metaForm, name: e.target.value })}
                                />
                            </div>
                            <div className="form-group">
                                <label>Device Type</label>
                                <select 
                                    className="form-input"
                                    value={metaForm.type}
                                    onChange={e => setMetaForm({ ...metaForm, type: e.target.value })}
                                    style={{ width: '100%', padding: '0.75rem', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.1)', color: 'white', borderRadius: '8px' }}
                                >
                                    <option value="unknown">Unknown / Auto-detect</option>
                                    <option value="mobile">Mobile Phone / Tablet</option>
                                    <option value="laptop">Laptop</option>
                                    <option value="desktop">Desktop / Workstation</option>
                                    <option value="tv">Smart TV / Media Player</option>
                                    <option value="server">Server / NAS</option>
                                    <option value="printer">Printer / Scanner</option>
                                    <option value="iot">IoT Device / Smart Home</option>
                                </select>
                            </div>
                            <div className="info-box">
                                <span>Overrides default hostname and icon detection.</span>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowMetaModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleSaveMeta}>
                                <Save size={16} /> Save Changes
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Clients;
