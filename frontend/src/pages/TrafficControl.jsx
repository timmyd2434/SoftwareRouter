import React, { useEffect, useState } from 'react';
import { Gauge, Save, RefreshCw, AlertTriangle, Settings, Trash2 } from 'lucide-react';
import './TrafficControl.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const TrafficControl = () => {
    const [configs, setConfigs] = useState({});
    const [interfaces, setInterfaces] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedIface, setSelectedIface] = useState(null);
    const [editConfig, setEditConfig] = useState({ mode: 'cake', upload: '', download: '', overhead: 0 });
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, []);

    const [metadata, setMetadata] = useState({});

    const fetchData = async () => {
        try {
            const [qosRes, ifaceRes, metaRes] = await Promise.all([
                authFetch('/api/qos'),
                authFetch('/api/interfaces'),
                authFetch('/api/interfaces/metadata')
            ]);

            if (qosRes.ok) {
                const data = await qosRes.json();
                setConfigs(data || {});
            }
            if (ifaceRes.ok) {
                const ifaces = await ifaceRes.json();
                // We typically only want to shape WAN or LAN interfaces, but let's show all
                setInterfaces(ifaces);
            }
            if (metaRes.ok) {
                const meta = await metaRes.json();
                setMetadata(meta || {});
            }
        } catch (err) {
            console.error("Failed to load QoS data", err);
        } finally {
            setLoading(false);
        }
    };

    const handleEdit = (ifaceName) => {
        const existing = configs[ifaceName];
        if (existing) {
            setEditConfig({ ...existing });
        } else {
            // Default new config
            setEditConfig({
                interface: ifaceName,
                mode: 'cake',
                upload: '100mbit',
                download: '',
                overhead: 0
            });
        }
        setSelectedIface(ifaceName);
    };

    const handleSave = async () => {
        setSaving(true);
        try {
            const payload = { ...editConfig, interface: selectedIface };
            const res = await authFetch('/api/qos', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) {
                setSelectedIface(null);
                fetchData();
            } else {
                alert("Failed to apply QoS settings");
            }
        } catch (err) {
            console.error(err);
            alert("Error saving settings");
        } finally {
            setSaving(false);
        }
    };

    const handleDelete = async (ifaceName) => {
        if (!window.confirm(`Disable QoS on ${ifaceName}?`)) return;
        try {
            const res = await authFetch(`/api/qos?interface=${ifaceName}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                fetchData();
                if (selectedIface === ifaceName) setSelectedIface(null);
            }
        } catch (err) {
            console.error(err);
        }
    };

    return (
        <div className="tc-container">
            <div className="page-header">
                <div className="title-area">
                    <Gauge size={28} className="text-secondary" />
                    <div>
                        <h2>Traffic Control & QoS</h2>
                        <p className="subtitle">Manage bandwidth and mitigate bufferbloat using Smart Queues (CAKE)</p>
                    </div>
                </div>
                <div className="actions">
                    <button className="icon-btn" onClick={fetchData} title="Refresh">
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                </div>
            </div>

            <div className="tc-grid">
                {/* Interface List */}
                <div className="glass-panel">
                    <h3>Interfaces</h3>
                    <div className="interface-list">
                        {interfaces.map(iface => {
                            const hasQoS = configs[iface.name] && configs[iface.name].mode !== 'none';
                            const meta = metadata[iface.name] || {};
                            return (
                                <div key={iface.name} className={`interface-item ${selectedIface === iface.name ? 'active' : ''} ${hasQoS ? 'has-qos' : ''}`} onClick={() => handleEdit(iface.name)}>
                                    <div className="iface-info">
                                        <strong>{iface.name}</strong>
                                        {meta.description && (
                                            <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontStyle: 'italic', marginBottom: '2px' }}>
                                                {meta.description}
                                            </span>
                                        )}
                                        <span className="mac">{iface.mac}</span>
                                    </div>
                                    <div className="qos-status">
                                        {hasQoS ? (
                                            <span className="badge-success">Active</span>
                                        ) : (
                                            <span className="badge-neutral">Pass-through</span>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>

                {/* Edit Panel */}
                <div className="glass-panel config-panel">
                    {selectedIface ? (
                        <>
                            <div className="panel-header">
                                <h3>Configure {selectedIface}</h3>
                                {configs[selectedIface] && (
                                    <button className="btn-icon-text danger" onClick={() => handleDelete(selectedIface)}>
                                        <Trash2 size={16} /> Disable
                                    </button>
                                )}
                            </div>

                            <div className="form-group">
                                <label>Queue Discipline</label>
                                <select
                                    className="form-input"
                                    value={editConfig.mode}
                                    onChange={(e) => setEditConfig({ ...editConfig, mode: e.target.value })}
                                >
                                    <option value="cake">CAKE (Recommended Smart Queue)</option>
                                    <option value="htb">Legacy Rate Limit (HTB)</option>
                                </select>
                                <small className="text-muted">
                                    CAKE automatically manages bufferbloat and fairness.
                                </small>
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label>Upload Limit (Egress)</label>
                                    <input
                                        type="text"
                                        className="form-input"
                                        placeholder="e.g. 100mbit"
                                        value={editConfig.upload}
                                        onChange={(e) => setEditConfig({ ...editConfig, upload: e.target.value })}
                                    />
                                    <small className="text-muted">Required for CAKE to work</small>
                                </div>
                                <div className="form-group">
                                    <label>Download Limit (Ingress)</label>
                                    <input
                                        type="text"
                                        className="form-input"
                                        placeholder="Optional (e.g. 500mbit)"
                                        value={editConfig.download}
                                        onChange={(e) => setEditConfig({ ...editConfig, download: e.target.value })}
                                    />
                                    <small className="text-muted">Requires IFB module</small>
                                </div>
                            </div>

                            <div className="form-group">
                                <label>Link Overhead (Bytes)</label>
                                <input
                                    type="number"
                                    className="form-input"
                                    placeholder="0"
                                    value={editConfig.overhead}
                                    onChange={(e) => setEditConfig({ ...editConfig, overhead: parseInt(e.target.value) || 0 })}
                                />
                                <small className="text-muted">Use 18 for Ethernet, 44 for ATM/DSL</small>
                            </div>

                            <div className="panel-footer">
                                <button className="primary-btn full-width" onClick={handleSave} disabled={saving}>
                                    <Save size={18} />
                                    {saving ? 'Applying...' : 'Apply Settings'}
                                </button>
                            </div>

                        </>
                    ) : (
                        <div className="empty-state">
                            <Settings size={48} className="text-muted" />
                            <p>Select an interface to configure Traffic Control</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default TrafficControl;
