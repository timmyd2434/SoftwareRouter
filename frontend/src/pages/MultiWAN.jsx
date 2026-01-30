import React, { useEffect, useState } from 'react';
import { Activity, Save, RefreshCw, Power } from 'lucide-react';
import './MultiWAN.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const MultiWAN = () => {
    // We now expect { mode: "...", interfaces: [...] }
    const [config, setConfig] = useState({ mode: 'failover', interfaces: [] });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        fetchInterfaces();
        const interval = setInterval(fetchInterfaces, 5000);
        return () => clearInterval(interval);
    }, []);

    const fetchInterfaces = async () => {
        try {
            const res = await authFetch('/api/wan');
            if (res.ok) {
                const data = await res.json();
                // Handle legacy array response vs new object response
                if (Array.isArray(data)) {
                    setConfig({ mode: 'failover', interfaces: data });
                } else {
                    setConfig(data || { mode: 'failover', interfaces: [] });
                }
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async () => {
        setSaving(true);
        try {
            const res = await authFetch('/api/wan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            if (res.ok) {
                // success
            } else {
                alert("Failed to save configuration");
            }
        } catch (err) {
            console.error(err);
        } finally {
            setSaving(false);
        }
    };

    const updateInterface = (index, field, value) => {
        const newIfaces = [...config.interfaces];
        newIfaces[index] = { ...newIfaces[index], [field]: value };
        setConfig({ ...config, interfaces: newIfaces });
    };

    const toggleEnabled = (index) => {
        const newIfaces = [...config.interfaces];
        newIfaces[index].enabled = !newIfaces[index].enabled;
        setConfig({ ...config, interfaces: newIfaces });
    };

    const addInterface = () => {
        const newIfaces = [...config.interfaces, {
            interface: 'eth0',
            name: 'New WAN',
            gateway: '',
            check_target: '8.8.8.8',
            priority: 2,
            weight: 1,
            enabled: false,
            state: 'unknown'
        }];
        setConfig({ ...config, interfaces: newIfaces });
    };

    const removeInterface = (index) => {
        if (!window.confirm("Remove this WAN configuration?")) return;
        const newIfaces = [...config.interfaces];
        newIfaces.splice(index, 1);
        setConfig({ ...config, interfaces: newIfaces });
    };

    return (
        <div className="multiwan-container">
            <div className="page-header">
                <div className="title-area">
                    <Activity size={28} className="text-secondary" />
                    <div>
                        <h2>Multi-WAN Failover</h2>
                        <p className="subtitle">Manage internet connection priorities and health checks</p>
                    </div>
                </div>
                <div className="actions">
                    <button className="icon-btn" onClick={fetchInterfaces} title="Refresh Status">
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                    <button className="primary-btn" onClick={handleSave} disabled={saving}>
                        <Save size={18} />
                        {saving ? 'Saving...' : 'Save Configuration'}
                    </button>
                </div>
            </div>

            {/* Mode Selection */}
            <div className="glass-panel" style={{ marginBottom: '2rem', padding: '1.5rem' }}>
                <h3 style={{ marginTop: 0, marginBottom: '1rem', fontSize: '1rem' }}>Operating Mode</h3>
                <div style={{ display: 'flex', gap: '2rem' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                        <input
                            type="radio"
                            name="wanMode"
                            checked={config.mode === 'failover'}
                            onChange={() => setConfig({ ...config, mode: 'failover' })}
                        />
                        <div>
                            <strong>Failover (Active/Passive)</strong>
                            <div className="text-muted" style={{ fontSize: '0.85rem' }}>Uses highest priority healthy link.</div>
                        </div>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                        <input
                            type="radio"
                            name="wanMode"
                            checked={config.mode === 'load_balance'}
                            onChange={() => setConfig({ ...config, mode: 'load_balance' })}
                        />
                        <div>
                            <strong>Load Balance (Active/Active)</strong>
                            <div className="text-muted" style={{ fontSize: '0.85rem' }}>Distributes traffic across all healthy links (ECMP).</div>
                        </div>
                    </label>
                </div>
            </div>

            <div className="wan-list">
                {config.interfaces.map((iface, idx) => (
                    <div key={idx} className={`wan-card ${iface.state === 'online' ? 'online' : 'offline'}`}>
                        <div className="wan-header">
                            <div className="wan-title">
                                <span className={`status-dot ${iface.state === 'online' ? 'green' : 'red'}`}></span>
                                <input
                                    type="text"
                                    className="wan-name-input"
                                    value={iface.name}
                                    onChange={(e) => updateInterface(idx, 'name', e.target.value)}
                                />
                            </div>
                            <div className="wan-toggle">
                                <button
                                    className={`toggle-btn ${iface.enabled ? 'active' : ''}`}
                                    onClick={() => toggleEnabled(idx)}
                                    title={iface.enabled ? "Enabled" : "Disabled"}
                                >
                                    <Power size={16} />
                                </button>
                                <button className="delete-btn" onClick={() => removeInterface(idx)}>×</button>
                            </div>
                        </div>

                        <div className="wan-body">
                            <div className="field-group">
                                <label>Interface</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={iface.interface}
                                    onChange={(e) => updateInterface(idx, 'interface', e.target.value)}
                                    placeholder="e.g. eth0"
                                />
                            </div>
                            <div className="field-group">
                                <label>Gateway IP</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={iface.gateway}
                                    onChange={(e) => updateInterface(idx, 'gateway', e.target.value)}
                                    placeholder="e.g. 192.168.1.1"
                                />
                            </div>
                            <div className="field-group">
                                <label>Check Target</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={iface.check_target}
                                    onChange={(e) => updateInterface(idx, 'check_target', e.target.value)}
                                    placeholder="8.8.8.8"
                                />
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                                <div className="field-group">
                                    <label>Priority</label>
                                    <input
                                        type="number"
                                        className="form-input"
                                        value={iface.priority}
                                        onChange={(e) => updateInterface(idx, 'priority', parseInt(e.target.value))}
                                        min="1"
                                        title="Lower number = higher priority"
                                    />
                                </div>
                                <div className="field-group">
                                    <label>Weight</label>
                                    <input
                                        type="number"
                                        className="form-input"
                                        value={iface.weight || 1}
                                        onChange={(e) => updateInterface(idx, 'weight', parseInt(e.target.value))}
                                        min="1"
                                        disabled={config.mode !== 'load_balance'}
                                        title="Relative bandwidth share for Load Balancing"
                                    />
                                </div>
                            </div>
                        </div>
                        <div className="wan-footer">
                            <span className="state-badge">{iface.state.toUpperCase()}</span>
                            {iface.enabled ? <span className="enabled-badge">Monitoring</span> : <span className="disabled-badge">Disabled</span>}
                        </div>
                    </div>
                ))}

                <button className="add-wan-btn" onClick={addInterface}>
                    + Add WAN Interface
                </button>
            </div>
        </div>
    );
};

export default MultiWAN;
