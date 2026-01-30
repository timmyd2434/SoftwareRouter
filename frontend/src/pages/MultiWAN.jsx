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
        fetchWanCandidates();
        const interval = setInterval(fetchInterfaces, 5000);
        return () => clearInterval(interval);
    }, []);

    const [wanCandidates, setWanCandidates] = useState([]);

    const fetchWanCandidates = async () => {
        try {
            const [ifaceRes, metaRes] = await Promise.all([
                authFetch('/api/interfaces'),
                authFetch('/api/interfaces/metadata')
            ]);

            if (ifaceRes.ok && metaRes.ok) {
                const ifaces = await ifaceRes.json();
                const metadata = await metaRes.json();

                // Filter for interfaces labeled as WAN
                const filtered = ifaces.filter(i => {
                    const meta = metadata[i.name];
                    return meta && (meta.label === 'WAN' || meta.label === 'Internet');
                });

                setWanCandidates(filtered);
            }
        } catch (err) {
            console.error("Failed to load interface candidates", err);
        }
    };

    const fetchInterfaces = async () => {
        try {
            const res = await authFetch('/api/wan');
            if (res.ok) {
                const data = await res.json();

                // Parse server response
                let serverConfig = { mode: 'failover', interfaces: [] };
                if (Array.isArray(data)) {
                    serverConfig = { mode: 'failover', interfaces: data };
                } else if (data) {
                    serverConfig = data;
                }

                // Merge strategy:
                // 1. Keep local mode if different? No, server is truth, but we don't want to jump.
                //    Actually, for mode, server should probably win unless we are editing.
                // 2. For interfaces:
                //    - Update status of existing ones.
                //    - Do NOT remove local ones that are missing from server (e.g. just added).

                setConfig(prevConfig => {
                    const newIfaces = [...prevConfig.interfaces];

                    // Update existing ones from server
                    serverConfig.interfaces.forEach(srvIface => {
                        // Find by interface name (assuming unique) or some index mapping if stable?
                        // Since we don't have IDs, we might rely on 'interface' field or index if strict.
                        // Let's rely on index for now as that's how we map, but this is brittle if array changes size.
                        // Better: Match by 'interface' field if set, otherwise fallback to index?
                        // Given the backend uses a simple array, index matching is the only 1:1 map we have guaranteed 
                        // unless we introduce IDs. For now, we'll try to match by index for existing items.

                        // BUT, if user added a new item at end, prevConfig has length N+1.
                        // We iterate server interfaces (N) and update the first N items of prevConfig.
                    });

                    // Simpler approach for this specific bug:
                    // Just update the 'state' field of items that match, and don't touch others.

                    const mergedInterfaces = prevConfig.interfaces.map((localIface, idx) => {
                        if (idx < serverConfig.interfaces.length) {
                            const srvIface = serverConfig.interfaces[idx];
                            // Only update status/state, preserve local edits to other fields?
                            // Or overwriting is fine if we assume server is truth?
                            // The bug is "erased it". That means server sent shorter list.
                            // So if we have more items locally, keep them!

                            // We update state from server always
                            return { ...localIface, state: srvIface.state };
                        }
                        return localIface; // Keep local item that doesn't exist on server yet
                    });

                    return {
                        mode: serverConfig.mode, // Sync mode
                        interfaces: mergedInterfaces
                    };
                });
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
                                <select
                                    className="form-input"
                                    value={iface.interface}
                                    onChange={(e) => updateInterface(idx, 'interface', e.target.value)}
                                >
                                    <option value="" disabled>Select Interface</option>
                                    {wanCandidates.map(c => (
                                        <option key={c.name} value={c.name}>
                                            {c.name} {c.mac ? `(${c.mac})` : ''}
                                        </option>
                                    ))}
                                    {/* Fallback for existing values not in the list */}
                                    {iface.interface && !wanCandidates.find(c => c.name === iface.interface) && (
                                        <option value={iface.interface}>{iface.interface} (Current)</option>
                                    )}
                                </select>
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
