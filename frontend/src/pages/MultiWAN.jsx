import React, { useEffect, useRef, useState } from 'react';
import { Activity, Save, RefreshCw, Power, CheckCircle } from 'lucide-react';
import './MultiWAN.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const MultiWAN = () => {
    // We now expect { mode: "...", interfaces: [...] }
    const [config, setConfig] = useState({ mode: 'failover', interfaces: [] });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [saveStatus, setSaveStatus] = useState(null); // null | 'success' | 'error'

    // Track whether this is the initial fetch so we can replace vs. merge
    const initialLoaded = useRef(false);

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

                // Normalise: API may return an array or a WANStore object
                let serverConfig = { mode: 'failover', interfaces: [] };
                if (Array.isArray(data)) {
                    serverConfig = { mode: 'failover', interfaces: data };
                } else if (data && typeof data === 'object') {
                    serverConfig = {
                        mode: data.mode || 'failover',
                        interfaces: data.interfaces || [],
                    };
                }

                if (!initialLoaded.current) {
                    // First load: replace local state entirely with server truth
                    setConfig(serverConfig);
                    initialLoaded.current = true;
                } else {
                    // Subsequent polling: only patch the live `state` field so we
                    // don't clobber in-progress edits the user hasn't saved yet.
                    setConfig(prevConfig => {
                        const mergedInterfaces = serverConfig.interfaces.map((srvIface, idx) => {
                            const localIface = prevConfig.interfaces[idx];
                            if (localIface) {
                                // Preserve user edits; only refresh the live state
                                return { ...localIface, state: srvIface.state };
                            }
                            return srvIface;
                        });

                        // If the user has added entries locally that the server
                        // doesn't know about yet, keep them at the end.
                        const extraLocal = prevConfig.interfaces.slice(serverConfig.interfaces.length);

                        return {
                            mode: serverConfig.mode,
                            interfaces: [...mergedInterfaces, ...extraLocal],
                        };
                    });
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
        setSaveStatus(null);
        try {
            const res = await authFetch('/api/wan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            if (res.ok) {
                setSaveStatus('success');
                // Re-fetch so the display reflects what the server persisted
                await fetchInterfaces();
                setTimeout(() => setSaveStatus(null), 3000);
            } else {
                setSaveStatus('error');
                alert("Failed to save configuration");
            }
        } catch (err) {
            console.error(err);
            setSaveStatus('error');
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
            interface: '',
            name: 'New WAN',
            gateway: '',
            check_target: '8.8.8.8',
            priority: config.interfaces.length + 1,
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
                        {saveStatus === 'success'
                            ? <><CheckCircle size={18} /> Saved!</>
                            : <><Save size={18} /> {saving ? 'Saving...' : 'Save Configuration'}</>
                        }
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

            {loading && config.interfaces.length === 0 ? (
                <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    Loading WAN configuration...
                </div>
            ) : (
                <div className="wan-list">
                    {config.interfaces.length === 0 && (
                        <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                            No WAN interfaces configured. Click <strong>+ Add WAN Interface</strong> to get started.
                        </div>
                    )}

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
                                <span className="state-badge">{(iface.state || 'unknown').toUpperCase()}</span>
                                {iface.enabled ? <span className="enabled-badge">Monitoring</span> : <span className="disabled-badge">Disabled</span>}
                            </div>
                        </div>
                    ))}

                    <button className="add-wan-btn" onClick={addInterface}>
                        + Add WAN Interface
                    </button>
                </div>
            )}
        </div>
    );
};

export default MultiWAN;
