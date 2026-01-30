import React, { useEffect, useState } from 'react';
import { Route, Save, RefreshCw, Power } from 'lucide-react';
import './DynamicRouting.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const DynamicRouting = () => {
    const [config, setConfig] = useState({
        ospf: { enabled: false, router_id: '', redistribute: [], networks: [] },
        bgp: { enabled: false, asn: 65000, router_id: '', neighbors: [], networks: [] }
    });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [activeTab, setActiveTab] = useState('ospf');

    useEffect(() => {
        fetchConfig();
    }, []);

    const fetchConfig = async () => {
        try {
            const res = await authFetch('/api/routing/dynamic');
            if (res.ok) {
                const data = await res.json();
                setConfig(data);
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
            const res = await authFetch('/api/routing/dynamic', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            if (res.ok) {
                // Success
            } else {
                alert("Failed to save configuration");
            }
        } catch (err) {
            console.error(err);
        } finally {
            setSaving(false);
        }
    };

    // --- OSPF Handlers ---
    const updateOSPF = (field, value) => {
        setConfig({ ...config, ospf: { ...config.ospf, [field]: value } });
    };

    const addOSPFNetwork = () => {
        const nets = [...(config.ospf.networks || []), { network: '', area: '0' }];
        updateOSPF('networks', nets);
    };

    const updateOSPFNetwork = (idx, field, value) => {
        const nets = [...config.ospf.networks];
        nets[idx] = { ...nets[idx], [field]: value };
        updateOSPF('networks', nets);
    };

    const removeOSPFNetwork = (idx) => {
        const nets = [...config.ospf.networks];
        nets.splice(idx, 1);
        updateOSPF('networks', nets);
    };

    const toggleRedistribute = (proto) => {
        const current = new Set(config.ospf.redistribute || []);
        if (current.has(proto)) current.delete(proto);
        else current.add(proto);
        updateOSPF('redistribute', Array.from(current));
    };

    // --- BGP Handlers ---
    const updateBGP = (field, value) => {
        setConfig({ ...config, bgp: { ...config.bgp, [field]: value } });
    };

    const addBGPNeighbor = () => {
        const neighbors = [...(config.bgp.neighbors || []), { ip: '', remote_asn: 0 }];
        updateBGP('neighbors', neighbors);
    };

    const updateBGPNeighbor = (idx, field, value) => {
        const neighbors = [...config.bgp.neighbors];
        neighbors[idx] = { ...neighbors[idx], [field]: value };
        updateBGP('neighbors', neighbors);
    };

    const removeBGPNeighbor = (idx) => {
        const neighbors = [...config.bgp.neighbors];
        neighbors.splice(idx, 1);
        updateBGP('neighbors', neighbors);
    };

    return (
        <div className="dr-container">
            <div className="page-header">
                <div className="title-area">
                    <Route size={28} className="text-secondary" />
                    <div>
                        <h2>Dynamic Routing</h2>
                        <p className="subtitle">Configure OSPF and BGP protocols via FRR</p>
                    </div>
                </div>
                <div className="actions">
                    <button className="icon-btn" onClick={fetchConfig} title="Refresh">
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                    <button className="primary-btn" onClick={handleSave} disabled={saving}>
                        <Save size={18} />
                        {saving ? 'Applying...' : 'Apply Config'}
                    </button>
                </div>
            </div>

            <div className="tabs">
                <button className={`tab-btn ${activeTab === 'ospf' ? 'active' : ''}`} onClick={() => setActiveTab('ospf')}>OSPF</button>
                <button className={`tab-btn ${activeTab === 'bgp' ? 'active' : ''}`} onClick={() => setActiveTab('bgp')}>BGP</button>
            </div>

            <div className="glass-panel" style={{ padding: '2rem' }}>

                {/* OSPF CONFIG */}
                {activeTab === 'ospf' && (
                    <div className="animate-fade-in">
                        <div className="config-header">
                            <h3>OSPF Settings</h3>
                            <div className="toggle-switch">
                                <label className="switch">
                                    <input
                                        type="checkbox"
                                        checked={config.ospf.enabled}
                                        onChange={(e) => updateOSPF('enabled', e.target.checked)}
                                    />
                                    <span className="slider round"></span>
                                </label>
                                <span className={config.ospf.enabled ? "text-success" : "text-muted"}>
                                    {config.ospf.enabled ? "Enabled" : "Disabled"}
                                </span>
                            </div>
                        </div>

                        <div className="form-grid">
                            <div className="form-group">
                                <label>Router ID</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={config.ospf.router_id}
                                    onChange={(e) => updateOSPF('router_id', e.target.value)}
                                    placeholder="e.g. 1.1.1.1"
                                />
                            </div>
                            <div className="form-group">
                                <label>Redistribute</label>
                                <div className="checkbox-group">
                                    <label><input type="checkbox" checked={config.ospf.redistribute?.includes('connected')} onChange={() => toggleRedistribute('connected')} /> Connected</label>
                                    <label><input type="checkbox" checked={config.ospf.redistribute?.includes('static')} onChange={() => toggleRedistribute('static')} /> Static</label>
                                    <label><input type="checkbox" checked={config.ospf.redistribute?.includes('kernel')} onChange={() => toggleRedistribute('kernel')} /> Kernel</label>
                                </div>
                            </div>
                        </div>

                        <h4 className="mt-4">Networks to Advertise</h4>
                        <div className="network-list">
                            {config.ospf.networks?.map((net, idx) => (
                                <div key={idx} className="network-row">
                                    <input
                                        type="text"
                                        className="form-input"
                                        placeholder="Network CIDR (e.g. 10.0.0.0/24)"
                                        value={net.network}
                                        onChange={(e) => updateOSPFNetwork(idx, 'network', e.target.value)}
                                    />
                                    <input
                                        type="text"
                                        className="form-input"
                                        placeholder="Area (e.g. 0)"
                                        value={net.area}
                                        onChange={(e) => updateOSPFNetwork(idx, 'area', e.target.value)}
                                    />
                                    <button className="icon-btn danger" onClick={() => removeOSPFNetwork(idx)}>×</button>
                                </div>
                            ))}
                            <button className="btn-dashed" onClick={addOSPFNetwork}>+ Add Network</button>
                        </div>
                    </div>
                )}

                {/* BGP CONFIG */}
                {activeTab === 'bgp' && (
                    <div className="animate-fade-in">
                        <div className="config-header">
                            <h3>BGP Settings</h3>
                            <div className="toggle-switch">
                                <label className="switch">
                                    <input
                                        type="checkbox"
                                        checked={config.bgp.enabled}
                                        onChange={(e) => updateBGP('enabled', e.target.checked)}
                                    />
                                    <span className="slider round"></span>
                                </label>
                                <span className={config.bgp.enabled ? "text-success" : "text-muted"}>
                                    {config.bgp.enabled ? "Enabled" : "Disabled"}
                                </span>
                            </div>
                        </div>

                        <div className="form-grid">
                            <div className="form-group">
                                <label>Local ASN</label>
                                <input
                                    type="number"
                                    className="form-input"
                                    value={config.bgp.asn}
                                    onChange={(e) => updateBGP('asn', parseInt(e.target.value))}
                                />
                            </div>
                            <div className="form-group">
                                <label>Router ID</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={config.bgp.router_id}
                                    onChange={(e) => updateBGP('router_id', e.target.value)}
                                    placeholder="Optional"
                                />
                            </div>
                        </div>

                        <h4 className="mt-4">Neighbors (Peers)</h4>
                        <div className="network-list">
                            {config.bgp.neighbors?.map((nbr, idx) => (
                                <div key={idx} className="network-row">
                                    <input
                                        type="text"
                                        className="form-input"
                                        placeholder="Neighbor IP"
                                        value={nbr.ip}
                                        onChange={(e) => updateBGPNeighbor(idx, 'ip', e.target.value)}
                                    />
                                    <input
                                        type="number"
                                        className="form-input"
                                        placeholder="Remote ASN"
                                        value={nbr.remote_asn}
                                        onChange={(e) => updateBGPNeighbor(idx, 'remote_asn', parseInt(e.target.value))}
                                    />
                                    <button className="icon-btn danger" onClick={() => removeBGPNeighbor(idx)}>×</button>
                                </div>
                            ))}
                            <button className="btn-dashed" onClick={addBGPNeighbor}>+ Add Neighbor</button>
                        </div>
                    </div>
                )}

            </div>
        </div>
    );
};

export default DynamicRouting;
