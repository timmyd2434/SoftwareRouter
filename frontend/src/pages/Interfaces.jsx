import React, { useEffect, useState } from 'react';
import { Network, Plus, Trash2, Settings, Power, RefreshCw, X, AlertCircle } from 'lucide-react';
import './Interfaces.css';

const Interfaces = () => {
    const [interfaces, setInterfaces] = useState([]);
    const [metadata, setMetadata] = useState({});
    const [loading, setLoading] = useState(true);
    const [showVLANModal, setShowVLANModal] = useState(false);
    const [showIPModal, setShowIPModal] = useState(false);
    const [showLabelModal, setShowLabelModal] = useState(false);
    const [selectedInterface, setSelectedInterface] = useState(null);

    const [vlanForm, setVlanForm] = useState({
        parentInterface: '',
        vlanId: ''
    });

    const [ipForm, setIpForm] = useState({
        interfaceName: '',
        ipAddress: '',
        action: 'add'
    });

    const [labelForm, setLabelForm] = useState({
        interfaceName: '',
        label: '',
        description: '',
        color: '#3b82f6'
    });

    const labelOptions = [
        { value: 'WAN', color: '#ef4444' },
        { value: 'LAN', color: '#22c55e' },
        { value: 'DMZ', color: '#f59e0b' },
        { value: 'Guest', color: '#8b5cf6' },
        { value: 'Management', color: '#06b6d4' },
        { value: 'Trunk', color: '#6366f1' }
    ];

    const fetchInterfaces = () => {
        setLoading(true);
        fetch('http://localhost:8080/api/interfaces')
            .then(res => res.json())
            .then(data => {
                setInterfaces(data);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    };

    const fetchMetadata = () => {
        fetch('http://localhost:8080/api/interfaces/metadata')
            .then(res => res.json())
            .then(data => {
                setMetadata(data || {});
            })
            .catch(err => {
                console.error('Failed to load metadata:', err);
            });
    };

    const handleCreateVLAN = async () => {
        if (!vlanForm.parentInterface || !vlanForm.vlanId) {
            alert('Please fill in all fields');
            return;
        }

        const vlanId = parseInt(vlanForm.vlanId);
        if (vlanId < 1 || vlanId > 4094) {
            alert('VLAN ID must be between 1 and 4094');
            return;
        }

        try {
            const res = await fetch('http://localhost:8080/api/interfaces/vlan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    parentInterface: vlanForm.parentInterface,
                    vlanId: vlanId
                })
            });

            if (res.ok) {
                const result = await res.json();
                alert(`VLAN created: ${result.interface}`);
                setShowVLANModal(false);
                setVlanForm({ parentInterface: '', vlanId: '' });
                fetchInterfaces();
            } else {
                const text = await res.text();
                alert(`Failed to create VLAN:\n${text}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleDeleteVLAN = async (interfaceName) => {
        if (!interfaceName.includes('.')) {
            alert('Can only delete VLAN interfaces');
            return;
        }

        if (!confirm(`Delete VLAN interface ${interfaceName}?`)) return;

        try {
            const res = await fetch(`http://localhost:8080/api/interfaces/vlan?interface=${interfaceName}`, {
                method: 'DELETE'
            });

            if (res.ok) {
                alert(`VLAN ${interfaceName} deleted`);
                fetchInterfaces();
            } else {
                const text = await res.text();
                alert(`Failed to delete VLAN:\n${text}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleConfigureIP = async () => {
        if (!ipForm.ipAddress.includes('/')) {
            alert('IP address must include CIDR notation (e.g., 192.168.1.1/24)');
            return;
        }

        try {
            const res = await fetch('http://localhost:8080/api/interfaces/ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(ipForm)
            });

            if (res.ok) {
                const result = await res.json();
                alert(result.message);
                setShowIPModal(false);
                setIpForm({ interfaceName: '', ipAddress: '', action: 'add' });
                fetchInterfaces();
            } else {
                const text = await res.text();
                alert(`Failed to configure IP:\n${text}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleToggleInterface = async (interfaceName, currentState) => {
        const newState = currentState ? 'down' : 'up';

        if (!confirm(`Set ${interfaceName} to ${newState.toUpperCase()}?`)) return;

        try {
            const res = await fetch('http://localhost:8080/api/interfaces/state', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    interfaceName: interfaceName,
                    state: newState
                })
            });

            if (res.ok) {
                fetchInterfaces();
            } else {
                const text = await res.text();
                alert(`Failed to change interface state:\n${text}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const openLabelModal = (interfaceName) => {
        const existingMeta = metadata[interfaceName] || {};
        setLabelForm({
            interfaceName,
            label: existingMeta.label || '',
            description: existingMeta.description || '',
            color: existingMeta.color || '#3b82f6'
        });
        setShowLabelModal(true);
    };

    const handleSetLabel = async () => {
        try {
            const res = await fetch('http://localhost:8080/api/interfaces/label', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(labelForm)
            });

            if (res.ok) {
                setShowLabelModal(false);
                fetchMetadata();
            } else {
                const text = await res.text();
                alert(`Failed to set label:\n${text}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const openIPModal = (interfaceName) => {
        setIpForm({ ...ipForm, interfaceName });
        setShowIPModal(true);
    };

    useEffect(() => {
        fetchInterfaces();
        fetchMetadata();
        // Auto-refresh every 15 seconds
        const interval = setInterval(() => {
            fetchInterfaces();
            fetchMetadata();
        }, 15000);
        return () => clearInterval(interval);
    }, []);

    const physicalInterfaces = interfaces.filter(i => !i.name.includes('.'));
    const vlanInterfaces = interfaces.filter(i => i.name.includes('.'));

    return (
        <div className="interfaces-container">
            <div className="section-header">
                <div>
                    <h2>Network Interfaces</h2>
                    <span className="subtitle">Physical and Virtual Adapters</span>
                </div>
                <div className="header-actions">
                    <button className="icon-btn" onClick={fetchInterfaces} title="Refresh">
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                    <button className="primary-btn" onClick={() => setShowVLANModal(true)}>
                        <Plus size={18} />
                        Create VLAN
                    </button>
                </div>
            </div>

            {loading && interfaces.length === 0 ? (
                <div className="loading-state">Loading interfaces...</div>
            ) : (
                <>
                    {/* Physical Interfaces */}
                    <div className="interface-section">
                        <h3 className="section-title">Physical Interfaces</h3>
                        <div className="interface-grid">
                            {physicalInterfaces.map((iface) => (
                                <InterfaceCard
                                    key={iface.index}
                                    iface={iface}
                                    metadata={metadata[iface.name]}
                                    onToggle={handleToggleInterface}
                                    onConfigureIP={openIPModal}
                                    onSetLabel={openLabelModal}
                                    onDelete={null}
                                />
                            ))}
                        </div>
                    </div>

                    {/* VLAN Interfaces */}
                    {vlanInterfaces.length > 0 && (
                        <div className="interface-section">
                            <h3 className="section-title">VLAN Interfaces</h3>
                            <div className="interface-grid">
                                {vlanInterfaces.map((iface) => (
                                    <InterfaceCard
                                        key={iface.index}
                                        iface={iface}
                                        metadata={metadata[iface.name]}
                                        onToggle={handleToggleInterface}
                                        onConfigureIP={openIPModal}
                                        onSetLabel={openLabelModal}
                                        onDelete={handleDeleteVLAN}
                                    />
                                ))}
                            </div>
                        </div>
                    )}
                </>
            )}

            {/* Create VLAN Modal */}
            {showVLANModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Create VLAN Interface</h3>
                            <button className="close-btn" onClick={() => setShowVLANModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Parent Interface</label>
                                <select
                                    className="form-select"
                                    value={vlanForm.parentInterface}
                                    onChange={e => setVlanForm({ ...vlanForm, parentInterface: e.target.value })}
                                >
                                    <option value="">Select an interface...</option>
                                    {physicalInterfaces.map(iface => (
                                        <option key={iface.name} value={iface.name}>{iface.name}</option>
                                    ))}
                                </select>
                            </div>
                            <div className="form-group">
                                <label>VLAN ID (1-4094)</label>
                                <input
                                    type="number"
                                    className="form-input"
                                    min="1"
                                    max="4094"
                                    value={vlanForm.vlanId}
                                    onChange={e => setVlanForm({ ...vlanForm, vlanId: e.target.value })}
                                    placeholder="e.g., 10"
                                />
                            </div>
                            <div className="info-box">
                                <AlertCircle size={16} />
                                <span>VLAN interface will be created as {vlanForm.parentInterface && vlanForm.vlanId ? `${vlanForm.parentInterface}.${vlanForm.vlanId}` : 'parent.vlan_id'}</span>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowVLANModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleCreateVLAN}>Create VLAN</button>
                        </div>
                    </div>
                </div>
            )}

            {/* Configure IP Modal */}
            {showIPModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Configure IP Address</h3>
                            <button className="close-btn" onClick={() => setShowIPModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Interface: <strong>{ipForm.interfaceName}</strong></label>
                            </div>
                            <div className="form-group">
                                <label>Action</label>
                                <select
                                    className="form-select"
                                    value={ipForm.action}
                                    onChange={e => setIpForm({ ...ipForm, action: e.target.value })}
                                >
                                    <option value="add">Add IP Address</option>
                                    <option value="del">Remove IP Address</option>
                                </select>
                            </div>
                            <div className="form-group">
                                <label>IP Address/Subnet (CIDR)</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={ipForm.ipAddress}
                                    onChange={e => setIpForm({ ...ipForm, ipAddress: e.target.value })}
                                    placeholder="e.g., 192.168.10.1/24"
                                />
                            </div>
                            <div className="info-box">
                                <AlertCircle size={16} />
                                <span>Use CIDR notation for subnet specification. Example: 192.168.1.1/24 for a /24 subnet</span>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowIPModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleConfigureIP}>Apply</button>
                        </div>
                    </div>
                </div>
            )}

            {/* Set Label Modal */}
            {showLabelModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Set Interface Label</h3>
                            <button className="close-btn" onClick={() => setShowLabelModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Interface: <strong>{labelForm.interfaceName}</strong></label>
                            </div>
                            <div className="form-group">
                                <label>Label Type</label>
                                <div className="label-options">
                                    {labelOptions.map(option => (
                                        <button
                                            key={option.value}
                                            className={`label-option ${labelForm.label === option.value ? 'selected' : ''}`}
                                            style={{ borderColor: option.color }}
                                            onClick={() => setLabelForm({ ...labelForm, label: option.value, color: option.color })}
                                        >
                                            <span className="label-color" style={{ backgroundColor: option.color }}></span>
                                            {option.value}
                                        </button>
                                    ))}
                                </div>
                            </div>
                            <div className="form-group">
                                <label>Description (Optional)</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={labelForm.description}
                                    onChange={e => setLabelForm({ ...labelForm, description: e.target.value })}
                                    placeholder="e.g., Primary WAN connection"
                                />
                            </div>
                            <div className="info-box">
                                <AlertCircle size={16} />
                                <span>Labels help you organize and identify interfaces by their role in your network</span>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowLabelModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleSetLabel}>Set Label</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

// Interface Card Component
const InterfaceCard = ({ iface, metadata, onToggle, onConfigureIP, onSetLabel, onDelete }) => {
    return (
        <div className={`interface-card glass-panel ${iface.is_up ? 'active' : 'inactive'}`}>
            <div className="iface-header">
                <div className="iface-title">
                    <Network size={20} className="icon" />
                    <div>
                        <h3>{iface.name}</h3>
                        {metadata?.label && (
                            <span
                                className="interface-label"
                                style={{ backgroundColor: metadata.color || '#3b82f6' }}
                            >
                                {metadata.label}
                            </span>
                        )}
                    </div>
                </div>
                <div className={`status-badge ${iface.is_up ? 'up' : 'down'}`}>
                    {iface.is_up ? 'UP' : 'DOWN'}
                </div>
            </div>

            <div className="iface-details">
                {metadata?.description && (
                    <div className="detail-row">
                        <span className="label">Description</span>
                        <span className="value">{metadata.description}</span>
                    </div>
                )}
                <div className="detail-row">
                    <span className="label">MAC Address</span>
                    <span className="value">{iface.mac || 'N/A'}</span>
                </div>
                <div className="detail-row">
                    <span className="label">MTU</span>
                    <span className="value">{iface.mtu}</span>
                </div>
                <div className="detail-row ip-row">
                    <span className="label">IP Addresses</span>
                    <div className="ip-list">
                        {iface.ip_addresses && iface.ip_addresses.length > 0 ? (
                            iface.ip_addresses.map((ip, idx) => (
                                <span key={idx} className="ip-tag">{ip}</span>
                            ))
                        ) : (
                            <span className="no-ip">No IP Assigned</span>
                        )}
                    </div>
                </div>
            </div>

            <div className="iface-actions">
                <button
                    className="action-btn"
                    onClick={() => onSetLabel(iface.name)}
                    title="Set Label"
                >
                    <Settings size={16} />
                    Label
                </button>
                <button
                    className="action-btn"
                    onClick={() => onConfigureIP(iface.name)}
                    title="Configure IP"
                >
                    <Settings size={16} />
                    IP
                </button>
                <button
                    className={`action-btn ${iface.is_up ? 'danger' : 'success'}`}
                    onClick={() => onToggle(iface.name, iface.is_up)}
                    title={iface.is_up ? 'Bring Down' : 'Bring Up'}
                >
                    <Power size={16} />
                    {iface.is_up ? 'Down' : 'Up'}
                </button>
                {onDelete && (
                    <button
                        className="action-btn danger icon-only"
                        onClick={() => onDelete(iface.name)}
                        title="Delete VLAN"
                    >
                        <Trash2 size={16} />
                    </button>
                )}
            </div>
        </div>
    );
};

export default Interfaces;
