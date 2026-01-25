import React, { useEffect, useState } from 'react';
import { Network, Plus, Trash2, Settings, Power, RefreshCw, X, AlertCircle } from 'lucide-react';
import './Interfaces.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const Interfaces = () => {
    const [interfaces, setInterfaces] = useState([]);
    const [metadata, setMetadata] = useState({});
    const [dhcpConfigs, setDhcpConfigs] = useState({});
    const [loading, setLoading] = useState(true);
    const [showVLANModal, setShowVLANModal] = useState(false);
    const [showIPModal, setShowIPModal] = useState(false);
    const [showDHCPModal, setShowDHCPModal] = useState(false);
    const [showLeasesModal, setShowLeasesModal] = useState(false);
    const [leases, setLeases] = useState([]);
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

    const [dhcpForm, setDhcpForm] = useState({
        interfaceName: '',
        enabled: false,
        startIP: '',
        endIP: '',
        leaseTime: '12h',
        gateway: '',
        dnsServers: []
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
        authFetch(API_ENDPOINTS.INTERFACES)
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
        authFetch(API_ENDPOINTS.INTERFACE_METADATA)
            .then(res => res.json())
            .then(data => {
                setMetadata(data || {});
            })
            .catch(err => {
                console.error('Failed to load metadata:', err);
            });
    };

    const fetchDhcpConfig = () => {
        authFetch(API_ENDPOINTS.DHCP_CONFIG)
            .then(res => res.json())
            .then(data => {
                setDhcpConfigs(data.configs || {});
            })
            .catch(err => {
                console.error('Failed to load DHCP config:', err);
            });
    };

    const fetchLeases = () => {
        authFetch(API_ENDPOINTS.DHCP_LEASES)
            .then(res => res.json())
            .then(data => {
                setLeases(data || []);
            })
            .catch(err => {
                console.error('Failed to load DHCP leases:', err);
            });
    };

    const openLeasesModal = () => {
        fetchLeases();
        setShowLeasesModal(true);
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
            const res = await authFetch(API_ENDPOINTS.INTERFACE_VLAN, {
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
            const res = await authFetch(`${API_ENDPOINTS.INTERFACE_VLAN}?interface=${interfaceName}`, {
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
            const res = await authFetch(API_ENDPOINTS.INTERFACE_IP, {
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
            const res = await authFetch(API_ENDPOINTS.INTERFACE_STATE, {
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
            const res = await authFetch(API_ENDPOINTS.INTERFACE_LABEL, {
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

    const openDHCPModal = (interfaceName) => {
        const existingConfig = dhcpConfigs[interfaceName] || {
            enabled: false,
            startIP: '',
            endIP: '',
            leaseTime: '12h',
            gateway: '',
            dnsServers: []
        };

        setDhcpForm({
            interfaceName,
            enabled: existingConfig.enabled,
            startIP: existingConfig.startIP || '',
            endIP: existingConfig.endIP || '',
            leaseTime: existingConfig.leaseTime || '12h',
            gateway: existingConfig.gateway || '',
            dnsServers: existingConfig.dnsServers || []
        });
        setShowDHCPModal(true);
    };

    const handleSetDhcpConfig = async () => {
        // Simple validation
        if (dhcpForm.enabled && (!dhcpForm.startIP || !dhcpForm.endIP)) {
            alert('Start IP and End IP are required when DHCP is enabled');
            return;
        }

        try {
            const res = await authFetch(API_ENDPOINTS.DHCP_CONFIG, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    interfaceName: dhcpForm.interfaceName,
                    config: {
                        enabled: dhcpForm.enabled,
                        startIP: dhcpForm.startIP,
                        endIP: dhcpForm.endIP,
                        leaseTime: dhcpForm.leaseTime,
                        gateway: dhcpForm.gateway,
                        dnsServers: dhcpForm.dnsServers
                    }
                })
            });

            if (res.ok) {
                setShowDHCPModal(false);
                fetchDhcpConfig();
            } else {
                const text = await res.text();
                alert(`Failed to set DHCP config:\n${text}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    useEffect(() => {
        fetchInterfaces();
        fetchMetadata();
        fetchDhcpConfig();
        // Auto-refresh every 15 seconds
        const interval = setInterval(() => {
            fetchInterfaces();
            fetchMetadata();
            fetchDhcpConfig();
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
                    <button className="primary-btn" onClick={openLeasesModal} style={{ marginRight: '1rem' }}>
                        <Network size={18} />
                        Active Leases
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
                                    dhcpConfig={dhcpConfigs[iface.name]}
                                    onToggle={handleToggleInterface}
                                    onConfigureIP={openIPModal}
                                    onConfigureDHCP={openDHCPModal}
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
                                        dhcpConfig={dhcpConfigs[iface.name]}
                                        onToggle={handleToggleInterface}
                                        onConfigureIP={openIPModal}
                                        onConfigureDHCP={openDHCPModal}
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
            {/* DHCP Configuration Modal */}
            {showDHCPModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Configure DHCP Server</h3>
                            <button className="close-btn" onClick={() => setShowDHCPModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Interface: <strong>{dhcpForm.interfaceName}</strong></label>
                            </div>

                            <div className="form-group checkbox-group">
                                <label className="checkbox-label">
                                    <input
                                        type="checkbox"
                                        checked={dhcpForm.enabled}
                                        onChange={e => setDhcpForm({ ...dhcpForm, enabled: e.target.checked })}
                                    />
                                    Enable DHCP Server on this interface
                                </label>
                            </div>

                            {dhcpForm.enabled && (
                                <>
                                    <div className="form-row">
                                        <div className="form-group">
                                            <label>Start IP Address</label>
                                            <input
                                                type="text"
                                                className="form-input"
                                                value={dhcpForm.startIP}
                                                onChange={e => setDhcpForm({ ...dhcpForm, startIP: e.target.value })}
                                                placeholder="e.g., 192.168.1.50"
                                            />
                                        </div>
                                        <div className="form-group">
                                            <label>End IP Address</label>
                                            <input
                                                type="text"
                                                className="form-input"
                                                value={dhcpForm.endIP}
                                                onChange={e => setDhcpForm({ ...dhcpForm, endIP: e.target.value })}
                                                placeholder="e.g., 192.168.1.150"
                                            />
                                        </div>
                                    </div>

                                    <div className="form-group">
                                        <label>Lease Time</label>
                                        <input
                                            type="text"
                                            className="form-input"
                                            value={dhcpForm.leaseTime}
                                            onChange={e => setDhcpForm({ ...dhcpForm, leaseTime: e.target.value })}
                                            placeholder="e.g., 12h, 7d"
                                        />
                                    </div>

                                    <div className="form-group">
                                        <label>Gateway IP (Optional)</label>
                                        <input
                                            type="text"
                                            className="form-input"
                                            value={dhcpForm.gateway}
                                            onChange={e => setDhcpForm({ ...dhcpForm, gateway: e.target.value })}
                                            placeholder="Leave blank for router IP"
                                        />
                                    </div>

                                    <div className="form-group">
                                        <label>DNS Servers (Optional, Comma Separated)</label>
                                        <input
                                            type="text"
                                            className="form-input"
                                            value={dhcpForm.dnsServers.join(', ')}
                                            onChange={e => setDhcpForm({ ...dhcpForm, dnsServers: e.target.value.split(',').map(s => s.trim()).filter(s => s) })}
                                            placeholder="e.g., 1.1.1.1, 8.8.8.8"
                                        />
                                    </div>
                                </>
                            )}

                            <div className="info-box">
                                <AlertCircle size={16} />
                                <span>DHCP allows devices to automatically get IP addresses when connecting to this interface.</span>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowDHCPModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleSetDhcpConfig}>Save Configuration</button>
                        </div>
                    </div>
                </div>
            )}

            {/* Leases Modal */}
            {showLeasesModal && (
                <div className="modal-overlay">
                    <div className="modal-content large-modal">
                        <div className="modal-header">
                            <h3>Active DHCP Leases</h3>
                            <button className="close-btn" onClick={() => setShowLeasesModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="leases-table-container">
                                {leases.length === 0 ? (
                                    <div className="empty-state">No active leases found</div>
                                ) : (
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th>IP Address</th>
                                                <th>MAC Address</th>
                                                <th>Hostname</th>
                                                <th>Expires</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {leases.map((lease, idx) => (
                                                <tr key={idx}>
                                                    <td>{lease.ip}</td>
                                                    <td>{lease.mac}</td>
                                                    <td>{lease.hostname}</td>
                                                    <td>{lease.expires}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                )}
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="primary-btn" onClick={fetchLeases}>
                                <RefreshCw size={16} /> Refresh
                            </button>
                            <button className="cancel-btn" onClick={() => setShowLeasesModal(false)}>Close</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

// Interface Card Component
const InterfaceCard = ({ iface, metadata, dhcpConfig, onToggle, onConfigureIP, onConfigureDHCP, onSetLabel, onDelete }) => {
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
                    className={`action-btn ${dhcpConfig?.enabled ? 'active-dhcp' : ''}`}
                    onClick={() => onConfigureDHCP(iface.name)}
                    title="Configure DHCP"
                >
                    <Network size={16} />
                    DHCP
                    {dhcpConfig?.enabled && <span className="status-dot"></span>}
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
