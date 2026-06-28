import React, { useState, useEffect } from 'react';
import { authFetch, API_ENDPOINTS } from '../apiConfig';
import {
    Plus, Trash2, Link as LinkIcon, Activity, Settings,
    AlertCircle, CheckCircle, MinusCircle
} from 'lucide-react';
import './Bonding.css';

const Bonding = () => {
    const [bonds, setBonds] = useState([]);
    const [interfaces, setInterfaces] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [showCreateModal, setShowCreateModal] = useState(false);

    // Form state
    const [newBondName, setNewBondName] = useState('bond0');
    const [newBondMode, setNewBondMode] = useState('802.3ad');
    const [selectedMembers, setSelectedMembers] = useState([]);
    const [miimon, setMiimon] = useState(100);

    const availableModes = [
        { value: '802.3ad', label: '802.3ad (LACP) - Dynamic Link Aggregation', description: 'Requires switch configuration. Best for bandwidth & redundancy.' },
        { value: 'active-backup', label: 'Active-Backup - Failover Only', description: 'No switch config required. Redundancy only.' },
        { value: 'balance-rr', label: 'Balance-RR - Round Robin', description: 'Static load balancing. Requires switch config.' },
        { value: 'balance-xor', label: 'Balance-XOR - Hash Policy', description: 'Static balancing based on hash.' },
        { value: 'balance-tlb', label: 'Balance-TLB - Adaptive Load Balancing', description: 'No switch config required. Traffic balancing.' }
    ];

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [bondsRes, ifaceRes] = await Promise.all([
                authFetch(API_ENDPOINTS.BONDS),
                authFetch(API_ENDPOINTS.INTERFACES)
            ]);

            if (!bondsRes.ok || !ifaceRes.ok) throw new Error('Failed to fetch data');

            const bondsData = await bondsRes.json();
            const ifaceData = await ifaceRes.json();

            setBonds(bondsData);
            setInterfaces(ifaceData);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleCreateBond = async (e) => {
        e.preventDefault();

        if (selectedMembers.length === 0) {
            alert('Please select at least one member interface');
            return;
        }

        try {
            const response = await authFetch(API_ENDPOINTS.BONDS, {
                method: 'POST',
                body: JSON.stringify({
                    name: newBondName,
                    members: selectedMembers,
                    mode: newBondMode,
                    miimon: parseInt(miimon)
                })
            });

            if (!response.ok) {
                const errorData = await response.text();
                throw new Error(errorData);
            }

            setShowCreateModal(false);
            resetForm();
            fetchData();
        } catch (err) {
            alert('Error creating bond: ' + err.message);
        }
    };

    const handleDeleteBond = async (bondName) => {
        if (!confirm(`Are you sure you want to delete ${bondName}?`)) return;

        try {
            const response = await authFetch(`${API_ENDPOINTS.BONDS}?name=${bondName}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                const errorData = await response.text();
                throw new Error(errorData);
            }

            fetchData();
        } catch (err) {
            alert('Error deleting bond: ' + err.message);
        }
    };

    const handleRemoveMember = async (bondName, member) => {
        if (!confirm(`Remove ${member} from ${bondName}?`)) return;

        try {
            const response = await authFetch(API_ENDPOINTS.BOND_MEMBER, {
                method: 'DELETE',
                body: JSON.stringify({
                    bondName: bondName,
                    member: member
                })
            });

            if (!response.ok) {
                const errorData = await response.text();
                throw new Error(errorData);
            }

            fetchData();
        } catch (err) {
            alert('Error removing member: ' + err.message);
        }
    };

    const resetForm = () => {
        setNewBondName(`bond${bonds.length}`);
        setNewBondMode('802.3ad');
        setSelectedMembers([]);
        setMiimon(100);
    };

    const toggleMemberSelection = (ifaceName) => {
        setSelectedMembers(prev =>
            prev.includes(ifaceName)
                ? prev.filter(m => m !== ifaceName)
                : [...prev, ifaceName]
        );
    };

    // Filter interfaces that can be added to a bond
    const availableInterfaces = interfaces.filter(iface => {
        // Exclude loopback
        if (iface.name === 'lo') return false;
        // Exclude existing bonds
        if (iface.name.startsWith('bond')) return false;
        // Exclude interfaces that are already members of another bond/bridge
        // (This is a simplified check, ideally backend provides this status)
        return true;
    });

    if (loading) return <div className="loading">Loading bonding configuration...</div>;

    return (
        <div className="bonding-container">
            <div className="section-header">
                <div>
                    <h2>
                        <LinkIcon size={24} className="icon" />
                        Link Bonding & Aggregation
                    </h2>
                    <span className="subtitle">Combine interfaces for redundancy and bandwidth</span>
                </div>
                <div className="header-actions">
                    <button
                        className="primary-btn"
                        onClick={() => {
                            resetForm();
                            setShowCreateModal(true);
                        }}
                    >
                        <Plus size={18} />
                        Create Bond
                    </button>
                </div>
            </div>

            {error && (
                <div className="error-banner">
                    <AlertCircle size={20} />
                    <span>{error}</span>
                </div>
            )}

            {loading ? (
                <div className="loading-state">Loading bonding configuration...</div>
            ) : (
                <>
                    {bonds.length === 0 ? (
                        <div className="empty-state">
                            <LinkIcon className="empty-state-icon" />
                            <h3>No Bond Interfaces</h3>
                            <p>Combine multiple network interfaces for redundancy and increased bandwidth.</p>
                        </div>
                    ) : (
                        <div className="bond-grid">
                            {bonds.map(bond => (
                                <div key={bond.name} className={`bond-card ${bond.isUp ? 'active' : 'inactive'}`}>
                                    <div className="bond-card-header">
                                        <div className="bond-title">
                                            <Activity size={20} className="icon" />
                                            <h3>{bond.name}</h3>
                                        </div>
                                        <span className={`status-badge ${bond.isUp ? 'up' : 'down'}`}>
                                            {bond.isUp ? 'active' : 'down'}
                                        </span>
                                    </div>

                                    <div className="bond-details">
                                        <div className="detail-row">
                                            <span className="label">Mode</span>
                                            <span className="value">{bond.mode}</span>
                                        </div>
                                        <div className="detail-row">
                                            <span className="label">MII Monitor</span>
                                            <span className="value">{bond.miimon} ms</span>
                                        </div>
                                        <div className="detail-row">
                                            <span className="label">MTU</span>
                                            <span className="value">{bond.mtu}</span>
                                        </div>
                                        <div className="detail-row">
                                            <span className="label">IP Address</span>
                                            <span className="value">
                                                {bond.ipAddresses && bond.ipAddresses.length > 0
                                                    ? bond.ipAddresses.join(', ')
                                                    : 'No IP Configured'}
                                            </span>
                                        </div>

                                        <div className="detail-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '0.5rem' }}>
                                            <span className="label">Member Interfaces ({bond.members.length})</span>
                                            <div className="member-list">
                                                {bond.memberState && bond.memberState.map(member => (
                                                    <div key={member.name} className="member-tag">
                                                        <div
                                                            className={`member-status-dot ${member.status === 'up' ? 'status-up-dot' : 'status-down-dot'}`}
                                                            title={`Status: ${member.status}`}
                                                        />
                                                        <span>{member.name}</span>
                                                        <span className="member-speed">{member.speed}</span>
                                                        <button
                                                            className="remove-member-btn"
                                                            onClick={() => handleRemoveMember(bond.name, member.name)}
                                                            title="Remove member"
                                                        >
                                                            <MinusCircle size={14} />
                                                        </button>
                                                    </div>
                                                ))}
                                                {(!bond.memberState || bond.memberState.length === 0) && (
                                                    <span className="no-members">No members</span>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="bond-actions">
                                        <button
                                            className="action-btn"
                                            onClick={() => {/* Placeholder for future settings */ }}
                                            title="Settings"
                                        >
                                            <Settings size={16} />
                                            Configure
                                        </button>
                                        <button
                                            className="action-btn danger"
                                            onClick={() => handleDeleteBond(bond.name)}
                                            title="Delete Bond"
                                        >
                                            <Trash2 size={16} />
                                            Delete
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </>
            )}

            {/* Create Bond Modal */}
            {showCreateModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Create Link Bond</h3>
                            <button className="close-btn" onClick={() => setShowCreateModal(false)}>
                                <MinusCircle size={20} style={{ transform: 'rotate(45deg)' }} />
                            </button>
                        </div>
                        <form onSubmit={handleCreateBond}>
                            <div className="modal-body">
                                <div className="form-group">
                                    <label>Bond Name</label>
                                    <input
                                        type="text"
                                        className="form-input"
                                        value={newBondName}
                                        onChange={(e) => setNewBondName(e.target.value)}
                                        placeholder="bond0"
                                        pattern="bond[0-9]+"
                                        required
                                    />
                                    <span className="help-text">Must strictly follow pattern bond0, bond1, etc.</span>
                                </div>

                                <div className="form-group">
                                    <label>Bonding Mode</label>
                                    <select
                                        className="form-select"
                                        value={newBondMode}
                                        onChange={(e) => setNewBondMode(e.target.value)}
                                    >
                                        {availableModes.map(mode => (
                                            <option key={mode.value} value={mode.value}>
                                                {mode.label}
                                            </option>
                                        ))}
                                    </select>
                                    <span className="help-text">
                                        {availableModes.find(m => m.value === newBondMode)?.description}
                                    </span>
                                </div>

                                <div className="form-group">
                                    <label>Monitoring Interval (miimon)</label>
                                    <input
                                        type="number"
                                        className="form-input"
                                        value={miimon}
                                        onChange={(e) => setMiimon(e.target.value)}
                                        min="0"
                                        max="10000"
                                    />
                                    <span className="help-text">Link monitoring frequency in milliseconds (default: 100)</span>
                                </div>

                                <div className="form-group">
                                    <label>Select Member Interfaces</label>
                                    <div className="interface-select-list">
                                        {availableInterfaces.map(iface => (
                                            <div
                                                key={iface.name}
                                                className={`interface-option ${selectedMembers.includes(iface.name) ? 'selected' : ''}`}
                                                onClick={() => toggleMemberSelection(iface.name)}
                                            >
                                                <input
                                                    type="checkbox"
                                                    checked={selectedMembers.includes(iface.name)}
                                                    onChange={() => { }} // Handled by onClick parent
                                                />
                                                <span className="font-mono">{iface.name}</span>
                                                <span className="text-secondary ml-auto text-sm" style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                                                    {iface.mac}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                    <span className="help-text" style={{ color: '#f59e0b' }}>
                                        Warning: Selected interfaces will be disconnected momentarily.
                                    </span>
                                </div>
                            </div>
                            <div className="modal-footer">
                                <button type="button" className="action-btn" onClick={() => setShowCreateModal(false)}>
                                    Cancel
                                </button>
                                <button type="submit" className="primary-btn">
                                    Create Bond
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};


export default Bonding;
