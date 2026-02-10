import React, { useState, useEffect } from 'react';
import { authFetch, API_ENDPOINTS } from '../apiConfig';
import {
    FiPlus, FiTrash2, FiLink, FiActivity, FiSettings,
    FiAlertCircle, FiCheckCircle, FiMinusCircle
} from 'react-icons/fi';
import './Bonding.css';

const Bonding = () => {
    const [bonds, setBonds] = useState([]);
    const [interfaces, setInterfaces] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(null);

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
            <div className="bond-header">
                <h2>
                    <Link className="text-primary" />
                    Link Bonding & Aggregation
                </h2>
                <button
                    className="btn btn-primary btn-icon" // Reusing standard button classes if available, otherwise CSS defines them
                    onClick={() => {
                        resetForm();
                        setShowCreateModal(true);
                    }}
                >
                    <Plus /> Create Bond
                </button>
            </div>

            {error && (
                <div className="error-banner">
                    <AlertCircle /> {error}
                </div>
            )}

            {bonds.length === 0 ? (
                <div className="empty-state">
                    <Link className="empty-state-icon" />
                    <h3>No Bond Interfaces</h3>
                    <p>Combine multiple network interfaces for redundancy and increased bandwidth.</p>
                </div>
            ) : (
                <div className="bond-grid">
                    {bonds.map(bond => (
                        <div key={bond.name} className="bond-card">
                            <div className="bond-card-header">
                                <div className="bond-name">
                                    <Activity className={bond.isUp ? "text-success" : "text-danger"} />
                                    {bond.name}
                                </div>
                                <div className="bond-actions">
                                    <span className="status-badge" style={{
                                        backgroundColor: bond.isUp ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                                        color: bond.isUp ? '#10b981' : '#ef4444'
                                    }}>
                                        {bond.isUp ? 'active' : 'down'}
                                    </span>
                                    <button
                                        className="remove-btn"
                                        onClick={() => handleDeleteBond(bond.name)}
                                        title="Delete Bond"
                                    >
                                        <Trash2 />
                                    </button>
                                </div>
                            </div>

                            <div className="bond-card-body">
                                <div className="bond-detail-row">
                                    <span className="detail-label">Mode</span>
                                    <span className="detail-value bond-mode">{bond.mode}</span>
                                </div>
                                <div className="bond-detail-row">
                                    <span className="detail-label">MII Monitor</span>
                                    <span className="detail-value">{bond.miimon} ms</span>
                                </div>
                                <div className="bond-detail-row">
                                    <span className="detail-label">MTU</span>
                                    <span className="detail-value">{bond.mtu}</span>
                                </div>
                                <div className="bond-detail-row">
                                    <span className="detail-label">IP Address</span>
                                    <span className="detail-value">
                                        {bond.ipAddresses && bond.ipAddresses.length > 0
                                            ? bond.ipAddresses.join(', ')
                                            : 'No IP Configured'}
                                    </span>
                                </div>

                                <div className="members-section">
                                    <div className="members-title">
                                        Member Interfaces ({bond.members.length})
                                    </div>
                                    <div className="member-list">
                                        {bond.memberState && bond.memberState.map(member => (
                                            <div key={member.name} className="member-item">
                                                <div className="member-info">
                                                    <div
                                                        className={`member-status-dot ${member.status === 'up' ? 'status-up' : 'status-down'}`}
                                                        title={`Status: ${member.status}`}
                                                    />
                                                    <span className="member-name font-mono">{member.name}</span>
                                                </div>
                                                <div className="member-meta">
                                                    <span className="member-speed">{member.speed}</span>
                                                    <button
                                                        className="remove-btn ml-2"
                                                        onClick={() => handleRemoveMember(bond.name, member.name)}
                                                        title="Remove member"
                                                    >
                                                        <MinusCircle />
                                                    </button>
                                                </div>
                                            </div>
                                        ))}
                                        {(!bond.memberState || bond.memberState.length === 0) && (
                                            <div className="text-secondary text-sm italic">No members</div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Create Bond Modal */}
            {showCreateModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Create Link Bond</h3>
                            <button className="close-btn" onClick={() => setShowCreateModal(false)}>×</button>
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
                                    <p className="help-text">Must strictly follow pattern bond0, bond1, etc.</p>
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
                                    <p className="help-text">
                                        {availableModes.find(m => m.value === newBondMode)?.description}
                                    </p>
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
                                    <p className="help-text">Link monitoring frequency in milliseconds (default: 100)</p>
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
                                                <span className="text-secondary ml-auto text-sm">
                                                    {iface.mac}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                    <p className="help-text text-warning mt-2">
                                        ⚠️ Connection may be interrupted briefly when interfaces are added to bond.
                                    </p>
                                </div>
                            </div>
                            <div className="modal-footer">
                                <button
                                    type="button"
                                    className="btn btn-secondary"
                                    onClick={() => setShowCreateModal(false)}
                                >
                                    Cancel
                                </button>
                                <button type="submit" className="btn btn-primary">
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
