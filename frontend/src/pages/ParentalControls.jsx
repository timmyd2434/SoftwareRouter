import React, { useState, useEffect } from 'react';
import { ShieldAlert, Plus, Trash2, Save, Clock, Users, X, Edit2, AlertTriangle } from 'lucide-react';
import { authFetch, API_BASE_URL } from '../apiConfig';
import './ParentalControls.css';

const ParentalControls = () => {
    const [policies, setPolicies] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState('');
    const [successMsg, setSuccessMsg] = useState('');

    const [isEditing, setIsEditing] = useState(false);
    const [currentPolicy, setCurrentPolicy] = useState(null);

    const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

    useEffect(() => {
        fetchPolicies();
        // Poll for active status every 30 seconds
        const poll = setInterval(fetchPolicies, 30000);
        return () => clearInterval(poll);
    }, []);

    const fetchPolicies = async () => {
        try {
            const res = await authFetch(`${API_BASE_URL}/api/parental/config`);
            if (res.ok) {
                const data = await res.json();
                setPolicies(data.policies || []);
            }
        } catch (err) {
            console.error('Failed to fetch parental policies:', err);
            setError('Failed to load parental control configurations');
        } finally {
            setLoading(false);
        }
    };

    const handleSaveConfig = async (newPoliciesList) => {
        setSaving(true);
        setError('');
        setSuccessMsg('');
        try {
            const res = await authFetch(`${API_BASE_URL}/api/parental/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ policies: newPoliciesList })
            });

            if (res.ok) {
                setPolicies(newPoliciesList); // optimistic, wait for next poll to get 'active' state
                setSuccessMsg('Configuration saved successfully');
                setIsEditing(false);
                setTimeout(() => setSuccessMsg(''), 3000);
                fetchPolicies(); // re-fetch to get 'active' state
            } else {
                setError('Failed to update config on server');
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setSaving(false);
        }
    };

    const togglePolicyEnable = (id, currentEnabled) => {
        const updated = policies.map(p => {
            if (p.id === id) {
                return { ...p, enabled: !currentEnabled };
            }
            return p;
        });
        handleSaveConfig(updated);
    };

    const deletePolicy = (id) => {
        if (!window.confirm("Are you sure you want to delete this policy?")) return;
        const updated = policies.filter(p => p.id !== id);
        handleSaveConfig(updated);
    };

    const openCreateModal = () => {
        setCurrentPolicy({
            id: 'policy_' + Date.now(),
            name: '',
            mac_addresses: [],
            enabled: true,
            scheduled: false,
            start_time: '20:00',
            end_time: '07:00',
            days_of_week: [1, 2, 3, 4, 5] // Mon-Fri
        });
        setIsEditing(true);
    };

    const openEditModal = (p) => {
        setCurrentPolicy({ ...p, mac_addresses: [...p.mac_addresses], days_of_week: [...p.days_of_week] });
        setIsEditing(true);
    };

    const saveCurrentPolicy = () => {
        if (!currentPolicy.name) {
            alert("Please provide a name for the policy");
            return;
        }

        const exactMatchIndex = policies.findIndex(p => p.id === currentPolicy.id);
        let updatedList = [...policies];
        if (exactMatchIndex >= 0) {
            updatedList[exactMatchIndex] = currentPolicy;
        } else {
            updatedList = [...updatedList, currentPolicy];
        }

        handleSaveConfig(updatedList);
    };

    // Modal helpers
    const updateCurrent = (field, val) => setCurrentPolicy(prev => ({ ...prev, [field]: val }));

    const handleMACChange = (index, val) => {
        const macs = [...currentPolicy.mac_addresses];
        macs[index] = val;
        updateCurrent('mac_addresses', macs);
    };

    const addMAC = () => updateCurrent('mac_addresses', [...currentPolicy.mac_addresses, '']);
    
    const removeMAC = (index) => {
        const macs = [...currentPolicy.mac_addresses];
        macs.splice(index, 1);
        updateCurrent('mac_addresses', macs);
    };

    const toggleDay = (dayIndex) => {
        let days = [...currentPolicy.days_of_week];
        if (days.includes(dayIndex)) {
            days = days.filter(d => d !== dayIndex);
        } else {
            days.push(dayIndex);
            days.sort();
        }
        updateCurrent('days_of_week', days);
    };

    return (
        <div className="parental-page">
            <div className="page-header">
                <div className="title-area">
                    <ShieldAlert size={28} className="text-danger" />
                    <div>
                        <h2>Parental Controls</h2>
                        <p className="subtitle">Block network access for specific devices conditionally or permanently</p>
                    </div>
                </div>
                <div className="header-actions">
                    <button className="primary-btn" onClick={openCreateModal}>
                        <Plus size={16} /> New Policy
                    </button>
                </div>
            </div>

            {error && <div className="alert alert-error"><AlertTriangle size={16} /> {error}</div>}
            {successMsg && <div className="alert alert-success">{successMsg}</div>}

            <div className="policies-grid">
                {loading && policies.length === 0 ? (
                    <div className="loading-state">Loading policies...</div>
                ) : policies.length === 0 ? (
                    <div className="empty-state">
                        <Users size={48} className="text-secondary" style={{ opacity: 0.5, marginBottom: '1rem' }} />
                        <h3>No Policies Found</h3>
                        <p>Create a policy to manage access for your kids' devices.</p>
                        <button className="primary-btn mt" onClick={openCreateModal}>
                            Create First Policy
                        </button>
                    </div>
                ) : (
                    policies.map((p) => (
                        <div key={p.id} className={`policy-card glass-panel ${p.active ? 'is-active' : ''}`}>
                            <div className="policy-card-header">
                                <div className="header-left">
                                    <h3>{p.name}</h3>
                                    {p.active ? (
                                        <span className="badge badge-danger">BLOCKING</span>
                                    ) : (
                                        <span className="badge badge-idle">WATCHING</span>
                                    )}
                                </div>
                                <div className="header-right">
                                    <label className="switch switch-sm">
                                        <input 
                                            type="checkbox" 
                                            checked={p.enabled} 
                                            onChange={() => togglePolicyEnable(p.id, p.enabled)} 
                                            disabled={saving}
                                        />
                                        <span className="slider"></span>
                                    </label>
                                </div>
                            </div>
                            <div className="policy-card-body">
                                <div className="info-row">
                                    <span className="label">Devices:</span>
                                    <span className="value">{p.mac_addresses.length} MAC{p.mac_addresses.length !== 1 ? 's' : ''}</span>
                                </div>
                                <div className="info-row">
                                    <span className="label">Schedule:</span>
                                    <span className="value">
                                        {p.scheduled ? (
                                            <span className="flex-center gap-sm"><Clock size={14} /> {p.start_time} - {p.end_time}</span>
                                        ) : (
                                            "Always On (Manual)"
                                        )}
                                    </span>
                                </div>
                                {p.scheduled && (
                                    <div className="days-row">
                                        {DAYS.map((day, i) => (
                                            <span key={i} className={`day-pill ${p.days_of_week.includes(i) ? 'active' : ''}`}>
                                                {day.charAt(0)}
                                            </span>
                                        ))}
                                    </div>
                                )}
                            </div>
                            <div className="policy-card-actions">
                                <button className="icon-btn" onClick={() => openEditModal(p)} title="Edit"><Edit2 size={16} /></button>
                                <button className="icon-btn text-danger" onClick={() => deletePolicy(p.id)} title="Delete"><Trash2 size={16} /></button>
                            </div>
                        </div>
                    ))
                )}
            </div>

            {/* Editor Modal */}
            {isEditing && currentPolicy && (
                <div className="modal-overlay">
                    <div className="modal-content glass-panel" style={{ maxWidth: '500px' }}>
                        <div className="modal-header">
                            <h3>{currentPolicy.id.startsWith('policy_') ? 'Create Policy' : 'Edit Policy'}</h3>
                            <button className="icon-btn" onClick={() => setIsEditing(false)}><X size={20} /></button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group mb">
                                <label>Policy Name</label>
                                <input 
                                    type="text" 
                                    className="form-input" 
                                    placeholder="e.g. Kids Tablets"
                                    value={currentPolicy.name}
                                    onChange={(e) => updateCurrent('name', e.target.value)}
                                />
                            </div>

                            <div className="form-group mb">
                                <label>Target Devices (MAC Addresses)</label>
                                <div className="mac-list">
                                    {currentPolicy.mac_addresses.map((mac, idx) => (
                                        <div key={idx} className="flex-center gap-sm mb-sm">
                                            <input 
                                                type="text" 
                                                className="form-input" 
                                                placeholder="AA:BB:CC:DD:EE:FF"
                                                value={mac}
                                                onChange={(e) => handleMACChange(idx, e.target.value)}
                                                style={{ flex: 1, fontFamily: 'monospace' }}
                                            />
                                            <button className="icon-btn text-danger" onClick={() => removeMAC(idx)}>
                                                <Trash2 size={16} />
                                            </button>
                                        </div>
                                    ))}
                                    <button className="secondary-btn btn-sm mt-sm" onClick={addMAC}>
                                        <Plus size={14} /> Add Device MAC
                                    </button>
                                </div>
                            </div>

                            <div className="form-group mb card schedule-card">
                                <div className="flex-between mb-sm">
                                    <label style={{ margin: 0 }}>Enable Time Schedule</label>
                                    <label className="switch switch-sm">
                                        <input 
                                            type="checkbox" 
                                            checked={currentPolicy.scheduled} 
                                            onChange={(e) => updateCurrent('scheduled', e.target.checked)} 
                                        />
                                        <span className="slider"></span>
                                    </label>
                                </div>

                                {currentPolicy.scheduled && (
                                    <>
                                        <p className="hint text-muted mb">Devices will only be BLOCKED during this window.</p>
                                        <div className="time-inputs flex-center gap mb">
                                            <div className="flex-1">
                                                <label className="text-xs">Start Time (Block)</label>
                                                <input 
                                                    type="time" 
                                                    className="form-input" 
                                                    value={currentPolicy.start_time}
                                                    onChange={(e) => updateCurrent('start_time', e.target.value)}
                                                />
                                            </div>
                                            <div className="flex-col" style={{ marginTop: '1rem' }}>to</div>
                                            <div className="flex-1">
                                                <label className="text-xs">End Time (Allow)</label>
                                                <input 
                                                    type="time" 
                                                    className="form-input" 
                                                    value={currentPolicy.end_time}
                                                    onChange={(e) => updateCurrent('end_time', e.target.value)}
                                                />
                                            </div>
                                        </div>
                                        
                                        <label className="text-xs">Active Days</label>
                                        <div className="days-selector flex-center gap-sm mt-sm">
                                            {DAYS.map((day, i) => (
                                                <button 
                                                    key={i}
                                                    className={`day-btn ${currentPolicy.days_of_week.includes(i) ? 'active' : ''}`}
                                                    onClick={() => toggleDay(i)}
                                                >
                                                    {day}
                                                </button>
                                            ))}
                                        </div>
                                    </>
                                )}
                            </div>
                        </div>
                        <div className="modal-footer flex-end gap">
                            <button className="secondary-btn" onClick={() => setIsEditing(false)}>Cancel</button>
                            <button className="primary-btn" onClick={saveCurrentPolicy} disabled={saving}>
                                {saving ? 'Saving...' : <><Save size={16} /> Save Policy</>}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ParentalControls;
