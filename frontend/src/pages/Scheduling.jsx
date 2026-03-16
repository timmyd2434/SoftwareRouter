import React, { useEffect, useState } from 'react';
import { Clock, Plus, X, Edit2, Trash2, Network } from 'lucide-react';
import './Scheduling.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const ALL_DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

const Scheduling = () => {
    const [schedules, setSchedules] = useState([]);
    const [interfaces, setInterfaces] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [editingId, setEditingId] = useState(null);
    const [message, setMessage] = useState(null);

    const emptyForm = {
        interface_name: '',
        down_time: '22:00',
        up_time: '06:00',
        days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        enabled: true,
        comment: ''
    };
    const [form, setForm] = useState(emptyForm);

    // Fetch schedules
    const fetchSchedules = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.SCHEDULES);
            if (res.ok) {
                const data = await res.json();
                setSchedules(Array.isArray(data) ? data : []);
            }
        } catch (err) {
            console.error('Failed to fetch schedules:', err);
        } finally {
            setLoading(false);
        }
    };

    // Fetch interfaces for the dropdown
    const fetchInterfaces = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.INTERFACES);
            if (res.ok) {
                const data = await res.json();
                setInterfaces(
                    (data || []).filter(
                        (i) => i.name !== 'lo' && !i.name.startsWith('veth')
                    )
                );
            }
        } catch (err) {
            console.error('Failed to fetch interfaces:', err);
        }
    };

    useEffect(() => {
        fetchSchedules();
        fetchInterfaces();
    }, []);

    const showMsg = (type, text) => {
        setMessage({ type, text });
        setTimeout(() => setMessage(null), 4000);
    };

    // Create or update
    const saveSchedule = async () => {
        if (!form.interface_name) {
            showMsg('error', 'Please select an interface');
            return;
        }
        if (form.days.length === 0) {
            showMsg('error', 'Select at least one day');
            return;
        }

        const method = editingId ? 'PUT' : 'POST';
        const body = editingId ? { ...form, id: editingId } : form;

        try {
            const res = await authFetch(API_ENDPOINTS.SCHEDULES, {
                method,
                body: JSON.stringify(body)
            });

            if (res.ok) {
                showMsg('success', editingId ? '✓ Schedule updated' : '✓ Schedule created');
                setShowModal(false);
                setEditingId(null);
                setForm(emptyForm);
                fetchSchedules();
            } else {
                const text = await res.text();
                showMsg('error', `Failed: ${text}`);
            }
        } catch (err) {
            showMsg('error', err.message);
        }
    };

    // Toggle enabled
    const toggleEnabled = async (sched) => {
        const updated = { ...sched, enabled: !sched.enabled };
        try {
            const res = await authFetch(API_ENDPOINTS.SCHEDULES, {
                method: 'PUT',
                body: JSON.stringify(updated)
            });
            if (res.ok) {
                fetchSchedules();
            }
        } catch (err) {
            showMsg('error', err.message);
        }
    };

    // Delete
    const deleteSchedule = async (id) => {
        if (!confirm('Delete this schedule?')) return;
        try {
            const res = await authFetch(`${API_ENDPOINTS.SCHEDULES}?id=${id}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                showMsg('success', '✓ Schedule deleted');
                fetchSchedules();
            }
        } catch (err) {
            showMsg('error', err.message);
        }
    };

    // Open edit modal
    const openEdit = (sched) => {
        setEditingId(sched.id);
        setForm({
            interface_name: sched.interface_name,
            down_time: sched.down_time,
            up_time: sched.up_time,
            days: [...sched.days],
            enabled: sched.enabled,
            comment: sched.comment || ''
        });
        setShowModal(true);
    };

    // Toggle day in form
    const toggleDay = (day) => {
        setForm((prev) => ({
            ...prev,
            days: prev.days.includes(day)
                ? prev.days.filter((d) => d !== day)
                : [...prev.days, day]
        }));
    };

    return (
        <div className="scheduling-container">
            <div className="page-header">
                <div>
                    <h1 className="page-title">
                        <Clock size={28} className="title-icon" />
                        Interface Scheduling
                    </h1>
                    <p className="page-subtitle">
                        Schedule automatic interface downtime windows
                    </p>
                </div>
            </div>

            {message && (
                <div className={`sched-alert ${message.type}`}>{message.text}</div>
            )}

            {/* Schedules Table */}
            <div className="glass-panel" style={{ marginBottom: 'var(--space-6)' }}>
                <div
                    style={{
                        padding: 'var(--space-6)',
                        borderBottom: '1px solid var(--glass-border)'
                    }}
                >
                    <div
                        style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center'
                        }}
                    >
                        <div>
                            <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Schedules</h3>
                            <p
                                style={{
                                    margin: '4px 0 0 0',
                                    fontSize: '0.85rem',
                                    color: 'var(--text-muted)'
                                }}
                            >
                                {schedules.length} schedule{schedules.length !== 1 ? 's' : ''}{' '}
                                configured
                            </p>
                        </div>
                        <button
                            className="primary-btn"
                            onClick={() => {
                                setEditingId(null);
                                setForm(emptyForm);
                                setShowModal(true);
                            }}
                        >
                            <Plus size={18} />
                            Add Schedule
                        </button>
                    </div>
                </div>

                <div style={{ padding: 'var(--space-4)', overflowX: 'auto' }}>
                    {loading ? (
                        <div className="schedule-empty">Loading schedules...</div>
                    ) : schedules.length === 0 ? (
                        <div className="schedule-empty">
                            <Clock size={48} style={{ opacity: 0.3 }} />
                            <p>No schedules configured</p>
                            <p>Create a schedule to automatically bring an interface down during specific hours</p>
                        </div>
                    ) : (
                        <table className="schedule-table">
                            <thead>
                                <tr>
                                    <th>Interface</th>
                                    <th>Down / Up</th>
                                    <th>Days</th>
                                    <th>Comment</th>
                                    <th>Enabled</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {schedules.map((s) => (
                                    <tr key={s.id}>
                                        <td>
                                            <span className="iface-badge">
                                                <Network size={14} />
                                                {s.interface_name}
                                            </span>
                                        </td>
                                        <td>
                                            <span className="time-display">{s.down_time}</span>
                                            <span className="time-arrow">→</span>
                                            <span className="time-display">{s.up_time}</span>
                                        </td>
                                        <td>
                                            <div className="day-pills">
                                                {ALL_DAYS.map((d) => (
                                                    <span
                                                        key={d}
                                                        className="day-pill"
                                                        style={{
                                                            opacity: s.days.includes(d) ? 1 : 0.2
                                                        }}
                                                    >
                                                        {d}
                                                    </span>
                                                ))}
                                            </div>
                                        </td>
                                        <td>
                                            <span className="schedule-comment">
                                                {s.comment || '—'}
                                            </span>
                                        </td>
                                        <td>
                                            <label className="toggle-switch">
                                                <input
                                                    type="checkbox"
                                                    checked={s.enabled}
                                                    onChange={() => toggleEnabled(s)}
                                                />
                                                <span className="toggle-slider" />
                                            </label>
                                        </td>
                                        <td>
                                            <div className="schedule-actions">
                                                <button
                                                    className="icon-btn-sm"
                                                    title="Edit"
                                                    onClick={() => openEdit(s)}
                                                >
                                                    <Edit2 size={16} />
                                                </button>
                                                <button
                                                    className="icon-btn-sm"
                                                    title="Delete"
                                                    onClick={() => deleteSchedule(s.id)}
                                                >
                                                    <Trash2 size={16} />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>

                <div style={{ padding: '0 var(--space-6) var(--space-4)' }}>
                    <div className="sched-info-box">
                        <strong>How it works:</strong> The scheduler checks every 30 seconds. During
                        the down window the interface is brought offline; outside the window it is
                        restored. Disabling a schedule immediately restores the interface.
                    </div>
                </div>
            </div>

            {/* Add/Edit Modal */}
            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>{editingId ? 'Edit Schedule' : 'Add Schedule'}</h3>
                            <button
                                className="close-btn"
                                onClick={() => setShowModal(false)}
                            >
                                <X size={20} />
                            </button>
                        </div>

                        <div className="modal-body">
                            {/* Interface */}
                            <div className="form-group">
                                <label>Interface *</label>
                                <select
                                    className="form-input"
                                    value={form.interface_name}
                                    onChange={(e) =>
                                        setForm({ ...form, interface_name: e.target.value })
                                    }
                                >
                                    <option value="">Select interface…</option>
                                    {interfaces.map((iface) => (
                                        <option key={iface.name} value={iface.name}>
                                            {iface.name}{' '}
                                            {iface.ip_addresses?.length
                                                ? `(${iface.ip_addresses[0]})`
                                                : ''}
                                        </option>
                                    ))}
                                </select>
                            </div>

                            {/* Down / Up times */}
                            <div style={{ display: 'flex', gap: 'var(--space-4)' }}>
                                <div className="form-group" style={{ flex: 1 }}>
                                    <label>Interface Down At *</label>
                                    <input
                                        type="time"
                                        className="form-input time-input"
                                        value={form.down_time}
                                        onChange={(e) =>
                                            setForm({ ...form, down_time: e.target.value })
                                        }
                                    />
                                </div>
                                <div className="form-group" style={{ flex: 1 }}>
                                    <label>Interface Up At *</label>
                                    <input
                                        type="time"
                                        className="form-input time-input"
                                        value={form.up_time}
                                        onChange={(e) =>
                                            setForm({ ...form, up_time: e.target.value })
                                        }
                                    />
                                </div>
                            </div>

                            {/* Days */}
                            <div className="form-group">
                                <label>Active Days *</label>
                                <div className="day-selector">
                                    {ALL_DAYS.map((d) => (
                                        <React.Fragment key={d}>
                                            <input
                                                type="checkbox"
                                                className="day-checkbox"
                                                id={`day-${d}`}
                                                checked={form.days.includes(d)}
                                                onChange={() => toggleDay(d)}
                                            />
                                            <label htmlFor={`day-${d}`} className="day-label">
                                                {d}
                                            </label>
                                        </React.Fragment>
                                    ))}
                                </div>
                            </div>

                            {/* Comment */}
                            <div className="form-group">
                                <label>Comment</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="e.g. Kids bedtime internet block"
                                    value={form.comment}
                                    onChange={(e) =>
                                        setForm({ ...form, comment: e.target.value })
                                    }
                                />
                            </div>
                        </div>

                        <div className="modal-footer">
                            <button
                                className="cancel-btn"
                                onClick={() => setShowModal(false)}
                            >
                                Cancel
                            </button>
                            <button className="primary-btn" onClick={saveSchedule}>
                                {editingId ? 'Update' : 'Create'} Schedule
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Scheduling;
