import React, { useState, useEffect } from 'react';
import { Trash2, Plus, Save, X, Edit2, ShieldCheck, ShieldAlert } from 'lucide-react';
import { API_ENDPOINTS, authFetch } from '../apiConfig';
import './PortForwarding.css';
import './GuestAccess.css';

const emptyForm = { name: '', destination: '', protocol: 'tcp', ports: '' };

// "443, 80" -> { ports: [443, 80] } or { error: '...' }
const parsePorts = (text) => {
    const parts = text.split(/[\s,]+/).filter(Boolean);
    if (parts.length === 0) return { error: 'Enter at least one port.' };
    if (parts.length > 16) return { error: 'At most 16 ports per rule.' };
    const ports = [];
    for (const part of parts) {
        const n = Number(part);
        if (!Number.isInteger(n) || n < 1 || n > 65535) {
            return { error: `"${part}" is not a valid port (1-65535).` };
        }
        ports.push(n);
    }
    return { ports };
};

// The backend answers validation problems with plain text and system errors with JSON.
const readError = async (response, fallback) => {
    try {
        const text = (await response.text()).trim();
        if (!text) return fallback;
        try {
            const json = JSON.parse(text);
            return json.message || json.error || fallback;
        } catch {
            return text;
        }
    } catch {
        return fallback;
    }
};

const GuestAccess = () => {
    const [rules, setRules] = useState([]);
    const [guestInterfaces, setGuestInterfaces] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const [showModal, setShowModal] = useState(false);
    const [editingRule, setEditingRule] = useState(null);
    const [form, setForm] = useState(emptyForm);
    const [formError, setFormError] = useState(null);

    useEffect(() => {
        fetchRules();
    }, []);

    const fetchRules = async () => {
        try {
            setLoading(true);
            const response = await authFetch(API_ENDPOINTS.GUEST_ACCESS);
            if (!response.ok) throw new Error(await readError(response, 'Failed to load guest access rules'));
            const data = await response.json();
            setRules(data.rules || []);
            setGuestInterfaces(data.guest_interfaces || []);
            setError(null);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const closeModal = () => {
        setShowModal(false);
        setEditingRule(null);
        setForm(emptyForm);
        setFormError(null);
    };

    const openAdd = () => {
        setEditingRule(null);
        setForm(emptyForm);
        setFormError(null);
        setShowModal(true);
    };

    const openEdit = (rule) => {
        setEditingRule(rule);
        setForm({
            name: rule.name || '',
            destination: rule.destination,
            protocol: rule.protocol || 'tcp',
            ports: (rule.ports || []).join(', ')
        });
        setFormError(null);
        setShowModal(true);
    };

    const send = async (method, id, payload) => {
        const url = id ? `${API_ENDPOINTS.GUEST_ACCESS}?id=${encodeURIComponent(id)}` : API_ENDPOINTS.GUEST_ACCESS;
        const response = await authFetch(url, {
            method,
            headers: payload ? { 'Content-Type': 'application/json' } : undefined,
            body: payload ? JSON.stringify(payload) : undefined
        });
        if (!response.ok) throw new Error(await readError(response, 'The change was not applied'));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const parsed = parsePorts(form.ports);
        if (parsed.error) {
            setFormError(parsed.error);
            return;
        }
        const payload = {
            name: form.name,
            destination: form.destination,
            protocol: form.protocol,
            ports: parsed.ports,
            enabled: editingRule ? editingRule.enabled : true
        };
        try {
            setBusy(true);
            await send(editingRule ? 'PUT' : 'POST', editingRule ? editingRule.id : null, payload);
            closeModal();
            fetchRules();
        } catch (err) {
            setFormError(err.message);
        } finally {
            setBusy(false);
        }
    };

    const handleToggle = async (rule) => {
        try {
            setBusy(true);
            await send('PUT', rule.id, { ...rule, enabled: !rule.enabled });
            await fetchRules();
        } catch (err) {
            setError(err.message);
        } finally {
            setBusy(false);
        }
    };

    const handleDelete = async (rule) => {
        if (!window.confirm(`Remove the exception "${rule.name || rule.destination}"? Isolated devices will lose access to it.`)) return;
        try {
            setBusy(true);
            await send('DELETE', rule.id);
            await fetchRules();
        } catch (err) {
            setError(err.message);
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="port-forwarding-page guest-access-page">
            <div className="page-header">
                <div>
                    <h1>Guest / IoT Access</h1>
                    <p className="subtitle">Isolated networks reach the internet only. Allow specific internal services here.</p>
                </div>
                <button className="btn-primary" onClick={openAdd} disabled={busy}>
                    <Plus size={18} />
                    Add Exception
                </button>
            </div>

            {error && <div className="guest-error">{error}</div>}

            {!loading && (guestInterfaces.length > 0 ? (
                <div className="guest-status ok">
                    <ShieldCheck size={20} />
                    <div>
                        <strong>Isolated: </strong>
                        {guestInterfaces.map((name) => (
                            <span className="guest-chip" key={name}>{name}</span>
                        ))}
                        <p>
                            Devices on {guestInterfaces.length > 1 ? 'these networks' : 'this network'} can use DHCP and DNS
                            on the router, reach the internet, and reach the destinations below. Your LAN, the router's
                            admin pages and SSH are blocked.
                        </p>
                    </div>
                </div>
            ) : (
                <div className="guest-status warn">
                    <ShieldAlert size={20} />
                    <div>
                        <strong>No network is isolated yet.</strong>
                        <p>
                            Set the label of an interface (for example a VLAN for your TVs) to Guest or IoT on the
                            Interfaces page. Until then, these exceptions have no effect and unlabelled interfaces
                            are treated as trusted LAN.
                        </p>
                    </div>
                </div>
            ))}

            <div className="rules-list">
                {loading ? (
                    <div className="loading">Loading exceptions...</div>
                ) : rules.length === 0 ? (
                    <div className="empty-state">
                        <p>No exceptions. Isolated devices can reach the internet and nothing else.</p>
                        <p className="guest-hint">Example: allow your TVs to reach Jellyfin through your reverse proxy at 192.168.3.102 on port 443.</p>
                    </div>
                ) : (
                    <div className="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Destination</th>
                                    <th>Protocol</th>
                                    <th>Ports</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rules.map((rule) => (
                                    <tr key={rule.id} className={rule.enabled ? '' : 'guest-rule-off'}>
                                        <td>{rule.name || '-'}</td>
                                        <td className="target-cell">{rule.destination}</td>
                                        <td><span className={`badge ${rule.protocol === 'udp' ? 'udp' : 'tcp'}`}>{(rule.protocol || 'tcp').toUpperCase()}</span></td>
                                        <td className="port-cell">{(rule.ports || []).join(', ')}</td>
                                        <td>
                                            <label className="toggle-switch">
                                                <input
                                                    type="checkbox"
                                                    checked={rule.enabled}
                                                    disabled={busy}
                                                    onChange={() => handleToggle(rule)}
                                                />
                                                <span className="toggle-slider"></span>
                                            </label>
                                        </td>
                                        <td>
                                            <button className="btn-icon" onClick={() => openEdit(rule)} disabled={busy} title="Edit exception">
                                                <Edit2 size={16} />
                                            </button>
                                            <button className="btn-icon danger" onClick={() => handleDelete(rule)} disabled={busy} title="Remove exception">
                                                <Trash2 size={16} />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {showModal && (
                <div className="modal-overlay">
                    <div className="modal">
                        <div className="modal-header">
                            <h2>{editingRule ? 'Edit' : 'Add'} Exception</h2>
                            <button className="btn-icon" onClick={closeModal} aria-label="Close">
                                <X size={20} />
                            </button>
                        </div>
                        <form onSubmit={handleSubmit}>
                            <div className="form-group">
                                <label>Name</label>
                                <input
                                    type="text"
                                    maxLength={64}
                                    placeholder="e.g. Jellyfin via reverse proxy"
                                    value={form.name}
                                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                                />
                            </div>

                            <div className="form-group">
                                <label>Destination</label>
                                <input
                                    type="text"
                                    required
                                    placeholder="192.168.3.102"
                                    value={form.destination}
                                    onChange={(e) => setForm({ ...form, destination: e.target.value })}
                                />
                                <span className="guest-hint">An IPv4 address, or a network such as 192.168.3.0/24.</span>
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label>Protocol</label>
                                    <select
                                        value={form.protocol}
                                        onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                                    >
                                        <option value="tcp">TCP</option>
                                        <option value="udp">UDP</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Ports</label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="443"
                                        value={form.ports}
                                        onChange={(e) => setForm({ ...form, ports: e.target.value })}
                                    />
                                    <span className="guest-hint">Separate several with commas: 80, 443</span>
                                </div>
                            </div>

                            {formError && <div className="guest-error" role="alert">{formError}</div>}

                            <div className="modal-actions">
                                <button type="button" className="btn-secondary" onClick={closeModal}>
                                    <X size={18} />
                                    Cancel
                                </button>
                                <button type="submit" className="btn-primary" disabled={busy}>
                                    <Save size={18} />
                                    {busy ? 'Applying...' : editingRule ? 'Update' : 'Add'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default GuestAccess;
