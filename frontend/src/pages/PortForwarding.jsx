import React, { useState, useEffect } from 'react';
import { Trash2, Plus, ArrowRight, Save, X } from 'lucide-react';
import { API_ENDPOINTS, authFetch } from '../apiConfig';
import './PortForwarding.css';

const PortForwarding = () => {
    const [rules, setRules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [showAddModal, setShowAddModal] = useState(false);

    // Form State
    const [newRule, setNewRule] = useState({
        description: '',
        protocol: 'tcp',
        external_port: '',
        internal_ip: '',
        internal_port: ''
    });

    useEffect(() => {
        fetchRules();
    }, []);

    const fetchRules = async () => {
        try {
            setLoading(true);
            const response = await authFetch(API_ENDPOINTS.PORT_FORWARDING);

            if (!response.ok) throw new Error('Failed to fetch rules');

            const data = await response.json();
            console.log('=== PORT FORWARDING DEBUG ===');
            console.log('Full API Response:', data);
            if (data && data.length > 0) {
                console.log('First rule:', data[0]);
                console.log('First rule protocol:', data[0].protocol);
            }
            console.log('=============================');
            setRules(data || []);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id) => {
        if (!window.confirm('Are you sure you want to delete this rule?')) return;

        try {
            const response = await authFetch(`${API_ENDPOINTS.PORT_FORWARDING}?id=${id}`, {
                method: 'DELETE'
            });

            if (!response.ok) throw new Error('Failed to delete rule');

            fetchRules();
        } catch (err) {
            alert(err.message);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            // Convert ports to numbers
            const payload = {
                ...newRule,
                external_port: parseInt(newRule.external_port),
                internal_port: parseInt(newRule.internal_port)
            };

            const response = await authFetch(API_ENDPOINTS.PORT_FORWARDING, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) throw new Error('Failed to create rule');

            setShowAddModal(false);
            setNewRule({
                description: '',
                protocol: 'tcp',
                external_port: '',
                internal_ip: '',
                internal_port: ''
            });
            fetchRules();
        } catch (err) {
            alert(err.message);
        }
    };

    return (
        <div className="port-forwarding-page">
            <div className="page-header">
                <div>
                    <h1>Port Forwarding</h1>
                    <p className="subtitle">Manage DNAT rules for external access</p>
                </div>
                <button className="btn-primary" onClick={() => setShowAddModal(true)}>
                    <Plus size={18} />
                    Add Rule
                </button>
            </div>

            {error && <div className="error-banner">{error}</div>}

            <div className="rules-list">
                {loading ? (
                    <div className="loading">Loading rules...</div>
                ) : rules.length === 0 ? (
                    <div className="empty-state">
                        <p>No port forwarding rules defined.</p>
                    </div>
                ) : (
                    <div className="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Protocol</th>
                                    <th>External Port</th>
                                    <th></th>
                                    <th>Internal Address</th>
                                    <th>Description</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rules.map((rule) => (
                                    <tr key={rule.id}>
                                        <td className={`badge ${(rule.protocol || 'tcp').toLowerCase()}`}>
                                            {(rule.protocol || 'tcp').toUpperCase()}
                                        </td>
                                        <td className="port-cell">{rule.external_port}</td>
                                        <td className="arrow-cell"><ArrowRight size={16} /></td>
                                        <td className="target-cell">
                                            {rule.internal_ip}:{rule.internal_port}
                                        </td>
                                        <td>{rule.description || '-'}</td>
                                        <td>
                                            <button
                                                className="btn-icon danger"
                                                onClick={() => handleDelete(rule.id)}
                                            >
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

            {showAddModal && (
                <div className="modal-overlay">
                    <div className="modal">
                        <div className="modal-header">
                            <h2>Add Port Forwarding Rule</h2>
                            <button className="btn-icon" onClick={() => setShowAddModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <form onSubmit={handleSubmit}>
                            <div className="form-group">
                                <label>Description</label>
                                <input
                                    type="text"
                                    placeholder="e.g. Web Server"
                                    value={newRule.description}
                                    onChange={e => setNewRule({ ...newRule, description: e.target.value })}
                                />
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label>Protocol</label>
                                    <select
                                        value={newRule.protocol}
                                        onChange={e => setNewRule({ ...newRule, protocol: e.target.value })}
                                    >
                                        <option value="tcp">TCP</option>
                                        <option value="udp">UDP</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>External Port (WAN)</label>
                                    <input
                                        type="number"
                                        min="1" max="65535"
                                        required
                                        placeholder="80"
                                        value={newRule.external_port}
                                        onChange={e => setNewRule({ ...newRule, external_port: e.target.value })}
                                    />
                                </div>
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label>Internal IP</label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="192.168.1.10"
                                        value={newRule.internal_ip}
                                        onChange={e => setNewRule({ ...newRule, internal_ip: e.target.value })}
                                    />
                                </div>
                                <div className="form-group">
                                    <label>Internal Port</label>
                                    <input
                                        type="number"
                                        min="1" max="65535"
                                        required
                                        placeholder="8080"
                                        value={newRule.internal_port}
                                        onChange={e => setNewRule({ ...newRule, internal_port: e.target.value })}
                                    />
                                </div>
                            </div>

                            <div className="modal-actions">
                                <button type="button" className="btn-secondary" onClick={() => setShowAddModal(false)}>
                                    Cancel
                                </button>
                                <button type="submit" className="btn-primary">
                                    <Save size={18} /> Save Rule
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PortForwarding;
