import React, { useState, useEffect } from 'react';
import { authFetch, API_BASE_URL } from '../apiConfig';
import { Bell, Mail, Globe, Plus, Trash2, Send, CheckCircle, AlertCircle, Save } from 'lucide-react';
import './Notifications.css';

const Notifications = () => {
    const [config, setConfig] = useState({
        enabled: false,
        min_severity: 'warning',
        cooldown_minutes: 5,
        email: {
            enabled: false,
            smtp_server: '',
            smtp_port: 587,
            username: '',
            password: '',
            from: '',
            to: '',
            use_tls: true,
        },
        webhooks: [],
    });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [testResults, setTestResults] = useState({});
    const [hasChanges, setHasChanges] = useState(false);

    useEffect(() => {
        fetchConfig();
    }, []);

    const fetchConfig = async () => {
        try {
            const res = await authFetch(`${API_BASE_URL}/api/notifications/config`);
            if (res.ok) {
                const data = await res.json();
                setConfig({
                    enabled: data.enabled ?? false,
                    min_severity: data.min_severity ?? 'warning',
                    cooldown_minutes: data.cooldown_minutes ?? 5,
                    email: {
                        enabled: data.email?.enabled ?? false,
                        smtp_server: data.email?.smtp_server ?? '',
                        smtp_port: data.email?.smtp_port ?? 587,
                        username: data.email?.username ?? '',
                        password: data.email?.password ?? '',
                        from: data.email?.from ?? '',
                        to: data.email?.to ?? '',
                        use_tls: data.email?.use_tls ?? true,
                    },
                    webhooks: Array.isArray(data.webhooks) ? data.webhooks : [],
                });
            }
        } catch (err) {
            console.error('Failed to load notification config:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async () => {
        setSaving(true);
        try {
            const res = await authFetch(`${API_BASE_URL}/api/notifications/config`, {
                method: 'POST',
                body: JSON.stringify(config),
            });
            if (res.ok) {
                setHasChanges(false);
                setTestResults(prev => ({ ...prev, save: 'success' }));
                setTimeout(() => setTestResults(prev => { const { save: _save, ...rest } = prev; return rest; }), 3000);
            }
        } catch (err) {
            console.error('Failed to save config:', err);
        } finally {
            setSaving(false);
        }
    };

    const handleTest = async (channel, webhookId, uiKey) => {
        const key = uiKey || webhookId || channel;
        setTestResults(prev => ({ ...prev, [key]: 'sending' }));

        try {
            const res = await authFetch(`${API_BASE_URL}/api/notifications/test`, {
                method: 'POST',
                body: JSON.stringify({ channel, id: webhookId || '' }),
            });
            const data = await res.json();
            setTestResults(prev => ({ ...prev, [key]: data.status === 'sent' ? 'success' : 'error' }));
        } catch {
            setTestResults(prev => ({ ...prev, [key]: 'error' }));
        }

        setTimeout(() => {
            setTestResults(prev => { const { [key]: _, ...rest } = prev; return rest; });
        }, 5000);
    };

    const updateField = (path, value) => {
        setConfig(prev => {
            const updated = JSON.parse(JSON.stringify(prev));
            const keys = path.split('.');
            let obj = updated;
            for (let i = 0; i < keys.length - 1; i++) {
                obj = obj[keys[i]];
            }
            obj[keys[keys.length - 1]] = value;
            return updated;
        });
        setHasChanges(true);
    };

    const addWebhook = () => {
        setConfig(prev => ({
            ...prev,
            webhooks: [
                ...prev.webhooks,
                { id: '', name: '', url: '', enabled: true, type: 'discord' }
            ],
        }));
        setHasChanges(true);
    };

    const removeWebhook = (index) => {
        setConfig(prev => ({
            ...prev,
            webhooks: prev.webhooks.filter((_, i) => i !== index),
        }));
        setHasChanges(true);
    };

    const updateWebhook = (index, field, value) => {
        setConfig(prev => {
            const updated = { ...prev, webhooks: [...prev.webhooks] };
            updated.webhooks[index] = { ...updated.webhooks[index], [field]: value };
            return updated;
        });
        setHasChanges(true);
    };

    const getTestButton = (key, channel, id) => {
        const status = testResults[key];
        if (status === 'sending') {
            return <button className="btn btn-sm btn-test" disabled><span className="spinner-sm"></span> Sending...</button>;
        }
        if (status === 'success') {
            return <button className="btn btn-sm btn-success-state" disabled><CheckCircle size={14} /> Sent!</button>;
        }
        if (status === 'error') {
            return <button className="btn btn-sm btn-error-state" disabled><AlertCircle size={14} /> Failed</button>;
        }
        return (
            <button className="btn btn-sm btn-test" onClick={() => handleTest(channel, id, key)}>
                <Send size={14} /> Test
            </button>
        );
    };

    if (loading) {
        return <div className="notifications-page"><div className="loading-state">Loading notification settings...</div></div>;
    }

    return (
        <div className="notifications-page">
            <div className="page-header">
                <div className="header-left">
                    <Bell size={24} />
                    <div>
                        <h2>Notifications</h2>
                        <p className="subtitle">Get alerts for critical events via email or webhooks</p>
                    </div>
                </div>
                <div className="header-actions">
                    {hasChanges && (
                        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                            <Save size={16} />
                            {saving ? 'Saving...' : 'Save Changes'}
                        </button>
                    )}
                    {testResults.save === 'success' && (
                        <span className="save-confirmation"><CheckCircle size={16} /> Saved</span>
                    )}
                </div>
            </div>

            {/* Master Toggle */}
            <div className="card master-toggle">
                <div className="toggle-row">
                    <div className="toggle-info">
                        <h3>Enable Notifications</h3>
                        <p>Send alerts when critical events occur (WAN down, brute force attacks, etc.)</p>
                    </div>
                    <label className="switch">
                        <input
                            type="checkbox"
                            checked={config.enabled}
                            onChange={(e) => updateField('enabled', e.target.checked)}
                        />
                        <span className="slider"></span>
                    </label>
                </div>

                {config.enabled && (
                    <div className="global-settings">
                        <div className="setting-row">
                            <label>Minimum Severity</label>
                            <select
                                value={config.min_severity}
                                onChange={(e) => updateField('min_severity', e.target.value)}
                            >
                                <option value="info">Info — All events</option>
                                <option value="warning">Warning — Warnings and critical only</option>
                                <option value="critical">Critical — Critical events only</option>
                            </select>
                        </div>
                        <div className="setting-row">
                            <label>Cooldown (minutes)</label>
                            <input
                                type="number"
                                min="1"
                                max="60"
                                value={config.cooldown_minutes}
                                onChange={(e) => updateField('cooldown_minutes', parseInt(e.target.value) || 5)}
                            />
                            <span className="hint">Prevent duplicate alerts for the same event type</span>
                        </div>
                    </div>
                )}
            </div>

            {config.enabled && (
                <>
                    {/* Email Configuration */}
                    <div className="card">
                        <div className="card-header">
                            <div className="card-title-row">
                                <Mail size={20} />
                                <h3>Email Notifications</h3>
                            </div>
                            <label className="switch">
                                <input
                                    type="checkbox"
                                    checked={config.email.enabled}
                                    onChange={(e) => updateField('email.enabled', e.target.checked)}
                                />
                                <span className="slider"></span>
                            </label>
                        </div>

                        {config.email.enabled && (
                            <div className="card-body">
                                <div className="form-grid">
                                    <div className="form-group">
                                        <label>SMTP Server</label>
                                        <input
                                            type="text"
                                            placeholder="smtp.gmail.com"
                                            value={config.email.smtp_server}
                                            onChange={(e) => updateField('email.smtp_server', e.target.value)}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>SMTP Port</label>
                                        <input
                                            type="number"
                                            placeholder="587"
                                            value={config.email.smtp_port}
                                            onChange={(e) => updateField('email.smtp_port', parseInt(e.target.value) || 587)}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>Username</label>
                                        <input
                                            type="text"
                                            placeholder="your-email@gmail.com"
                                            value={config.email.username}
                                            onChange={(e) => updateField('email.username', e.target.value)}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>Password / App Password</label>
                                        <input
                                            type="password"
                                            placeholder="••••••••"
                                            value={config.email.password}
                                            onChange={(e) => updateField('email.password', e.target.value)}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>From Address</label>
                                        <input
                                            type="email"
                                            placeholder="router@yourdomain.com"
                                            value={config.email.from}
                                            onChange={(e) => updateField('email.from', e.target.value)}
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label>To Address</label>
                                        <input
                                            type="email"
                                            placeholder="you@yourdomain.com"
                                            value={config.email.to}
                                            onChange={(e) => updateField('email.to', e.target.value)}
                                        />
                                    </div>
                                </div>
                                <div className="card-actions">
                                    {getTestButton('email', 'email')}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Webhooks */}
                    <div className="card">
                        <div className="card-header">
                            <div className="card-title-row">
                                <Globe size={20} />
                                <h3>Webhook Notifications</h3>
                            </div>
                            <button className="btn btn-sm btn-secondary" onClick={addWebhook}>
                                <Plus size={14} /> Add Webhook
                            </button>
                        </div>

                        <div className="card-body">
                            {config.webhooks.length === 0 ? (
                                <div className="empty-state">
                                    <p>No webhooks configured. Add a Discord, Slack, or custom webhook to receive alerts.</p>
                                </div>
                            ) : (
                                <div className="webhooks-list">
                                    {config.webhooks.map((wh, idx) => (
                                        <div key={idx} className="webhook-item">
                                            <div className="webhook-top-row">
                                                <label className="switch switch-sm">
                                                    <input
                                                        type="checkbox"
                                                        checked={wh.enabled}
                                                        onChange={(e) => updateWebhook(idx, 'enabled', e.target.checked)}
                                                    />
                                                    <span className="slider"></span>
                                                </label>
                                                <select
                                                    value={wh.type}
                                                    onChange={(e) => updateWebhook(idx, 'type', e.target.value)}
                                                    className="type-select"
                                                >
                                                    <option value="discord">Discord</option>
                                                    <option value="slack">Slack</option>
                                                    <option value="generic">Generic (JSON POST)</option>
                                                </select>
                                                <input
                                                    type="text"
                                                    placeholder="Webhook Name"
                                                    value={wh.name}
                                                    onChange={(e) => updateWebhook(idx, 'name', e.target.value)}
                                                    className="name-input"
                                                />
                                                <button className="btn btn-sm btn-danger" onClick={() => removeWebhook(idx)}>
                                                    <Trash2 size={14} />
                                                </button>
                                            </div>
                                            <div className="webhook-url-row">
                                                <input
                                                    type="url"
                                                    placeholder={
                                                        wh.type === 'discord' ? 'https://discord.com/api/webhooks/...' :
                                                        wh.type === 'slack' ? 'https://hooks.slack.com/services/...' :
                                                        'https://your-server.com/webhook'
                                                    }
                                                    value={wh.url}
                                                    onChange={(e) => updateWebhook(idx, 'url', e.target.value)}
                                                />
                                                {getTestButton(wh.id || `wh-${idx}`, 'webhook', wh.id)}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Event Types Reference */}
                    <div className="card">
                        <div className="card-header">
                            <div className="card-title-row">
                                <h3>Supported Events</h3>
                            </div>
                        </div>
                        <div className="card-body">
                            <table className="events-table">
                                <thead>
                                    <tr>
                                        <th>Event</th>
                                        <th>Severity</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><code>wan_state_change</code></td>
                                        <td><span className="severity-badge critical">Critical</span></td>
                                        <td>WAN interface goes online or offline</td>
                                    </tr>
                                    <tr>
                                        <td><code>brute_force_detected</code></td>
                                        <td><span className="severity-badge critical">Critical</span></td>
                                        <td>IP address banned after 5+ failed login attempts</td>
                                    </tr>
                                    <tr>
                                        <td><code>vpn_state_change</code></td>
                                        <td><span className="severity-badge warning">Warning</span></td>
                                        <td>VPN tunnel connected or disconnected</td>
                                    </tr>
                                    <tr>
                                        <td><code>ids_alert</code></td>
                                        <td><span className="severity-badge critical">Critical</span></td>
                                        <td>Intrusion detection system flagged traffic</td>
                                    </tr>
                                    <tr>
                                        <td><code>system_health</code></td>
                                        <td><span className="severity-badge warning">Warning</span></td>
                                        <td>CPU, RAM, or disk usage exceeds thresholds</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};

export default Notifications;
