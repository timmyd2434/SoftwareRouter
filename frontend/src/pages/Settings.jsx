import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Shield, Cloud, Terminal, Save, Lock, User, CheckCircle, AlertCircle, Loader2, Globe, RotateCcw, Trash2, Download, GitBranch, RefreshCw } from 'lucide-react';
import { API_ENDPOINTS, authFetch } from '../apiConfig';
import ConfirmModal from '../components/ConfirmModal';
import './Settings.css';

const Settings = () => {
    const [config, setConfig] = useState({
        cf_token: '',
        protected_subnet: '10.0.0.0/24',
        ad_blocker: 'none',
        openvpn_port: 1194,
        web_access: {
            allow_wan: false,
            wan_port_http: 980,
            wan_port_https: 9443
        }
    });

    const [adguardSettings, setAdguardSettings] = useState({
        url: '',
        username: '',
        password: ''
    });

    const [creds, setCreds] = useState({
        newUsername: '',
        newPassword: '',
        confirmPassword: ''
    });

    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(null); // 'config' or 'creds'
    const [message, setMessage] = useState({ type: '', text: '' });

    useEffect(() => {
        fetchConfig();
        fetchAdGuardSettings();
    }, []);

    const fetchConfig = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.CONFIG);
            if (res.ok) {
                const data = await res.json();
                setConfig(data);
            }
        } catch (err) {
            console.error('Failed to fetch config', err);
        } finally {
            setLoading(false);
        }
    };

    const fetchAdGuardSettings = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.SETTINGS);
            if (res.ok) {
                const data = await res.json();
                if (data.adguard) {
                    setAdguardSettings(data.adguard);
                }
            }
        } catch (err) {
            console.error('Failed to fetch AdGuard settings', err);
        }
    };

    const handleSaveAdGuard = async (e) => {
        e.preventDefault();
        setSaving('adguard');
        setMessage({ type: '', text: '' });

        try {
            const res = await authFetch(API_ENDPOINTS.SETTINGS, {
                method: 'POST',
                body: JSON.stringify({ adguard: adguardSettings })
            });
            if (res.ok) {
                setMessage({ type: 'success', text: 'AdGuard settings saved successfully' });
                await fetchAdGuardSettings(); // Refresh to get masked password
            } else {
                setMessage({ type: 'error', text: 'Failed to save AdGuard settings' });
            }
        } catch {
            setMessage({ type: 'error', text: 'Network error' });
        } finally {
            setSaving(null);
        }
    };

    const handleSaveConfig = async (e) => {
        e.preventDefault();
        setSaving('config');
        setMessage({ type: '', text: '' });

        try {
            const res = await authFetch(API_ENDPOINTS.CONFIG, {
                method: 'POST',
                body: JSON.stringify(config)
            });
            if (res.ok) {
                setMessage({ type: 'success', text: 'Configuration saved successfully' });
            } else {
                setMessage({ type: 'error', text: 'Failed to save configuration' });
            }
        } catch {
            setMessage({ type: 'error', text: 'Network error' });
        } finally {
            setSaving(null);
        }
    };

    const handleUpdateCreds = async (e) => {
        e.preventDefault();
        if (creds.newPassword !== creds.confirmPassword) {
            setMessage({ type: 'error', text: 'Passwords do not match' });
            return;
        }

        setSaving('creds');
        setMessage({ type: '', text: '' });

        try {
            const res = await authFetch(API_ENDPOINTS.UPDATE_CREDS, {
                method: 'POST',
                body: JSON.stringify({
                    newUsername: creds.newUsername,
                    newPassword: creds.newPassword
                })
            });
            if (res.ok) {
                setMessage({ type: 'success', text: 'Credentials updated successfully' });
                localStorage.setItem('sr_user', creds.newUsername);
                setCreds({ newUsername: '', newPassword: '', confirmPassword: '' });
            } else {
                setMessage({ type: 'error', text: 'Failed to update credentials' });
            }
        } catch {
            setMessage({ type: 'error', text: 'Network error' });
        } finally {
            setSaving(null);
        }
    };

    if (loading) {
        return <div className="settings-loading"><Loader2 className="spin" /> Loading configurations...</div>;
    }

    return (
        <div className="settings-container">
            <div className="section-header">
                <div>
                    <h2>Advanced System Settings</h2>
                    <span className="subtitle">Configure security, networking, and authentication</span>
                </div>
                {message.text && (
                    <div className={`status-banner ${message.type}`}>
                        {message.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
                        {message.text}
                    </div>
                )}
            </div>

            <div className="settings-grid">
                {/* Auth Settings */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Lock size={20} className="header-icon" />
                        <h3>Administrative Access</h3>
                    </div>
                    <form onSubmit={handleUpdateCreds} className="card-form">
                        <div className="input-group">
                            <label>New Username</label>
                            <div className="field-wrapper">
                                <User size={18} />
                                <input
                                    type="text"
                                    value={creds.newUsername}
                                    onChange={e => setCreds({ ...creds, newUsername: e.target.value })}
                                    placeholder="Enter new username"
                                    required
                                />
                            </div>
                        </div>
                        <div className="input-group">
                            <label>New Password</label>
                            <div className="field-wrapper">
                                <Lock size={18} />
                                <input
                                    type="password"
                                    value={creds.newPassword}
                                    onChange={e => setCreds({ ...creds, newPassword: e.target.value })}
                                    placeholder="••••••••"
                                    required
                                />
                            </div>
                        </div>
                        <div className="input-group">
                            <label>Confirm Password</label>
                            <div className="field-wrapper">
                                <Lock size={18} />
                                <input
                                    type="password"
                                    value={creds.confirmPassword}
                                    onChange={e => setCreds({ ...creds, confirmPassword: e.target.value })}
                                    placeholder="••••••••"
                                    required
                                />
                            </div>
                        </div>
                        <button type="submit" className="save-btn" disabled={saving}>
                            {saving === 'creds' ? <Loader2 size={18} className="spin" /> : <Save size={18} />}
                            Update Access
                        </button>
                    </form>
                </div>

                {/* AdGuard Home Integration */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Shield size={20} className="header-icon shield" />
                        <h3>AdGuard Home Integration</h3>
                    </div>
                    <form onSubmit={handleSaveAdGuard} className="card-form">
                        <div className="input-group">
                            <label>AdGuard Home URL</label>
                            <div className="field-wrapper">
                                <Globe size={18} />
                                <input
                                    type="text"
                                    value={adguardSettings.url}
                                    onChange={e => setAdguardSettings({ ...adguardSettings, url: e.target.value })}
                                    placeholder="http://localhost:3000"
                                    required
                                />
                            </div>
                            <span className="hint">Full URL including protocol (http:// or https://)</span>
                        </div>
                        <div className="input-group">
                            <label>Username</label>
                            <div className="field-wrapper">
                                <User size={18} />
                                <input
                                    type="text"
                                    value={adguardSettings.username}
                                    onChange={e => setAdguardSettings({ ...adguardSettings, username: e.target.value })}
                                    placeholder="admin"
                                />
                            </div>
                        </div>
                        <div className="input-group">
                            <label>Password</label>
                            <div className="field-wrapper">
                                <Lock size={18} />
                                <input
                                    type="password"
                                    value={adguardSettings.password}
                                    onChange={e => setAdguardSettings({ ...adguardSettings, password: e.target.value })}
                                    placeholder="Enter password"
                                />
                            </div>
                            <span className="hint">Leave as **** to keep existing password</span>
                        </div>
                        <button type="submit" className="save-btn" disabled={saving}>
                            {saving === 'adguard' ? <Loader2 size={18} className="spin" /> : <Save size={18} />}
                            Save AdGuard Settings
                        </button>
                    </form>
                </div>

                {/* Access Control */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Lock size={20} className="header-icon shield" />
                        <h3>Access Control</h3>
                    </div>
                    <form onSubmit={handleSaveConfig} className="card-form">
                        <div className="form-group checkbox-group">
                            <label className="checkbox-label" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                                <input
                                    type="checkbox"
                                    checked={config.web_access?.allow_wan || false}
                                    onChange={e => setConfig({
                                        ...config,
                                        web_access: { ...config.web_access, allow_wan: e.target.checked }
                                    })}
                                />
                                Allow WAN Access to WebUI
                            </label>
                            <p className="hint" style={{ marginTop: '0.5rem' }}>
                                If enabled, the WebUI will be accessible from the WAN IP on the specified ports.
                                <strong> Use with caution.</strong>
                            </p>
                        </div>

                        {config.web_access?.allow_wan && (
                            <div className="form-row">
                                <div className="input-group">
                                    <label>WAN HTTP Port</label>
                                    <div className="field-wrapper">
                                        <Globe size={18} />
                                        <input
                                            type="number"
                                            value={config.web_access?.wan_port_http || 980}
                                            onChange={e => setConfig({
                                                ...config,
                                                web_access: { ...config.web_access, wan_port_http: parseInt(e.target.value) }
                                            })}
                                            placeholder="980"
                                        />
                                    </div>
                                </div>
                                <div className="input-group">
                                    <label>WAN HTTPS Port</label>
                                    <div className="field-wrapper">
                                        <Lock size={18} />
                                        <input
                                            type="number"
                                            value={config.web_access?.wan_port_https || 9443}
                                            onChange={e => setConfig({
                                                ...config,
                                                web_access: { ...config.web_access, wan_port_https: parseInt(e.target.value) }
                                            })}
                                            placeholder="9443"
                                        />
                                    </div>
                                </div>
                            </div>
                        )}
                        <button type="submit" className="save-btn" disabled={saving}>
                            {saving === 'config' ? <Loader2 size={18} className="spin" /> : <Save size={18} />}
                            Save Access Settings
                        </button>
                    </form>
                </div>

                {/* Cloudflare Tunnel */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Cloud size={20} className="header-icon cloud" />
                        <h3>Cloudflare Tunnel (Argo)</h3>
                    </div>
                    <form onSubmit={handleSaveConfig} className="card-form">
                        <div className="input-group">
                            <label>Tunnel Token</label>
                            <div className="field-wrapper">
                                <Terminal size={18} />
                                <input
                                    type="password"
                                    value={config.cf_token}
                                    onChange={e => setConfig({ ...config, cf_token: e.target.value })}
                                    placeholder="Paste eye-ball token"
                                />
                            </div>
                            <span className="hint">The token provided in your Cloudflare Zero Trust dashboard.</span>
                        </div>
                        <div className="input-group">
                            <label>Protected Subnet Path</label>
                            <div className="field-wrapper">
                                <Globe size={18} />
                                <input
                                    type="text"
                                    value={config.protected_subnet}
                                    onChange={e => setConfig({ ...config, protected_subnet: e.target.value })}
                                    placeholder="192.168.10.0/24"
                                />
                            </div>
                            <span className="hint">This subnet will be routed exclusively through the tunnel.</span>
                        </div>
                        <button type="submit" className="save-btn" disabled={saving}>
                            {saving === 'config' ? <Loader2 size={18} className="spin" /> : <Save size={18} />}
                            Deploy Tunnel Config
                        </button>
                    </form>
                </div>

                <div className="settings-card glass-panel dns-privacy-card">
                    <div className="card-header">
                        <Shield size={20} className="header-icon shield" />
                        <h3>DNS Privacy (DoT/DoH)</h3>
                    </div>
                    <form onSubmit={handleSaveConfig} className="card-form">
                        <div className="form-group checkbox-group mb">
                            <label className="checkbox-label" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                                <input
                                    type="checkbox"
                                    checked={config.dns_privacy?.enabled || false}
                                    onChange={e => setConfig({
                                        ...config,
                                        dns_privacy: { ...config.dns_privacy, enabled: e.target.checked }
                                    })}
                                />
                                Enable DNS Encryption (System-wide)
                            </label>
                            <p className="hint" style={{ marginTop: '0.5rem' }}>
                                Encrypts DNS queries using DNS-over-TLS (DoT) via systemd-resolved.
                                Note: May conflict if using Pi-hole or AdGuard Home.
                            </p>
                        </div>
                        
                        {config.dns_privacy?.enabled && (
                            <>
                                <div className="input-group">
                                    <label>DNS Provider</label>
                                    <select 
                                        className="form-input"
                                        value={config.dns_privacy?.provider || 'cloudflare'}
                                        onChange={e => setConfig({
                                            ...config,
                                            dns_privacy: { ...config.dns_privacy, provider: e.target.value }
                                        })}
                                        style={{ width: '100%', padding: '0.75rem', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.1)', color: 'white', borderRadius: '8px' }}
                                    >
                                        <option value="cloudflare">Cloudflare (1.1.1.1)</option>
                                        <option value="quad9">Quad9 (9.9.9.9)</option>
                                        <option value="google">Google (8.8.8.8)</option>
                                    </select>
                                </div>
                                <div className="input-group">
                                    <label>Strict Mode</label>
                                    <select 
                                        className="form-input"
                                        value={config.dns_privacy?.mode || 'opportunistic'}
                                        onChange={e => setConfig({
                                            ...config,
                                            dns_privacy: { ...config.dns_privacy, mode: e.target.value }
                                        })}
                                        style={{ width: '100%', padding: '0.75rem', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.1)', color: 'white', borderRadius: '8px' }}
                                    >
                                        <option value="opportunistic">Opportunistic (Fallback to unencrypted)</option>
                                        <option value="strict">Strict (Fail if encryption fails)</option>
                                    </select>
                                </div>
                            </>
                        )}
                        
                        <button type="submit" className="save-btn" disabled={saving}>
                            {saving === 'config' ? <Loader2 size={18} className="spin" /> : <Save size={18} />}
                            Save DNS Privacy Config
                        </button>
                    </form>
                </div>

                {/* DNS Adblocker */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Shield size={20} className="header-icon shield" />
                        <h3>DNS Ad-Blocker Select</h3>
                    </div>
                    <div className="dns-selection">
                        <label className={`dns-option ${config.ad_blocker === 'none' ? 'active' : ''}`}>
                            <input
                                type="radio"
                                name="adblocker"
                                value="none"
                                checked={config.ad_blocker === 'none'}
                                onChange={e => setConfig({ ...config, ad_blocker: e.target.value })}
                            />
                            <div className="option-content">
                                <strong>Default (Unbound)</strong>
                                <span>No ad-blocking, internal recursive DNS only.</span>
                            </div>
                        </label>
                        <label className={`dns-option ${config.ad_blocker === 'adguard' ? 'active' : ''}`}>
                            <input
                                type="radio"
                                name="adblocker"
                                value="adguard"
                                checked={config.ad_blocker === 'adguard'}
                                onChange={e => setConfig({ ...config, ad_blocker: e.target.value })}
                            />
                            <div className="option-content">
                                <strong>AdGuard Home</strong>
                                <span>Premium UI, extremely fast, excellent filtering.</span>
                            </div>
                        </label>
                        <label className={`dns-option ${config.ad_blocker === 'pihole' ? 'active' : ''}`}>
                            <input
                                type="radio"
                                name="adblocker"
                                value="pihole"
                                checked={config.ad_blocker === 'pihole'}
                                onChange={e => setConfig({ ...config, ad_blocker: e.target.value })}
                            />
                            <div className="option-content">
                                <strong>Pi-hole (FTL)</strong>
                                <span>The classic standard for network-wide ad blocking.</span>
                            </div>
                        </label>
                        <button onClick={handleSaveConfig} className="save-btn" disabled={saving}>
                            {saving === 'config' ? <Loader2 size={18} className="spin" /> : <Save size={18} />}
                            Apply DNS Choice
                        </button>
                    </div>
                </div>

                {/* VPN Settings Preview */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Globe size={20} className="header-icon vpn" />
                        <h3>VPN Gateway Options</h3>
                    </div>
                    <div className="card-info">
                        <div className="info-stat">
                            <span>Primary VPN Port</span>
                            <strong>{config.openvpn_port}</strong>
                        </div>
                        <p className="note">
                            OpenVPN configuration generation is coming in the next module.
                            WireGuard remains the recommended high-performance choice.
                        </p>
                    </div>
                </div>

                {/* Backup & Restore */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Save size={20} className="header-icon" />
                        <h3>Backup & Restore</h3>
                    </div>
                    <BackupRestore />
                </div>

                {/* System Update */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Download size={20} className="header-icon" />
                        <h3>Software Update</h3>
                    </div>
                    <SystemUpdate />
                </div>

                {/* Session Management */}
                <div className="settings-card glass-panel">
                    <div className="card-header">
                        <Shield size={20} className="header-icon" />
                        <h3>Active Sessions</h3>
                    </div>
                    <SessionManagement />
                </div>
            </div>
        </div>
    );
};

const BackupRestore = () => {
    const [backups, setBackups] = useState([]);
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState({ type: '', text: '' });
    
    // Modal & Password states
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [createPassword, setCreatePassword] = useState('');
    
    const [showRestoreModal, setShowRestoreModal] = useState(false);
    const [restorePassword, setRestorePassword] = useState('');
    const [selectedFile, setSelectedFile] = useState(null);
    const [selectedLocalBackup, setSelectedLocalBackup] = useState(null);

    const fetchBackups = async () => {
        try {
            const res = await authFetch('/api/backup/list');
            if (res.ok) {
                const data = await res.json();
                setBackups(data || []);
            }
        } catch (err) {
            console.error('Failed to fetch backups', err);
        }
    };

    useEffect(() => {
        fetchBackups();
    }, []);

    const handleCreateBackup = async (e) => {
        if (e) e.preventDefault();
        if (!createPassword) {
            setMessage({ type: 'error', text: 'Encryption password is required to create a backup' });
            return;
        }

        try {
            setLoading(true);
            setMessage({ type: '', text: '' });

            const res = await authFetch(`/api/backup/create?password=${encodeURIComponent(createPassword)}`);
            if (res.ok) {
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `softrouter-backup-${new Date().toISOString().split('T')[0]}.enc`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

                setMessage({ type: 'success', text: 'Encrypted backup created and downloaded!' });
                setShowCreateModal(false);
                setCreatePassword('');
                fetchBackups();
            } else {
                const text = await res.text();
                setMessage({ type: 'error', text: text || 'Failed to create backup' });
            }
        } catch {
            setMessage({ type: 'error', text: 'Network error creating backup' });
        } finally {
            setLoading(false);
        }
    };

    const handleRestoreBackup = async (e) => {
        if (e) e.preventDefault();
        if (!selectedFile && !selectedLocalBackup) return;
        if (!restorePassword) {
            setMessage({ type: 'error', text: 'Decryption password is required to restore backup' });
            return;
        }

        try {
            setLoading(true);
            setMessage({ type: '', text: '' });

            let res;
            if (selectedLocalBackup) {
                res = await authFetch('/api/backup/restore-local', {
                    method: 'POST',
                    body: JSON.stringify({
                        filename: selectedLocalBackup.filename,
                        password: restorePassword
                    })
                });
            } else {
                const formData = new FormData();
                formData.append('file', selectedFile);
                formData.append('password', restorePassword);

                res = await authFetch('/api/backup/restore', {
                    method: 'POST',
                    body: formData,
                    headers: {} // Browser sets multipart boundary automatically
                });
            }

            if (res.ok) {
                setMessage({ type: 'success', text: 'Backup restored successfully! System config reloaded.' });
                setShowRestoreModal(false);
                setSelectedFile(null);
                setSelectedLocalBackup(null);
                setRestorePassword('');
            } else {
                const text = await res.text();
                setMessage({ type: 'error', text: text || 'Failed to restore backup' });
            }
        } catch {
            setMessage({ type: 'error', text: 'Network error restoring backup' });
        } finally {
            setLoading(false);
        }
    };

    const handleDeleteBackup = async (filename) => {
        if (!confirm(`Delete backup "${filename}"? This cannot be undone.`)) return;
        try {
            setMessage({ type: '', text: '' });
            const res = await authFetch(`${API_ENDPOINTS.BACKUP_DELETE}?filename=${encodeURIComponent(filename)}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                setMessage({ type: 'success', text: 'Backup deleted successfully' });
                fetchBackups();
            } else {
                setMessage({ type: 'error', text: 'Failed to delete backup' });
            }
        } catch {
            setMessage({ type: 'error', text: 'Network error' });
        }
    };

    return (
        <div className="backup-section">
            {message.text && (
                <div className={`alert ${message.type}`}>
                    {message.type === 'success' ? <CheckCircle size={16} /> : <AlertCircle size={16} />}
                    {message.text}
                </div>
            )}

            <div className="backup-actions">
                <button onClick={() => { setCreatePassword(''); setShowCreateModal(true); }} className="btn-primary" disabled={loading}>
                    {loading ? <Loader2 size={18} className="spin" /> : <Save size={18} />}
                    Create Backup
                </button>

                <label className="btn-secondary file-upload-btn">
                    <input
                        type="file"
                        accept=".enc,.json"
                        onChange={(e) => {
                            if (e.target.files[0]) {
                                setSelectedFile(e.target.files[0]);
                                setSelectedLocalBackup(null);
                                setRestorePassword('');
                                setShowRestoreModal(true);
                            }
                        }}
                        style={{ display: 'none' }}
                    />
                    <Cloud size={18} />
                    Upload & Restore
                </label>
            </div>

            {backups.length > 0 && (
                <div className="backup-list">
                    <h4>Available Backups</h4>
                    <table className="backup-table">
                        <thead>
                            <tr>
                                <th>Filename</th>
                                <th>Date</th>
                                <th>Size</th>
                                <th className="actions-cell">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {backups.map((backup, idx) => (
                                <tr key={idx}>
                                    <td>{backup.filename}</td>
                                    <td>{new Date(backup.timestamp).toLocaleString()}</td>
                                    <td>{(backup.size / 1024).toFixed(1)} KB</td>
                                    <td className="actions-cell">
                                        <button
                                            className="btn-action restore-btn"
                                            onClick={() => {
                                                setSelectedLocalBackup(backup);
                                                setSelectedFile(null);
                                                setRestorePassword('');
                                                setShowRestoreModal(true);
                                            }}
                                            title="Restore this backup"
                                        >
                                            <RotateCcw size={14} />
                                        </button>
                                        <button
                                            className="btn-action"
                                            onClick={() => handleDeleteBackup(backup.filename)}
                                            title="Delete this backup"
                                            style={{ color: 'var(--danger, #ef4444)' }}
                                        >
                                            <Trash2 size={14} />
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Create Backup Modal */}
            {showCreateModal && (
                <div className="modal-overlay">
                    <div className="modal-content" style={{ width: '420px' }}>
                        <div className="modal-header">
                            <h3>Create Encrypted Backup</h3>
                            <button className="close-btn" onClick={() => setShowCreateModal(false)}>✕</button>
                        </div>
                        <form onSubmit={handleCreateBackup} className="modal-body">
                            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                Enter a password to encrypt this system backup (AES-256-GCM). You will need this password to restore the backup.
                            </p>
                            <div className="form-group">
                                <label>Encryption Password</label>
                                <input
                                    type="password"
                                    className="form-input"
                                    placeholder="Enter password"
                                    value={createPassword}
                                    onChange={(e) => setCreatePassword(e.target.value)}
                                    required
                                    autoFocus
                                />
                            </div>
                            <div className="modal-footer" style={{ marginTop: '1rem' }}>
                                <button type="button" className="cancel-btn" onClick={() => setShowCreateModal(false)}>Cancel</button>
                                <button type="submit" className="btn-primary" disabled={loading || !createPassword}>
                                    {loading ? <Loader2 size={16} className="spin" /> : <Save size={16} />}
                                    Encrypt & Download
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Restore Backup Modal */}
            {showRestoreModal && (
                <div className="modal-overlay">
                    <div className="modal-content" style={{ width: '420px' }}>
                        <div className="modal-header">
                            <h3>Restore Backup</h3>
                            <button className="close-btn" onClick={() => {
                                setShowRestoreModal(false);
                                setSelectedFile(null);
                                setSelectedLocalBackup(null);
                            }}>✕</button>
                        </div>
                        <form onSubmit={handleRestoreBackup} className="modal-body">
                            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                Restoring from: <strong>{selectedLocalBackup ? selectedLocalBackup.filename : selectedFile?.name}</strong>
                            </p>
                            <div className="form-group">
                                <label>Decryption Password</label>
                                <input
                                    type="password"
                                    className="form-input"
                                    placeholder="Enter backup password"
                                    value={restorePassword}
                                    onChange={(e) => setRestorePassword(e.target.value)}
                                    required
                                    autoFocus
                                />
                            </div>
                            <div className="modal-footer" style={{ marginTop: '1rem' }}>
                                <button type="button" className="cancel-btn" onClick={() => {
                                    setShowRestoreModal(false);
                                    setSelectedFile(null);
                                    setSelectedLocalBackup(null);
                                }}>Cancel</button>
                                <button type="submit" className="btn-primary" style={{ background: 'var(--warning, #d97706)' }} disabled={loading || !restorePassword}>
                                    {loading ? <Loader2 size={16} className="spin" /> : <RotateCcw size={16} />}
                                    Confirm Restore
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

// Session Management Component
const SessionManagement = () => {
    const [sessions, setSessions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showRevokeModal, setShowRevokeModal] = useState(false);
    const [sessionToRevoke, setSessionToRevoke] = useState(null);
    const [message, setMessage] = useState({ type: '', text: '' });

    const fetchSessions = async () => {
        try {
            setLoading(true);
            const res = await authFetch('/api/sessions');
            if (res.ok) {
                const data = await res.json();
                setSessions(data || []);
            }
        } catch (err) {
            console.error('Failed to fetch sessions', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSessions();
    }, []);

    const handleRevokeSession = async () => {
        if (!sessionToRevoke) return;

        try {
            const sessionId = sessionToRevoke.id;
            if (!sessionId) {
                setMessage({ type: 'error', text: 'Invalid session ID' });
                return;
            }

            const res = await authFetch(`/api/sessions?id=${encodeURIComponent(sessionId)}`, {
                method: 'DELETE'
            });

            if (res.ok) {
                setMessage({ type: 'success', text: 'Session revoked successfully' });
                fetchSessions();
            } else {
                setMessage({ type: 'error', text: 'Failed to revoke session' });
            }
        } catch {
            setMessage({ type: 'error', text: 'Network error revoking session' });
        } finally {
            setShowRevokeModal(false);
            setSessionToRevoke(null);
        }
    };

    if (loading) {
        return <div className="loading-sm"><Loader2 className="spin" /> Loading sessions...</div>;
    }

    return (
        <div className="session-section">
            {message.text && (
                <div className={`alert ${message.type}`}>
                    {message.type === 'success' ? <CheckCircle size={16} /> : <AlertCircle size={16} />}
                    {message.text}
                </div>
            )}

            {sessions.length === 0 ? (
                <div className="empty-state-sm">No active sessions</div>
            ) : (
                <table className="session-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Last Used</th>
                            <th>Expires</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {sessions.map((session, idx) => (
                            <tr key={idx} className={session.is_current ? 'current-session' : ''}>
                                <td>
                                    {session.ip_address}
                                    {session.is_current && <span className="current-badge">Current</span>}
                                </td>
                                <td>{new Date(session.last_used).toLocaleString()}</td>
                                <td>{new Date(session.expires_at).toLocaleString()}</td>
                                <td>
                                    {!session.is_current && (
                                        <button
                                            onClick={() => {
                                                setSessionToRevoke(session);
                                                setShowRevokeModal(true);
                                            }}
                                            className="btn-revoke"
                                        >
                                            Revoke
                                        </button>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}

            <ConfirmModal
                isOpen={showRevokeModal}
                title="Revoke Session"
                message="Are you sure you want to revoke this session? The user will be logged out."
                onConfirm={handleRevokeSession}
                onCancel={() => {
                    setShowRevokeModal(false);
                    setSessionToRevoke(null);
                }}
                confirmText="Revoke"
                danger={true}
            />
        </div>
    );
};

// System Update Component
const SystemUpdate = () => {
    const [selectedBranch, setSelectedBranch] = useState('Dev');
    const [status, setStatus] = useState(null);
    const [checking, setChecking] = useState(false);
    const [updating, setUpdating] = useState(false);
    const [showUpdateModal, setShowUpdateModal] = useState(false);
    const [message, setMessage] = useState({ type: '', text: '' });

    const fetchStatus = async (branch = selectedBranch) => {
        try {
            setChecking(true);
            setMessage({ type: '', text: '' });
            const res = await authFetch(`${API_ENDPOINTS.UPDATE_STATUS}?branch=${branch}`);
            if (res.ok) {
                const data = await res.json();
                setStatus(data);
            } else {
                setMessage({ type: 'error', text: 'Failed to fetch update status' });
            }
        } catch (err) {
            console.error('Error fetching update status:', err);
            setMessage({ type: 'error', text: 'Network error checking update status' });
        } finally {
            setChecking(false);
        }
    };

    useEffect(() => {
        fetchStatus(selectedBranch);
    }, [selectedBranch]);

    const handleApplyUpdate = async () => {
        try {
            setUpdating(true);
            setShowUpdateModal(false);
            setMessage({ type: 'info', text: 'Initiating system update... The service will restart.' });

            const res = await authFetch(API_ENDPOINTS.UPDATE_APPLY, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ branch: selectedBranch, force: false })
            });

            if (res.ok) {
                setMessage({ type: 'success', text: 'Update process started! The web interface will refresh once complete.' });
            } else {
                setMessage({ type: 'error', text: 'Failed to trigger update process' });
                setUpdating(false);
            }
        } catch (err) {
            console.error('Error applying update:', err);
            setMessage({ type: 'error', text: 'Network error triggering update' });
            setUpdating(false);
        }
    };

    return (
        <div className="update-section">
            {message.text && (
                <div className={`alert ${message.type}`}>
                    {message.type === 'success' ? <CheckCircle size={16} /> : message.type === 'error' ? <AlertCircle size={16} /> : <Loader2 size={16} className="spin" />}
                    {message.text}
                </div>
            )}

            <div className="update-branch-selector">
                <label className="input-label">Target Branch</label>
                <div className="branch-options">
                    <button
                        type="button"
                        className={`branch-btn ${selectedBranch === 'main' ? 'active' : ''}`}
                        onClick={() => setSelectedBranch('main')}
                    >
                        <GitBranch size={16} />
                        Main (Stable)
                    </button>
                    <button
                        type="button"
                        className={`branch-btn ${selectedBranch === 'Dev' ? 'active' : ''}`}
                        onClick={() => setSelectedBranch('Dev')}
                    >
                        <GitBranch size={16} />
                        Dev (Development)
                    </button>
                </div>
            </div>

            {status && (
                <div className="update-status-info">
                    <div className="status-row">
                        <span>Current Branch:</span>
                        <strong>{status.current_branch}</strong>
                    </div>
                    <div className="status-row">
                        <span>Installed Commit:</span>
                        <code className="commit-hash">{status.current_commit}</code>
                    </div>
                    <div className="status-row">
                        <span>Latest Commit on {selectedBranch}:</span>
                        <code className="commit-hash">{status.latest_commit}</code>
                    </div>
                    <div className="status-row">
                        <span>Status:</span>
                        {status.update_available ? (
                            <span className="badge badge-warning">{status.behind_count} commit(s) behind</span>
                        ) : (
                            <span className="badge badge-success">Up to date</span>
                        )}
                    </div>
                    {status.last_checked && (
                        <span className="hint">Last checked: {new Date(status.last_checked).toLocaleTimeString()}</span>
                    )}
                </div>
            )}

            <div className="update-actions">
                <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => fetchStatus(selectedBranch)}
                    disabled={checking || updating}
                >
                    <RefreshCw size={16} className={checking ? 'spin' : ''} />
                    Check for Updates
                </button>
                <button
                    type="button"
                    className="btn-primary"
                    onClick={() => setShowUpdateModal(true)}
                    disabled={checking || updating || (status && !status.update_available)}
                >
                    {updating ? <Loader2 size={16} className="spin" /> : <Download size={16} />}
                    Update Software
                </button>
            </div>

            <ConfirmModal
                isOpen={showUpdateModal}
                title={`Update SoftRouter (${selectedBranch} branch)`}
                message={`Are you sure you want to update SoftRouter using branch "${selectedBranch}"? The system will back up configs, pull the latest code, rebuild the application, and restart services.`}
                onConfirm={handleApplyUpdate}
                onCancel={() => setShowUpdateModal(false)}
                confirmText="Update Now"
                danger={false}
            />
        </div>
    );
};

export default Settings;
