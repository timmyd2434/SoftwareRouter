import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Shield, Cloud, Terminal, Save, Lock, User, CheckCircle, AlertCircle, Loader2, Globe } from 'lucide-react';
import { API_ENDPOINTS, authFetch } from '../apiConfig';
import './Settings.css';

const Settings = () => {
    const [config, setConfig] = useState({
        cf_token: '',
        protected_subnet: '10.0.0.0/24',
        ad_blocker: 'none',
        openvpn_port: 1194
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
        } catch (err) {
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
        } catch (err) {
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
        } catch (err) {
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
            </div>
        </div>
    );
};

export default Settings;
