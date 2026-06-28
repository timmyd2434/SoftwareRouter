import React, { useEffect, useState } from 'react';
import { Shield, Globe, Plus, X, Download } from 'lucide-react';
import './GeoBlocking.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

// Common countries for geoblocking (pre-populated for convenience)
const COMMON_COUNTRIES = [
    { code: 'CN', name: 'China' },
    { code: 'RU', name: 'Russia' },
    { code: 'KP', name: 'North Korea' },
    { code: 'IR', name: 'Iran' },
    { code: 'SY', name: 'Syria' },
    { code: 'CU', name: 'Cuba' },
    { code: 'SD', name: 'Sudan' },
    { code: 'VE', name: 'Venezuela' },
    { code: 'BY', name: 'Belarus' },
    { code: 'MM', name: 'Myanmar' },
];

const GeoBlocking = () => {
    const [config, setConfig] = useState({
        enabled: false,
        blockedCountries: [],
        allowPrivateIPs: true,
        mode: 'blocklist'
    });
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState(null);
    const [customCountry, setCustomCountry] = useState('');

    // Fetch configuration
    const fetchConfig = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.GEOBLOCKING_CONFIG);
            const data = await res.json();
            setConfig(data);
        } catch (err) {
            console.error("Failed to fetch config:", err);
        }
    };

    useEffect(() => {
        fetchConfig();
    }, []);

    // Save configuration
    const saveConfig = async () => {
        setSaving(true);
        setMessage(null);

        try {
            const res = await authFetch(API_ENDPOINTS.GEOBLOCKING_CONFIG, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });

            if (res.ok) {
                setMessage({ type: 'success', text: '✓ GeoBlocking configuration saved and applied!' });
                setTimeout(() => setMessage(null), 5000);
            } else {
                const text = await res.text();
                setMessage({ type: 'error', text: `Failed: ${text}` });
            }
        } catch (err) {
            setMessage({ type: 'error', text: `Error: ${err.message}` });
        } finally {
            setSaving(false);
        }
    };

    // Add country to blocked list
    const addCountry = (countryCode) => {
        if (!countryCode || config.blockedCountries.includes(countryCode.toUpperCase())) {
            return;
        }

        setConfig({
            ...config,
            blockedCountries: [...config.blockedCountries, countryCode.toUpperCase()]
        });
        setCustomCountry('');
    };

    // Remove country from blocked list
    const removeCountry = (countryCode) => {
        setConfig({
            ...config,
            blockedCountries: config.blockedCountries.filter(c => c !== countryCode)
        });
    };

    // Toggle enabled
    const toggleEnabled = () => {
        setConfig({ ...config, enabled: !config.enabled });
    };

    return (
        <div className="geoblocking-container">
            <div className="page-header">
                <div>
                    <h1 className="page-title">
                        <Globe size={28} className="title-icon" />
                        GeoBlocking
                    </h1>
                    <p className="page-subtitle">Block traffic from specific countries</p>
                </div>
                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    <label className="toggle-switch">
                        <input
                            type="checkbox"
                            checked={config.enabled}
                            onChange={toggleEnabled}
                        />
                        <span className="toggle-slider"></span>
                    </label>
                    <span style={{ fontWeight: '500' }}>
                        {config.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                </div>
            </div>

            {message && (
                <div className={`alert-box ${message.type === 'success' ? 'success' : 'error'}`}>
                    {message.text}
                </div>
            )}

            {/* Configuration Panel */}
            <div className="glass-panel" style={{ marginBottom: 'var(--space-6)' }}>
                <div style={{ padding: 'var(--space-6)' }}>
                    <h3 style={{ margin: '0 0 16px 0', fontSize: '1.1rem' }}>
                        Blocked Countries ({config.blockedCountries.length})
                    </h3>

                    {/* Selected Countries */}
                    {config.blockedCountries.length > 0 && (
                        <div className="selected-countries">
                            {config.blockedCountries.map(code => (
                                <div key={code} className="country-chip">
                                    <Shield size={14} />
                                    <span>{code}</span>
                                    <button
                                        className="chip-remove"
                                        onClick={() => removeCountry(code)}
                                        title="Remove country"
                                    >
                                        <X size={14} />
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}

                    {config.blockedCountries.length === 0 && (
                        <div className="empty-state-inline">
                            <p>No countries blocked</p>
                        </div>
                    )}

                    {/* Quick Add Common Countries */}
                    <div style={{ marginTop: 'var(--space-4)' }}>
                        <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500' }}>
                            Quick Add Common Countries
                        </label>
                        <div className="common-countries-grid">
                            {COMMON_COUNTRIES.map(country => (
                                <button
                                    key={country.code}
                                    className={`country-btn ${config.blockedCountries.includes(country.code) ? 'selected' : ''}`}
                                    onClick={() => {
                                        if (config.blockedCountries.includes(country.code)) {
                                            removeCountry(country.code);
                                        } else {
                                            addCountry(country.code);
                                        }
                                    }}
                                >
                                    {country.blockedCountries?.includes(country.code) ? '✓ ' : ''}
                                    {country.name} ({country.code})
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Add Custom Country */}
                    <div style={{ marginTop: 'var(--space-4)' }}>
                        <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500' }}>
                            Add Custom Country (ISO Code)
                        </label>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <input
                                type="text"
                                className="form-input"
                                placeholder="US, GB, DE, etc."
                                value={customCountry}
                                onChange={(e) => setCustomCountry(e.target.value.toUpperCase().substring(0, 2))}
                                onKeyPress={(e) => {
                                    if (e.key === 'Enter') {
                                        addCountry(customCountry);
                                    }
                                }}
                                style={{ maxWidth: '200px' }}
                            />
                            <button
                                className="primary-btn"
                                onClick={() => addCountry(customCountry)}
                                disabled={!customCountry || customCountry.length !== 2}
                            >
                                <Plus size={18} />
                                Add
                            </button>
                        </div>
                        <small style={{ color: '#888', fontSize: '12px', marginTop: '4px', display: 'block' }}>
                            Use 2-letter ISO 3166-1 country codes (e.g., US, GB, CN, RU)
                        </small>
                    </div>

                    {/* Options */}
                    <div style={{ marginTop: 'var(--space-6)', paddingTop: 'var(--space-4)', borderTop: '1px solid var(--glass-border)' }}>
                        <h4 style={{ margin: '0 0 12px 0', fontSize: '0.95rem' }}>Options</h4>

                        <label className="checkbox-label">
                            <input
                                type="checkbox"
                                checked={config.allowPrivateIPs}
                                onChange={(e) => setConfig({ ...config, allowPrivateIPs: e.target.checked })}
                            />
                            <span>Allow private/local IP addresses (RFC1918)</span>
                        </label>

                        <div style={{ marginTop: '12px' }}>
                            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem' }}>Mode</label>
                            <select
                                className="form-input"
                                value={config.mode}
                                onChange={(e) => setConfig({ ...config, mode: e.target.value })}
                                style={{ maxWidth: '300px' }}
                            >
                                <option value="blocklist">Blocklist (Block selected countries)</option>
                                <option value="allowlist">Allowlist (Only allow selected countries)</option>
                            </select>
                        </div>
                    </div>

                    {/* Info Box */}
                    <div className="info-box" style={{ marginTop: 'var(--space-4)' }}>
                        <strong>How it works:</strong> IP ranges for selected countries are automatically downloaded from ipdeny.com
                        when you save. Firewall rules are applied immediately. Country IP lists are cached locally.
                    </div>

                    {/* Save Button */}
                    <div style={{ marginTop: 'var(--space-6)', display: 'flex', gap: '12px' }}>
                        <button
                            className="primary-btn"
                            onClick={saveConfig}
                            disabled={saving}
                            style={{ minWidth: '140px' }}
                        >
                            {saving ? 'Applying...' : 'Apply Changes'}
                        </button>
                        {config.blockedCountries.length > 0 && (
                            <button
                                className="secondary-btn"
                                onClick={() => setConfig({ ...config, blockedCountries: [] })}
                            >
                                Clear All
                            </button>
                        )}
                    </div>
                </div>
            </div>

            {/* Warning Box */}
            {config.mode === 'allowlist' && (
                <div className="warning-box">
                    <strong>⚠️ Allowlist Mode Warning:</strong> In allowlist mode, ALL traffic except from selected countries will be blocked.
                    Make sure you include your own country to avoid locking yourself out!
                </div>
            )}
        </div>
    );
};

export default GeoBlocking;
