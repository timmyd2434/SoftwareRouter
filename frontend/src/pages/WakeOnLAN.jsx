import React, { useEffect, useState } from 'react';
import { Power, Plus, X, Trash2 } from 'lucide-react';
import './WakeOnLAN.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const WakeOnLAN = () => {
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [quickMAC, setQuickMAC] = useState('');
    const [waking, setWaking] = useState(null);
    const [message, setMessage] = useState(null);

    // New device form
    const [deviceForm, setDeviceForm] = useState({
        name: '',
        macAddress: '',
        ipAddress: ''
    });

    // Fetch saved devices
    const fetchDevices = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.WOL_DEVICES);
            const data = await res.json();
            setDevices(Array.isArray(data) ? data : []);
        } catch (err) {
            console.error("Failed to fetch devices:", err);
            setDevices([]);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDevices();
    }, []);

    // Wake device by MAC
    const wakeDevice = async (macAddress, deviceName = null) => {
        setWaking(macAddress);
        setMessage(null);

        try {
            const res = await authFetch(API_ENDPOINTS.WOL_WAKE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ macAddress })
            });

            if (res.ok) {
                await res.json();
                setMessage({ type: 'success', text: deviceName ? `✓ Waking ${deviceName}...` : '✓ Magic packet sent!' });
                if (!deviceName) setQuickMAC(''); // Clear quick wake input
            } else {
                const text = await res.text();
                setMessage({ type: 'error', text: `Failed: ${text}` });
            }
        } catch (err) {
            setMessage({ type: 'error', text: `Error: ${err.message}` });
        } finally {
            setWaking(null);
            setTimeout(() => setMessage(null), 5000);
        }
    };

    // Save new device
    const saveDevice = async () => {
        if (!deviceForm.name || !deviceForm.macAddress) {
            alert("Name and MAC address are required");
            return;
        }

        try {
            const res = await authFetch(API_ENDPOINTS.WOL_DEVICES, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(deviceForm)
            });

            if (res.ok) {
                setShowModal(false);
                setDeviceForm({ name: '', macAddress: '', ipAddress: '' });
                fetchDevices();
                setMessage({ type: 'success', text: '✓ Device saved!' });
                setTimeout(() => setMessage(null), 3000);
            } else {
                const text = await res.text();
                alert(`Failed to save device: ${text}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    // Delete device
    const deleteDevice = async (name) => {
        if (!confirm(`Delete device "${name}"?`)) {
            return;
        }

        try {
            const res = await authFetch(`${API_ENDPOINTS.WOL_DEVICES}?name=${encodeURIComponent(name)}`, {
                method: 'DELETE'
            });

            if (res.ok) {
                fetchDevices();
                setMessage({ type: 'success', text: '✓ Device deleted' });
                setTimeout(() => setMessage(null), 3000);
            } else {
                const text = await res.text();
                alert(`Failed to delete device: ${text}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    // Format MAC address as user types
    const formatMACInput = (value) => {
        // Remove non-hex characters
        const cleaned = value.replace(/[^0-9A-Fa-f]/g, '');

        // Add colons every 2 characters
        let formatted = '';
        for (let i = 0; i < cleaned.length && i < 12; i++) {
            if (i > 0 && i % 2 === 0) formatted += ':';
            formatted += cleaned[i];
        }

        return formatted.toUpperCase();
    };

    return (
        <div className="wol-container">
            <div className="page-header">
                <div>
                    <h1 className="page-title">
                        <Power size={28} className="title-icon" />
                        Wake-on-LAN
                    </h1>
                    <p className="page-subtitle">Wake sleeping devices on your network</p>
                </div>
            </div>

            {message && (
                <div className={`alert-box ${message.type === 'success' ? 'success' : 'error'}`}>
                    {message.text}
                </div>
            )}

            {/* Saved Devices Section */}
            <div className="glass-panel" style={{ marginBottom: 'var(--space-6)' }}>
                <div style={{ padding: 'var(--space-6)', borderBottom: '1px solid var(--glass-border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                            <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Saved Devices</h3>
                            <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                Manage frequently-woken devices
                            </p>
                        </div>
                        <button className="primary-btn" onClick={() => setShowModal(true)}>
                            <Plus size={18} />
                            Add Device
                        </button>
                    </div>
                </div>

                <div className="devices-grid">
                    {loading ? (
                        <div className="loading-state">Loading devices...</div>
                    ) : devices.length === 0 ? (
                        <div className="empty-state">
                            <Power size={48} style={{ opacity: 0.3, marginBottom: '12px' }} />
                            <p>No saved devices</p>
                            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                Add devices for quick wake access
                            </p>
                        </div>
                    ) : (
                        devices.map((device) => (
                            <div key={device.name} className="device-card">
                                <div className="device-info">
                                    <h4>{device.name}</h4>
                                    <div className="device-mac">{device.macAddress}</div>
                                    {device.ipAddress && (
                                        <div className="device-ip">{device.ipAddress}</div>
                                    )}
                                </div>
                                <div className="device-actions">
                                    <button
                                        className="primary-btn"
                                        onClick={() => wakeDevice(device.macAddress, device.name)}
                                        disabled={waking === device.macAddress}
                                    >
                                        <Power size={16} />
                                        {waking === device.macAddress ? 'Waking...' : 'Wake'}
                                    </button>
                                    <button
                                        className="icon-btn-sm"
                                        onClick={() => deleteDevice(device.name)}
                                        title="Delete Device"
                                    >
                                        <Trash2 size={16} />
                                    </button>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>

            {/* Quick Wake Section */}
            <div className="glass-panel">
                <div style={{ padding: 'var(--space-6)' }}>
                    <h3 style={{ margin: '0 0 4px 0', fontSize: '1.1rem' }}>Quick Wake</h3>
                    <p style={{ margin: '0 0 var(--space-4) 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                        Wake a device without saving it
                    </p>

                    <div className="quick-wake-form">
                        <div className="form-group" style={{ flex: 1 }}>
                            <label>MAC Address</label>
                            <input
                                type="text"
                                className="form-input"
                                placeholder="AA:BB:CC:DD:EE:FF"
                                value={quickMAC}
                                onChange={(e) => setQuickMAC(formatMACInput(e.target.value))}
                                onKeyPress={(e) => {
                                    if (e.key === 'Enter' && quickMAC) {
                                        wakeDevice(quickMAC);
                                    }
                                }}
                            />
                        </div>
                        <button
                            className="primary-btn"
                            style={{ marginTop: '28px' }}
                            onClick={() => wakeDevice(quickMAC)}
                            disabled={!quickMAC || waking === quickMAC}
                        >
                            <Power size={18} />
                            {waking === quickMAC ? 'Waking...' : 'Wake Device'}
                        </button>
                    </div>

                    <div className="info-box" style={{ marginTop: 'var(--space-4)' }}>
                        <strong>Note:</strong> Device must be on the same network and have Wake-on-LAN enabled in BIOS/UEFI settings.
                    </div>
                </div>
            </div>

            {/* Add Device Modal */}
            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Add Device</h3>
                            <button className="close-btn" onClick={() => setShowModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Device Name *</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="Office Desktop"
                                    value={deviceForm.name}
                                    onChange={(e) => setDeviceForm({ ...deviceForm, name: e.target.value })}
                                />
                            </div>

                            <div className="form-group">
                                <label>MAC Address *</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="AA:BB:CC:DD:EE:FF"
                                    value={deviceForm.macAddress}
                                    onChange={(e) => setDeviceForm({ ...deviceForm, macAddress: formatMACInput(e.target.value) })}
                                />
                            </div>

                            <div className="form-group">
                                <label>IP Address (Optional)</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="192.168.1.100"
                                    value={deviceForm.ipAddress}
                                    onChange={(e) => setDeviceForm({ ...deviceForm, ipAddress: e.target.value })}
                                />
                                <small style={{ color: '#888', fontSize: '12px' }}>For reference only, not used for waking</small>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={saveDevice}>Save Device</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default WakeOnLAN;
