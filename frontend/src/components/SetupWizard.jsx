import React, { useState, useEffect } from 'react';
import { Loader2 } from 'lucide-react';
import './SetupWizard.css';

export default function SetupWizard({ show, onComplete }) {
    const [interfaces, setInterfaces] = useState([]);
    const [selectedWAN, setSelectedWAN] = useState('');
    const [selectedLANs, setSelectedLANs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        if (show) {
            fetchInterfaces();
        }
    }, [show]);

    const fetchInterfaces = async () => {
        try {
            const token = localStorage.getItem('sr_token');
            const response = await fetch('/api/interfaces', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) throw new Error('Failed to fetch interfaces');

            const data = await response.json();
            setInterfaces(data.interfaces || []);
            setLoading(false);
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    };

    const handleComplete = async () => {
        if (!selectedWAN) {
            setError('Please select a WAN interface');
            return;
        }

        if (selectedLANs.length === 0) {
            setError('Please select at least one LAN interface');
            return;
        }

        try {
            setLoading(true);
            const token = localStorage.getItem('sr_token');

            // Get CSRF token
            const csrfResponse = await fetch('/api/csrf-token', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const csrfData = await csrfResponse.json();

            // Build updates array
            const updates = interfaces.map(iface => {
                let label = 'None';
                if (iface.name === selectedWAN) label = 'WAN';
                if (selectedLANs.includes(iface.name)) label = 'LAN';

                return {
                    interface: iface.name,
                    label: label
                };
            });

            // Apply configuration
            const response = await fetch('/api/interface/metadata/bulk', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfData.token
                },
                body: JSON.stringify({ updates })
            });

            if (!response.ok) throw new Error('Failed to save configuration');

            setLoading(false);
            onComplete();
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    };

    const upInterfaces = interfaces.filter(i => i.state === 'UP');
    const availableLANs = upInterfaces.filter(i => i.name !== selectedWAN);

    if (!show) return null;

    return (
        <div className="modal show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
            <div className="modal-dialog modal-lg modal-dialog-centered">
                <div className="modal-content">
                    <div className="modal-header setup-wizard-header">
                        <h5 className="modal-title">
                            <i className="bi bi-router me-2"></i>
                            Initial Setup Wizard
                        </h5>
                    </div>
                    <div className="modal-body">
                        {loading && !interfaces.length ? (
                            <div className="text-center py-5">
                                <Loader2 className="spin" size={40} />
                                <p className="mt-3">Loading network interfaces...</p>
                            </div>
                        ) : (
                            <>
                                <div className="alert alert-info d-flex align-items-start">
                                    <i className="bi bi-info-circle-fill me-2 mt-1"></i>
                                    <div>
                                        <strong>Welcome to SoftRouter!</strong>
                                        <br />
                                        Please identify your WAN (internet) and LAN (internal network) interfaces.
                                        This is required to configure firewall rules correctly.
                                    </div>
                                </div>

                                {error && (
                                    <div className="alert alert-danger alert-dismissible fade show">
                                        <i className="bi bi-exclamation-triangle-fill me-2"></i>
                                        {error}
                                        <button type="button" className="btn-close" onClick={() => setError('')}></button>
                                    </div>
                                )}

                                <div className="card mb-4">
                                    <div className="card-header bg-primary text-white">
                                        <i className="bi bi-globe me-2"></i>
                                        <strong>Step 1:</strong> Select WAN Interface (Internet Connection)
                                    </div>
                                    <div className="card-body">
                                        {upInterfaces.length === 0 ? (
                                            <div className="alert alert-warning">
                                                No active interfaces found. Please ensure at least one interface is connected.
                                            </div>
                                        ) : (
                                            <div>
                                                {upInterfaces.map(iface => (
                                                    <div key={iface.name} className="form-check mb-2">
                                                        <input
                                                            className="form-check-input"
                                                            type="radio"
                                                            name="wan"
                                                            id={`wan-${iface.name}`}
                                                            value={iface.name}
                                                            checked={selectedWAN === iface.name}
                                                            onChange={(e) => {
                                                                setSelectedWAN(e.target.value);
                                                                setSelectedLANs(selectedLANs.filter(n => n !== e.target.value));
                                                            }}
                                                        />
                                                        <label className="form-check-label d-flex justify-content-between w-100" htmlFor={`wan-${iface.name}`}>
                                                            <div>
                                                                <strong>{iface.name}</strong>
                                                                {iface.ipv4 && <span className="text-muted ms-2">({iface.ipv4})</span>}
                                                            </div>
                                                            <small className="text-muted">{iface.mac}</small>
                                                        </label>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </div>

                                <div className="card">
                                    <div className="card-header bg-success text-white">
                                        <i className="bi bi-hdd-network me-2"></i>
                                        <strong>Step 2:</strong> Select LAN Interfaces (Internal Network)
                                    </div>
                                    <div className="card-body">
                                        {!selectedWAN ? (
                                            <div className="alert alert-info">
                                                <i className="bi bi-arrow-up me-2"></i>
                                                Please select a WAN interface first
                                            </div>
                                        ) : availableLANs.length === 0 ? (
                                            <div className="alert alert-warning">
                                                No additional interfaces available for LAN
                                            </div>
                                        ) : (
                                            <div>
                                                {availableLANs.map(iface => (
                                                    <div key={iface.name} className="form-check mb-2">
                                                        <input
                                                            className="form-check-input"
                                                            type="checkbox"
                                                            id={`lan-${iface.name}`}
                                                            value={iface.name}
                                                            checked={selectedLANs.includes(iface.name)}
                                                            onChange={(e) => {
                                                                if (e.target.checked) {
                                                                    setSelectedLANs([...selectedLANs, iface.name]);
                                                                } else {
                                                                    setSelectedLANs(selectedLANs.filter(n => n !== iface.name));
                                                                }
                                                            }}
                                                        />
                                                        <label className="form-check-label d-flex justify-content-between w-100" htmlFor={`lan-${iface.name}`}>
                                                            <div>
                                                                <strong>{iface.name}</strong>
                                                                {iface.ipv4 && <span className="text-muted ms-2">({iface.ipv4})</span>}
                                                            </div>
                                                            <small className="text-muted">{iface.mac}</small>
                                                        </label>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {selectedWAN && selectedLANs.length > 0 && (
                                    <div className="alert alert-success mt-3">
                                        <i className="bi bi-check-circle-fill me-2"></i>
                                        <strong>Configuration Summary:</strong>
                                        <ul className="mb-0 mt-2">
                                            <li><strong>WAN:</strong> {selectedWAN}</li>
                                            <li><strong>LAN:</strong> {selectedLANs.join(', ')}</li>
                                        </ul>
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                    <div className="modal-footer">
                        <button
                            className="btn btn-primary btn-lg w-100"
                            onClick={handleComplete}
                            disabled={!selectedWAN || selectedLANs.length === 0 || loading}
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="spin me-2" size={18} />
                                    Applying Configuration...
                                </>
                            ) : (
                                <>
                                    <i className="bi bi-check-lg me-2"></i>
                                    Complete Setup
                                </>
                            )}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
