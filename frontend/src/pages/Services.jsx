import React, { useEffect, useState } from 'react';
import { Server, CheckCircle, XCircle, Power, RotateCw, AlertCircle } from 'lucide-react';
import './Services.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const Services = () => {
    const [services, setServices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState({});

    const fetchServices = () => {
        setLoading(true);
        authFetch(API_ENDPOINTS.SERVICES)
            .then(res => res.json())
            .then(data => {
                setServices(data);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    };

    const handleServiceAction = async (serviceName, displayName, action) => {
        if (!serviceName) {
            alert('Unknown service ID for ' + displayName);
            return;
        }

        // Set loading state for this specific service
        setActionLoading(prev => ({ ...prev, [displayName]: action }));

        try {
            const res = await authFetch(API_ENDPOINTS.SERVICES_CONTROL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ serviceName, action })
            });

            if (res.ok) {
                const result = await res.json();
                // Wait a moment for systemd to update, then refresh
                setTimeout(() => {
                    fetchServices();
                    setActionLoading(prev => ({ ...prev, [displayName]: null }));
                }, 1000);
            } else {
                const text = await res.text();
                console.error('Service action failed:', text);

                // More helpful error message
                if (text.includes('failed because the control process exited')) {
                    alert(`Failed to ${action} ${displayName}\n\nThis service may be misconfigured or have conflicts.\n\nSuggested actions:\n• Check: sudo systemctl status ${serviceName}\n• View logs: sudo journalctl -xeu ${serviceName}\n\nNote: DHCP services typically require proper network configuration.`);
                } else {
                    alert(`Action failed: ${text}`);
                }
                setActionLoading(prev => ({ ...prev, [displayName]: null }));
            }
        } catch (err) {
            console.error(err);
            alert(`Network error: ${err.message}`);
            setActionLoading(prev => ({ ...prev, [displayName]: null }));
        }
    };

    useEffect(() => {
        fetchServices();
        // Auto-refresh every 10 seconds
        const interval = setInterval(fetchServices, 10000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="services-container">
            <div className="section-header">
                <div>
                    <h2>System Services</h2>
                    <span className="subtitle">Manage DHCP, DNS, and VPN modules</span>
                </div>
                <button className="icon-btn" onClick={fetchServices} title="Refresh Services">
                    <RotateCw size={20} className={loading ? "spin" : ""} />
                </button>
            </div>

            {loading && services.length === 0 ? (
                <div className="loading-state">Loading services...</div>
            ) : (
                <div className="services-grid">
                    {services.map((svc, idx) => {
                        const isLoading = actionLoading[svc.name];
                        const isRunning = svc.status === 'Running';

                        return (
                            <div key={idx} className="service-card glass-panel">
                                <div className="svc-header">
                                    <div className="svc-icon-wrapper">
                                        <Server size={24} />
                                    </div>
                                    <div className="svc-info">
                                        <h3>{svc.name}</h3>
                                        {svc.version !== '-' && <span className="svc-version">v{svc.version}</span>}
                                    </div>
                                </div>

                                <div className="svc-status-row">
                                    <div className={`status-pill ${svc.status.toLowerCase()}`}>
                                        {isRunning ? <CheckCircle size={14} /> : <XCircle size={14} />}
                                        {svc.status}
                                    </div>
                                    {svc.uptime !== '-' && <span className="uptime">{svc.uptime}</span>}
                                </div>

                                <div className="svc-controls">
                                    <button
                                        className={`control-btn ${isRunning ? 'stop' : 'start'}`}
                                        onClick={() => handleServiceAction(svc.service_id, svc.name, isRunning ? 'stop' : 'start')}
                                        disabled={isLoading}
                                    >
                                        {isLoading === 'start' || isLoading === 'stop' ? (
                                            <RotateCw size={16} className="spin" />
                                        ) : (
                                            <Power size={16} />
                                        )}
                                        {isLoading === 'start' && 'Starting...'}
                                        {isLoading === 'stop' && 'Stopping...'}
                                        {!isLoading && (isRunning ? 'Stop' : 'Start')}
                                    </button>
                                    <button
                                        className="control-btn icon-only"
                                        onClick={() => handleServiceAction(svc.service_id, svc.name, 'restart')}
                                        disabled={isLoading || !isRunning}
                                        title="Restart Service"
                                    >
                                        {isLoading === 'restart' ? (
                                            <RotateCw size={16} className="spin" />
                                        ) : (
                                            <RotateCw size={16} />
                                        )}
                                    </button>
                                </div>

                                {isLoading && (
                                    <div className="action-indicator">
                                        <AlertCircle size={14} />
                                        Performing {isLoading}...
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}

        </div>
    );
};

export default Services;
