import React, { useEffect, useState } from 'react';
import Card from '../components/dashboard/Card';
import { Cpu, HardDrive, Wifi, Activity } from 'lucide-react';
import './Dashboard.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const Dashboard = () => {
    const [systemStatus, setSystemStatus] = useState(null);
    const [loading, setLoading] = useState(true);

    // Poll backend for status
    useEffect(() => {
        const fetchStatus = async () => {
            try {
                const res = await authFetch(API_ENDPOINTS.STATUS);
                if (res.ok) {
                    const data = await res.json();
                    setSystemStatus(data);
                }
            } catch (err) {
                console.error("Failed to fetch system status", err);
            } finally {
                setLoading(false);
            }
        };

        fetchStatus();
        const interval = setInterval(fetchStatus, 5000); // Update every 5s
        return () => clearInterval(interval);
    }, []);

    const formatMemory = (kb) => {
        if (!kb) return "0 GB";
        return (kb / (1024 * 1024)).toFixed(2) + " GB";
    };

    return (
        <div className="dashboard-container">
            <div className="dashboard-grid">
                <Card
                    title="CPU Load"
                    value={loading ? "..." : (systemStatus?.cpu_usage?.toFixed(2) || "0.00")}
                    subtext="System Load Average"
                    icon={Cpu}
                />
                <Card
                    title="Memory"
                    value={loading ? "..." : formatMemory(systemStatus?.memory_used)}
                    subtext={`of ${formatMemory(systemStatus?.memory_total)} Total`}
                    icon={HardDrive}
                />
                <Card
                    title="Network Status"
                    value="ACTIVE"
                    subtext="All Interfaces Up"
                    icon={Activity}
                />
                <Card
                    title="Time"
                    value={loading ? "..." : new Date(systemStatus?.timestamp).toLocaleTimeString()}
                    subtext="Server Time"
                    icon={Wifi}
                />
            </div>

            <div className="dashboard-sections">
                <div className="section-panel glass-panel">
                    <h3>System Information</h3>
                    <div className="panel-content">
                        <div className="info-row">
                            <span className="label">Hostname:</span>
                            <span className="value">{systemStatus?.hostname || 'Unknown'}</span>
                        </div>
                        <div className="info-row">
                            <span className="label">OS Version:</span>
                            <span className="value">{systemStatus?.os || 'Loading...'}</span>
                        </div>
                        <div className="info-row">
                            <span className="label">Uptime:</span>
                            <span className="value">{systemStatus?.uptime || 'Loading...'}</span>
                        </div>
                    </div>
                </div>

                <div className="section-panel glass-panel">
                    <h3>Recent Alerts</h3>
                    <div className="panel-content">
                        <div className="empty-state">No active alerts</div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
