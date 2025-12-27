import React, { useEffect, useState } from 'react';
import Card from '../components/dashboard/Card';
import { Cpu, HardDrive, Wifi, Activity } from 'lucide-react';
import './Dashboard.css';
import { API_ENDPOINTS } from '../apiConfig';

const Dashboard = () => {
    const [systemStatus, setSystemStatus] = useState(null);
    const [loading, setLoading] = useState(true);

    // Poll backend for status
    useEffect(() => {
        const fetchStatus = async () => {
            try {
                const res = await fetch(API_ENDPOINTS.STATUS);
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

    return (
        <div className="dashboard-container">
            <div className="dashboard-grid">
                <Card
                    title="CPU Usage"
                    value={loading ? "..." : "12%"}
                    subtext="4 Cores Active"
                    icon={Cpu}
                    trend={2.4}
                />
                <Card
                    title="Memory"
                    value={loading ? "..." : "2.4 GB"}
                    subtext="of 8.0 GB Total"
                    icon={HardDrive}
                />
                <Card
                    title="Network Traffic"
                    value="1.2 Gbps"
                    subtext="Total Throughput"
                    icon={Activity}
                    trend={12}
                />
                <Card
                    title="Active Devices"
                    value="24"
                    subtext="Connected Clients"
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
