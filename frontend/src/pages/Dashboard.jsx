import React, { useEffect, useState } from 'react';
import Card from '../components/dashboard/Card';
import { Cpu, HardDrive, Wifi, Activity, ArrowUp, ArrowDown } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './Dashboard.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const Dashboard = () => {
    const [systemStatus, setSystemStatus] = useState(null);
    const [trafficHistory, setTrafficHistory] = useState([]);
    const [loading, setLoading] = useState(true);

    const fetchStatus = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.STATUS);
            if (res.ok) {
                const data = await res.json();
                setSystemStatus(data);
            }
        } catch (err) {
            console.error("Failed to fetch system status", err);
        }
    };

    const fetchTrafficHistory = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.TRAFFIC_HISTORY);
            if (res.ok) {
                const data = await res.json();
                // Ensure we have data
                setTrafficHistory(data || []);
            }
        } catch (err) {
            console.error("Failed to fetch traffic history", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStatus();
        fetchTrafficHistory();

        const statusInterval = setInterval(fetchStatus, 5000);
        const trafficInterval = setInterval(fetchTrafficHistory, 1000); // Live update every second

        return () => {
            clearInterval(statusInterval);
            clearInterval(trafficInterval);
        };
    }, []);

    const formatMemory = (kb) => {
        if (!kb) return "0 GB";
        return (kb / (1024 * 1024)).toFixed(2) + " GB";
    };

    const formatBandwidth = (bytesPerSec) => {
        if (bytesPerSec === undefined || bytesPerSec === null) return "0 B/s";
        if (bytesPerSec === 0) return "0 B/s";
        const k = 1024;
        const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
        const i = Math.floor(Math.log(bytesPerSec) / Math.log(k));
        return parseFloat((bytesPerSec / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const currentTraffic = trafficHistory.length > 0 ? trafficHistory[trafficHistory.length - 1] : { rx_bps: 0, tx_bps: 0 };

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
                    title="Real-time RX"
                    value={loading ? "..." : formatBandwidth(currentTraffic.rx_bps)}
                    subtext="Incoming Aggregate"
                    icon={ArrowDown}
                />
                <Card
                    title="Real-time TX"
                    value={loading ? "..." : formatBandwidth(currentTraffic.tx_bps)}
                    subtext="Outgoing Aggregate"
                    icon={ArrowUp}
                />
            </div>

            {/* Live Throughput Chart */}
            <div className="chart-section glass-panel">
                <div className="chart-header">
                    <div className="title-group">
                        <Activity className="text-secondary" size={20} />
                        <h3>Live Network Throughput</h3>
                    </div>
                    <div className="chart-legend">
                        <div className="legend-item"><span className="dot rx"></span> Download</div>
                        <div className="legend-item"><span className="dot tx"></span> Upload</div>
                    </div>
                </div>
                <div className="chart-wrapper">
                    <ResponsiveContainer width="100%" height={300}>
                        <AreaChart data={trafficHistory}>
                            <defs>
                                <linearGradient id="colorRx" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="colorTx" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="var(--secondary)" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="var(--secondary)" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                            <XAxis
                                dataKey="timestamp"
                                hide={true}
                            />
                            <YAxis
                                tickFormatter={(val) => formatBandwidth(val).split(' ')[0]}
                                stroke="var(--text-muted)"
                                fontSize={12}
                                axisLine={false}
                                tickLine={false}
                            />
                            <Tooltip
                                contentStyle={{ backgroundColor: 'var(--bg-panel)', border: '1px solid var(--glass-border)', borderRadius: '8px' }}
                                itemStyle={{ fontSize: '12px' }}
                                formatter={(val) => formatBandwidth(val)}
                                labelStyle={{ display: 'none' }}
                            />
                            <Area
                                type="monotone"
                                dataKey="rx_bps"
                                stroke="var(--primary)"
                                fillOpacity={1}
                                fill="url(#colorRx)"
                                strokeWidth={2}
                                isAnimationActive={false}
                            />
                            <Area
                                type="monotone"
                                dataKey="tx_bps"
                                stroke="var(--secondary)"
                                fillOpacity={1}
                                fill="url(#colorTx)"
                                strokeWidth={2}
                                isAnimationActive={false}
                            />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>
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
