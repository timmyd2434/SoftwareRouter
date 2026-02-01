import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Activity, RefreshCw, Network } from 'lucide-react';
import './TrafficStats.css';
import { authFetch } from '../apiConfig';

const TrafficStats = () => {
    const [history, setHistory] = useState([]);
    const [interfaces, setInterfaces] = useState([]);
    const [selectedInterface, setSelectedInterface] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchInterfaces();
    }, []);

    useEffect(() => {
        if (selectedInterface) {
            fetchHistory();
            const interval = setInterval(fetchHistory, 1000);
            return () => clearInterval(interval);
        }
    }, [selectedInterface]);

    const fetchInterfaces = async () => {
        try {
            const res = await authFetch('/api/interfaces');
            if (res.ok) {
                const data = await res.json();
                setInterfaces(data);
                if (data.length > 0 && !selectedInterface) {
                    setSelectedInterface(data[0].name);
                }
            }
        } catch (err) {
            console.error(err);
        }
    };

    const fetchHistory = async () => {
        try {
            const res = await authFetch(`/api/traffic/history?interface=${selectedInterface}`);
            if (res.ok) {
                const data = await res.json();
                // Format timestamp
                const formatted = data.map(pt => ({
                    ...pt,
                    time: new Date(pt.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
                    rx_mbps: (pt.rx_rate * 8 / 1000000).toFixed(2),
                    tx_mbps: (pt.tx_rate * 8 / 1000000).toFixed(2)
                }));
                setHistory(formatted);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="traffic-stats-container">
            <div className="page-header">
                <div className="title-area">
                    <Activity size={28} className="text-secondary" />
                    <div>
                        <h2>Traffic Stats</h2>
                        <p className="subtitle">Historical bandwidth usage</p>
                    </div>
                </div>
            </div>

            <div className="traffic-stats-grid">
                {/* Interface List */}
                <div className="glass-panel">
                    <h3>Interfaces</h3>
                    <div className="interface-list">
                        {interfaces.map(iface => (
                            <div
                                key={iface.name}
                                className={`interface-item ${selectedInterface === iface.name ? 'active' : ''}`}
                                onClick={() => setSelectedInterface(iface.name)}
                            >
                                <Network size={16} />
                                <span>{iface.name}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Graph */}
                <div className="glass-panel chart-panel">
                    <h3>{selectedInterface} Usage (Mbps)</h3>

                    <div className="chart-container">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={history}>
                                <defs>
                                    <linearGradient id="colorRx" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                                        <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                                    </linearGradient>
                                    <linearGradient id="colorTx" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8} />
                                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} minTickGap={30} />
                                <YAxis stroke="#94a3b8" fontSize={12} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#e2e8f0' }}
                                />
                                <Legend />
                                <Area
                                    type="monotone"
                                    dataKey="rx_mbps"
                                    stroke="#10b981"
                                    fillOpacity={1}
                                    fill="url(#colorRx)"
                                    name="Download (Mbps)"
                                    isAnimationActive={false}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="tx_mbps"
                                    stroke="#3b82f6"
                                    fillOpacity={1}
                                    fill="url(#colorTx)"
                                    name="Upload (Mbps)"
                                    isAnimationActive={false}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default TrafficStats;
