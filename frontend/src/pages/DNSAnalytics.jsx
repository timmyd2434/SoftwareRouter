import React, { useEffect, useState } from 'react';
import { Shield, Search, Globe, Users, Activity, ExternalLink, RefreshCw, BarChart3, PieChart } from 'lucide-react';
import { PieChart as ReChartsPie, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import './DNSAnalytics.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const DNSAnalytics = () => {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchStats = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.DNS_STATS);
            if (res.ok) {
                const data = await res.json();
                setStats(data);
            }
        } catch (err) {
            console.error("Failed to fetch DNS stats", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStats();
        const interval = setInterval(fetchStats, 60000); // Update every minute
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <div className="dns-loading">
                <RefreshCw className="spin" size={48} />
                <p>Analyzing network traffic...</p>
            </div>
        );
    }

    const pieData = [
        { name: 'Blocked', value: stats?.blocked_filtering || 0 },
        { name: 'Allowed', value: (stats?.total_queries || 0) - (stats?.blocked_filtering || 0) },
    ];

    const COLORS = ['#ef4444', 'var(--primary)'];

    return (
        <div className="dns-analytics-container">
            <div className="section-header">
                <div>
                    <h2>Ad-Blocking Analytics 🚫</h2>
                    <span className="subtitle">Real-time DNS filtering and network privacy metrics</span>
                </div>
                <button className="refresh-btn" onClick={() => { setLoading(true); fetchStats(); }}>
                    <RefreshCw size={18} /> Refresh
                </button>
            </div>

            <div className="dns-stats-overview">
                <div className="dns-stat-card glass-panel highlight">
                    <div className="icon-wrap blocked">
                        <Shield size={24} />
                    </div>
                    <div className="details">
                        <span className="label">Total Blocks</span>
                        <h2 className="value text-error">{(stats?.blocked_filtering || 0).toLocaleString()}</h2>
                        <span className="sub">Since last reset</span>
                    </div>
                </div>

                <div className="dns-stat-card glass-panel">
                    <div className="icon-wrap total">
                        <Activity size={24} />
                    </div>
                    <div className="details">
                        <span className="label">Total Queries</span>
                        <h2 className="value">{(stats?.total_queries || 0).toLocaleString()}</h2>
                        <span className="sub">Requests handled</span>
                    </div>
                </div>

                <div className="dns-stat-card glass-panel">
                    <div className="icon-wrap percent">
                        <BarChart3 size={24} />
                    </div>
                    <div className="details">
                        <span className="label">Block Percentage</span>
                        <h2 className="value text-secondary">{(stats?.blocked_percentage || 0).toFixed(1)}%</h2>
                        <span className="sub">Privacy efficiency</span>
                    </div>
                </div>
            </div>

            <div className="dns-charts-grid">
                <div className="chart-item glass-panel">
                    <h3>Filtering Distribution</h3>
                    <div className="distribution-wrap">
                        <div className="pie-wrap">
                            <ResponsiveContainer width="100%" height={200}>
                                <ReChartsPie>
                                    <Pie
                                        data={pieData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={80}
                                        paddingAngle={5}
                                        dataKey="value"
                                    >
                                        {pieData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip />
                                </ReChartsPie>
                            </ResponsiveContainer>
                        </div>
                        <div className="legend">
                            <div className="legend-row">
                                <span className="dot blocked"></span>
                                <span>Blocked Queries</span>
                            </div>
                            <div className="legend-row">
                                <span className="dot allowed"></span>
                                <span>Allowed Traffic</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="chart-item glass-panel">
                    <h3>Top Blocked Domains</h3>
                    <div className="top-list">
                        {(stats?.top_blocked || []).length === 0 ? (
                            <div className="empty-list">No domains blocked yet</div>
                        ) : (
                            stats.top_blocked.map((item, idx) => (
                                <div key={idx} className="list-item">
                                    <span className="domain">{item.domain}</span>
                                    <span className="hits text-error">{item.hits} blocks</span>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>

            <div className="dns-lower-grid">
                <div className="lower-item glass-panel">
                    <h3>Recent Queries</h3>
                    <div className="top-list full">
                        {(stats?.top_queries || []).map((item, idx) => (
                            <div key={idx} className="list-item">
                                <span className="domain">{item.domain}</span>
                                <span className="hits">{item.hits} requests</span>
                                <div className="bar-bg">
                                    <div className="bar-fill" style={{ width: `${(item.hits / stats.total_queries) * 100}%` }}></div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="lower-item glass-panel external-mgmt">
                    <Globe size={48} className="icon-faded" />
                    <h3>Advanced Management</h3>
                    <p>For detailed rule customization, upstream DNS settings, and per-client filtering, use the full AdGuard Home interface.</p>
                    <a
                        href={`http://${window.location.hostname}:3000`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="external-link-btn"
                    >
                        Open AdGuard Home UI <ExternalLink size={16} />
                    </a>
                </div>
            </div>
        </div>
    );
};

export default DNSAnalytics;
