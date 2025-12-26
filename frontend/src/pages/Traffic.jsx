import React, { useEffect, useState } from 'react';
import { Activity, RefreshCw, TrendingUp, TrendingDown, AlertCircle, Network } from 'lucide-react';
import './Traffic.css';

const Traffic = () => {
    const [stats, setStats] = useState({});
    const [connections, setConnections] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedInterface, setSelectedInterface] = useState(null);

    // Helper to format bytes to human readable
    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    // Helper to format large numbers
    const formatNumber = (num) => {
        if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(2) + 'K';
        return num;
    };

    const fetchStats = () => {
        setLoading(true);
        fetch('http://localhost:8080/api/traffic/stats')
            .then(res => res.json())
            .then(data => {
                setStats(data);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    };

    const fetchConnections = () => {
        fetch('http://localhost:8080/api/traffic/connections')
            .then(res => res.json())
            .then(data => {
                setConnections(data || []);
            })
            .catch(err => {
                console.error(err);
            });
    };

    useEffect(() => {
        fetchStats();
        fetchConnections();

        // Auto-refresh every 2 seconds
        const interval = setInterval(() => {
            fetchStats();
            fetchConnections();
        }, 2000);

        return () => clearInterval(interval);
    }, []);

    const interfaceList = Object.keys(stats).filter(name => !name.startsWith('lo'));
    const selectedStats = selectedInterface && stats[selectedInterface];

    return (
        <div className="traffic-container">
            <div className="section-header">
                <div>
                    <h2>Traffic Monitoring</h2>
                    <span className="subtitle">Real-time network statistics and active connections</span>
                </div>
                <div className="header-actions">
                    <button className="icon-btn" onClick={() => { fetchStats(); fetchConnections(); }} title="Refresh">
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                </div>
            </div>

            {loading && Object.keys(stats).length === 0 ? (
                <div className="loading-state">Loading traffic statistics...</div>
            ) : (
                <>
                    {/* Interface Statistics Grid */}
                    <div className="stats-grid">
                        {interfaceList.map(ifaceName => {
                            const ifaceStats = stats[ifaceName];
                            const totalBytes = ifaceStats.rx_bytes + ifaceStats.tx_bytes;

                            return (
                                <div
                                    key={ifaceName}
                                    className={`stat-card glass-panel ${selectedInterface === ifaceName ? 'selected' : ''}`}
                                    onClick={() => setSelectedInterface(ifaceName)}
                                >
                                    <div className="stat-header">
                                        <Network size={20} className="stat-icon" />
                                        <h3>{ifaceName}</h3>
                                    </div>

                                    <div className="stat-totals">
                                        <div className="stat-item">
                                            <div className="stat-label">
                                                <TrendingDown size={16} className="rx-color" />
                                                RX
                                            </div>
                                            <div className="stat-value">{formatBytes(ifaceStats.rx_bytes)}</div>
                                            <div className="stat-packets">{formatNumber(ifaceStats.rx_packets)} pkts</div>
                                        </div>
                                        <div className="stat-item">
                                            <div className="stat-label">
                                                <TrendingUp size={16} className="tx-color" />
                                                TX
                                            </div>
                                            <div className="stat-value">{formatBytes(ifaceStats.tx_bytes)}</div>
                                            <div className="stat-packets">{formatNumber(ifaceStats.tx_packets)} pkts</div>
                                        </div>
                                    </div>

                                    {(ifaceStats.rx_errors > 0 || ifaceStats.tx_errors > 0 || ifaceStats.rx_dropped > 0 || ifaceStats.tx_dropped > 0) && (
                                        <div className="stat-errors">
                                            <AlertCircle size={14} />
                                            Errors: {ifaceStats.rx_errors + ifaceStats.tx_errors} | Dropped: {ifaceStats.rx_dropped + ifaceStats.tx_dropped}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>

                    {/* Detailed Stats for Selected Interface */}
                    {selectedStats && (
                        <div className="detailed-stats glass-panel">
                            <h3>Detailed Statistics: {selectedInterface}</h3>
                            <div className="details-grid">
                                <div className="detail-card">
                                    <div className="detail-label">Receive (RX)</div>
                                    <div className="detail-row">
                                        <span>Bytes</span>
                                        <span className="detail-value">{formatBytes(selectedStats.rx_bytes)}</span>
                                    </div>
                                    <div className="detail-row">
                                        <span>Packets</span>
                                        <span className="detail-value">{selectedStats.rx_packets.toLocaleString()}</span>
                                    </div>
                                    <div className="detail-row error">
                                        <span>Errors</span>
                                        <span className="detail-value">{selectedStats.rx_errors}</span>
                                    </div>
                                    <div className="detail-row error">
                                        <span>Dropped</span>
                                        <span className="detail-value">{selectedStats.rx_dropped}</span>
                                    </div>
                                </div>

                                <div className="detail-card">
                                    <div className="detail-label">Transmit (TX)</div>
                                    <div className="detail-row">
                                        <span>Bytes</span>
                                        <span className="detail-value">{formatBytes(selectedStats.tx_bytes)}</span>
                                    </div>
                                    <div className="detail-row">
                                        <span>Packets</span>
                                        <span className="detail-value">{selectedStats.tx_packets.toLocaleString()}</span>
                                    </div>
                                    <div className="detail-row error">
                                        <span>Errors</span>
                                        <span className="detail-value">{selectedStats.tx_errors}</span>
                                    </div>
                                    <div className="detail-row error">
                                        <span>Dropped</span>
                                        <span className="detail-value">{selectedStats.tx_dropped}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Active Connections Table */}
                    <div className="connections-section">
                        <h3>Active Connections ({connections.length})</h3>
                        <div className="connections-table-container glass-panel">
                            <table className="connections-table">
                                <thead>
                                    <tr>
                                        <th>Protocol</th>
                                        <th>State</th>
                                        <th>Local Address</th>
                                        <th>Remote Address</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {connections.length === 0 ? (
                                        <tr>
                                            <td colSpan="4" className="empty-state">No active connections</td>
                                        </tr>
                                    ) : (
                                        connections.slice(0, 50).map((conn, idx) => (
                                            <tr key={idx}>
                                                <td>
                                                    <span className={`protocol-badge ${conn.protocol}`}>
                                                        {conn.protocol}
                                                    </span>
                                                </td>
                                                <td>
                                                    <span className={`state-badge ${conn.state.toLowerCase()}`}>
                                                        {conn.state}
                                                    </span>
                                                </td>
                                                <td className="monospace">{conn.local_addr}</td>
                                                <td className="monospace">{conn.remote_addr}</td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                            {connections.length > 50 && (
                                <div className="table-note">
                                    <AlertCircle size={14} />
                                    Showing 50 of {connections.length} connections
                                </div>
                            )}
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};

export default Traffic;
