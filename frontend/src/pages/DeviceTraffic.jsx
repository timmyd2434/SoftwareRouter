import React, { useState, useEffect } from 'react';
import { Activity, ArrowDown, ArrowUp, RefreshCw, Monitor, Search } from 'lucide-react';
import { authFetch, API_BASE_URL } from '../apiConfig';
import './DeviceTraffic.css';

const DeviceTraffic = () => {
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [sortBy, setSortBy] = useState('total_today');
    const [sortDesc, setSortDesc] = useState(true);

    useEffect(() => {
        fetchDevices();
        const interval = setInterval(fetchDevices, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchDevices = async () => {
        try {
            const res = await authFetch(`${API_BASE_URL}/api/traffic/devices`);
            if (res.ok) {
                const data = await res.json();
                setDevices(data || []);
            }
        } catch (err) {
            console.error('Failed to fetch device traffic:', err);
        } finally {
            setLoading(false);
        }
    };

    const formatBytes = (bytes) => {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const formatRate = (bytesPerSec) => {
        // Convert to bits per second
        const bps = bytesPerSec * 8;
        if (!bps || bps === 0) return '0 bps';
        const k = 1000;
        const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
        const i = Math.floor(Math.log(bps) / Math.log(k));
        return parseFloat((bps / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    };

    const handleSort = (field) => {
        if (sortBy === field) {
            setSortDesc(!sortDesc);
        } else {
            setSortBy(field);
            setSortDesc(true);
        }
    };

    const filteredAndSorted = [...devices]
        .filter(d => 
            (d.hostname && d.hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
            (d.ip && d.ip.includes(searchTerm)) ||
            (d.mac && d.mac.toLowerCase().includes(searchTerm.toLowerCase()))
        )
        .sort((a, b) => {
            const valA = a[sortBy] || 0;
            const valB = b[sortBy] || 0;
            if (valA < valB) return sortDesc ? 1 : -1;
            if (valA > valB) return sortDesc ? -1 : 1;
            return 0;
        });

    // Calculate totals
    const totalRxRate = devices.reduce((sum, d) => sum + (d.rx_rate || 0), 0);
    const totalTxRate = devices.reduce((sum, d) => sum + (d.tx_rate || 0), 0);
    const totalToday = devices.reduce((sum, d) => sum + (d.total_today || 0), 0);

    return (
        <div className="device-traffic-page">
            <div className="page-header">
                <div className="title-area">
                    <Monitor size={28} className="text-primary" />
                    <div>
                        <h2>Device Bandwidth</h2>
                        <p className="subtitle">Real-time and daily bandwidth usage per device</p>
                    </div>
                </div>
                <div className="header-actions">
                    <button className="primary-btn" onClick={() => { setLoading(true); fetchDevices(); }}>
                        <RefreshCw size={16} className={loading ? "spin" : ""} />
                        Refresh
                    </button>
                </div>
            </div>

            <div className="traffic-summary">
                <div className="summary-card glass-panel">
                    <div className="summary-icon mb"><ArrowDown size={24} /></div>
                    <div className="summary-info">
                        <span className="summary-label">Total Download Rate</span>
                        <span className="summary-value text-success">{formatRate(totalRxRate)}</span>
                    </div>
                </div>
                <div className="summary-card glass-panel">
                    <div className="summary-icon gb"><ArrowUp size={24} /></div>
                    <div className="summary-info">
                        <span className="summary-label">Total Upload Rate</span>
                        <span className="summary-value text-primary">{formatRate(totalTxRate)}</span>
                    </div>
                </div>
                <div className="summary-card glass-panel">
                    <div className="summary-icon tb"><Activity size={24} /></div>
                    <div className="summary-info">
                        <span className="summary-label">Total Volume Today</span>
                        <span className="summary-value">{formatBytes(totalToday)}</span>
                    </div>
                </div>
            </div>

            <div className="glass-panel table-container">
                <div className="table-toolbar">
                    <div className="search-bar">
                        <Search size={16} />
                        <input 
                            type="text" 
                            placeholder="Search by device, IP, or MAC..." 
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    <div className="toolbar-stats">
                        Showing {filteredAndSorted.length} devices
                    </div>
                </div>

                <div className="table-responsive">
                    <table className="traffic-table">
                        <thead>
                            <tr>
                                <th onClick={() => handleSort('hostname')} className="sortable">
                                    Device {sortBy === 'hostname' && (sortDesc ? '▼' : '▲')}
                                </th>
                                <th onClick={() => handleSort('ip')} className="sortable">
                                    IP Address {sortBy === 'ip' && (sortDesc ? '▼' : '▲')}
                                </th>
                                <th onClick={() => handleSort('rx_rate')} className="sortable text-right">
                                    Current Download {sortBy === 'rx_rate' && (sortDesc ? '▼' : '▲')}
                                </th>
                                <th onClick={() => handleSort('tx_rate')} className="sortable text-right">
                                    Current Upload {sortBy === 'tx_rate' && (sortDesc ? '▼' : '▲')}
                                </th>
                                <th onClick={() => handleSort('total_today')} className="sortable text-right">
                                    Total Today {sortBy === 'total_today' && (sortDesc ? '▼' : '▲')}
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {loading && devices.length === 0 ? (
                                <tr>
                                    <td colSpan="5" className="text-center pad-lg">
                                        <RefreshCw size={24} className="spin text-secondary mb-sm" />
                                        <p>Loading traffic data...</p>
                                    </td>
                                </tr>
                            ) : filteredAndSorted.length === 0 ? (
                                <tr>
                                    <td colSpan="5" className="text-center pad-lg">
                                        <p>No device traffic recorded today.</p>
                                    </td>
                                </tr>
                            ) : (
                                filteredAndSorted.map((device) => (
                                    <tr key={device.ip}>
                                        <td>
                                            <div className="device-ident">
                                                <span className="device-name">{device.hostname || 'Unknown Device'}</span>
                                                <span className="device-mac">{device.mac || '—'}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <span className="ip-badge">{device.ip}</span>
                                        </td>
                                        <td className="text-right">
                                            {device.rx_rate > 0 ? (
                                                <span className="rate-active rx"><ArrowDown size={14} /> {formatRate(device.rx_rate)}</span>
                                            ) : (
                                                <span className="rate-idle">0 bps</span>
                                            )}
                                        </td>
                                        <td className="text-right">
                                            {device.tx_rate > 0 ? (
                                                <span className="rate-active tx"><ArrowUp size={14} /> {formatRate(device.tx_rate)}</span>
                                            ) : (
                                                <span className="rate-idle">0 bps</span>
                                            )}
                                        </td>
                                        <td className="text-right">
                                            <span className="total-volume">{formatBytes(device.total_today)}</span>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default DeviceTraffic;
