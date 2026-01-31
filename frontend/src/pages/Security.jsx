import React, { useEffect, useState } from 'react';
import { Shield, AlertTriangle, Ban, TrendingUp, RefreshCw, AlertCircle, CheckCircle } from 'lucide-react';
import './Security.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const Security = () => {
    const [stats, setStats] = useState(null);
    const [alerts, setAlerts] = useState([]);
    const [decisions, setDecisions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('all'); // all, high, medium, low

    const fetchStats = () => {
        authFetch(API_ENDPOINTS.SECURITY_STATS)
            .then(res => res.json())
            .then(data => setStats(data))
            .catch(err => console.error(err));
    };

    const fetchAlerts = () => {
        authFetch(API_ENDPOINTS.SECURITY_ALERTS)
            .then(res => res.json())
            .then(data => {
                setAlerts(data || []);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    };

    const fetchDecisions = () => {
        authFetch(API_ENDPOINTS.SECURITY_DECISIONS)
            .then(res => res.json())
            .then(data => setDecisions(data || []))
            .catch(err => console.error(err));
    };

    useEffect(() => {
        fetchStats();
        fetchAlerts();
        fetchDecisions();

        // Auto-refresh every 5 seconds
        const interval = setInterval(() => {
            fetchStats();
            fetchAlerts();
            fetchDecisions();
        }, 5000);

        return () => clearInterval(interval);
    }, []);

    const getSeverityClass = (severity) => {
        switch (severity) {
            case 1: return 'high';
            case 2: return 'medium';
            case 3: return 'low';
            default: return 'info';
        }
    };

    const getSeverityLabel = (severity) => {
        switch (severity) {
            case 1: return 'HIGH';
            case 2: return 'MEDIUM';
            case 3: return 'LOW';
            default: return 'INFO';
        }
    };

    const filteredAlerts = alerts.filter(alert => {
        if (filter === 'all') return true;
        if (filter === 'high') return alert.severity === 1;
        if (filter === 'medium') return alert.severity === 2;
        if (filter === 'low') return alert.severity === 3;
        return true;
    });

    return (
        <div className="security-container">
            <div className="section-header">
                <div>
                    <h2>Security Monitor</h2>
                    <span className="subtitle">IDS/IPS Alerts and Threat Intelligence</span>
                </div>
                <div className="header-actions">
                    <button
                        className="icon-btn"
                        onClick={() => { fetchStats(); fetchAlerts(); fetchDecisions(); }}
                        title="Refresh"
                    >
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                </div>
            </div>

            {/* Security Statistics Cards */}
            {stats && (
                <div className="stats-grid">
                    <div className="security-stat-card glass-panel">
                        <div className="stat-icon suricata">
                            <Shield size={28} />
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Suricata Alerts</div>
                            <div className="stat-value">{stats.suricata_stats.total_alerts || 0}</div>
                            <div className="stat-breakdown">
                                <span className="severity high">{stats.suricata_stats.high_severity || 0} High</span>
                                <span className="severity medium">{stats.suricata_stats.medium_severity || 0} Med</span>
                                <span className="severity low">{stats.suricata_stats.low_severity || 0} Low</span>
                            </div>
                        </div>
                    </div>

                    <div className="security-stat-card glass-panel">
                        <div className="stat-icon crowdsec">
                            <Ban size={28} />
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">CrowdSec Blocks</div>
                            <div className="stat-value">{stats.crowdsec_stats.active_decisions || 0}</div>
                            <div className="stat-breakdown">
                                <span>{stats.crowdsec_stats.blocked_ips || 0} Unique IPs</span>
                            </div>
                        </div>
                    </div>

                    <div className="security-stat-card glass-panel">
                        <div className="stat-icon status">
                            <CheckCircle size={28} />
                        </div>
                        <div className="stat-content">
                            <div className="stat-label">Protection Status</div>
                            <div className="stat-value status-text">
                                {stats.suricata_stats.total_alerts > 0 || stats.crowdsec_stats.active_decisions > 0
                                    ? 'ACTIVE'
                                    : 'MONITORING'}
                            </div>
                            <div className="stat-breakdown">
                                <span>Multi-layer Defense</span>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Top Signatures */}
            {stats && stats.suricata_stats.top_signatures && stats.suricata_stats.top_signatures.length > 0 && (
                <div className="top-signatures glass-panel">
                    <h3>Top Alert Signatures</h3>
                    <div className="signature-list">
                        {stats.suricata_stats.top_signatures.map((sig, idx) => (
                            <div key={idx} className="signature-item">
                                <div className="signature-rank">#{idx + 1}</div>
                                <div className="signature-text">{sig}</div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Alert Filter */}
            <div className="section-controls">
                <h3>Recent Suricata Alerts ({filteredAlerts.length})</h3>
                <div className="filter-buttons">
                    <button
                        className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
                        onClick={() => setFilter('all')}
                    >
                        All
                    </button>
                    <button
                        className={`filter-btn high ${filter === 'high' ? 'active' : ''}`}
                        onClick={() => setFilter('high')}
                    >
                        High
                    </button>
                    <button
                        className={`filter-btn medium ${filter === 'medium' ? 'active' : ''}`}
                        onClick={() => setFilter('medium')}
                    >
                        Medium
                    </button>
                    <button
                        className={`filter-btn low ${filter === 'low' ? 'active' : ''}`}
                        onClick={() => setFilter('low')}
                    >
                        Low
                    </button>
                </div>
            </div>

            {/* Alerts Table */}
            <div className="alerts-container glass-panel">
                {loading && alerts.length === 0 ? (
                    <div className="empty-state">
                        <Shield size={48} />
                        <p>Loading security alerts...</p>
                        <span className="hint">Suricata alerts will appear here once IDS/IPS is installed</span>
                    </div>
                ) : filteredAlerts.length === 0 ? (
                    <div className="empty-state">
                        <CheckCircle size={48} className="success-icon" />
                        <p>No alerts detected</p>
                        <span className="hint">Your network is secure</span>
                    </div>
                ) : (
                    <div className="alerts-table-container">
                        <table className="alerts-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Severity</th>
                                    <th>Signature</th>
                                    <th>Source</th>
                                    <th>Destination</th>
                                    <th>Protocol</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredAlerts.slice(0, 50).map((alert, idx) => (
                                    <tr key={idx}>
                                        <td className="monospace time-col">
                                            {new Date(alert.timestamp).toLocaleTimeString()}
                                        </td>
                                        <td>
                                            <span className={`severity-badge ${getSeverityClass(alert.severity)}`}>
                                                {getSeverityLabel(alert.severity)}
                                            </span>
                                        </td>
                                        <td className="signature-col">{alert.signature}</td>
                                        <td className="monospace">{alert.src_ip}:{alert.src_port}</td>
                                        <td className="monospace">{alert.dest_ip}:{alert.dest_port}</td>
                                        <td>
                                            <span className="protocol-badge">{alert.protocol}</span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* CrowdSec Decisions */}
            <div className="decisions-section">
                <h3>CrowdSec Active Blocks ({decisions.length})</h3>
                <div className="decisions-container glass-panel">
                    {decisions.length === 0 ? (
                        <div className="empty-state">
                            <Ban size={48} />
                            <p>No active blocks</p>
                            <span className="hint">CrowdSec blocking decisions will appear here</span>
                        </div>
                    ) : (
                        <div className="decisions-table-container">
                            <table className="decisions-table">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Scenario</th>
                                        <th>Type</th>
                                        <th>Duration</th>
                                        <th>Source</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {decisions.slice(0, 30).map((decision, idx) => (
                                        <tr key={idx}>
                                            <td className="monospace">{decision.value}</td>
                                            <td>{decision.scenario}</td>
                                            <td>
                                                <span className="type-badge">{decision.type}</span>
                                            </td>
                                            <td>{decision.duration}</td>
                                            <td className="source-col">{decision.source}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>

            {/* Installation Notice */}
            {(!stats || stats.suricata_stats.total_alerts === 0) && alerts.length === 0 && (
                <div className="installation-notice">
                    <AlertCircle size={20} />
                    <div>
                        <strong>Security Stack Not Detected</strong>
                        <p>
                            Run <code>sudo ./install-security.sh</code> to install Suricata and CrowdSec.
                            See the installation script in the project root directory.
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Security;
