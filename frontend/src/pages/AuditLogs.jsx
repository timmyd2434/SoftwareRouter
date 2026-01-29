import React, { useState, useEffect } from 'react';
import { authFetch } from '../apiConfig';
import './AuditLogs.css';

const AuditLogs = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Filters
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [actionFilter, setActionFilter] = useState('');
    const [userFilter, setUserFilter] = useState('');
    const [limit, setLimit] = useState(50);

    const fetchLogs = async () => {
        try {
            setLoading(true);
            setError(null);

            const params = new URLSearchParams();
            if (startDate) params.append('start', new Date(startDate).toISOString());
            if (endDate) params.append('end', new Date(endDate).toISOString());
            if (actionFilter) params.append('action', actionFilter);
            if (userFilter) params.append('user', userFilter);
            params.append('limit', limit);

            const response = await authFetch(`/api/audit/logs?${params.toString()}`);
            const data = await response.json();

            setLogs(Array.isArray(data) ? data : []);
        } catch (err) {
            setError('Failed to load audit logs');
            console.error('Error fetching logs:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchLogs();
    }, []);

    const handleSearch = (e) => {
        e.preventDefault();
        fetchLogs();
    };

    const handleReset = () => {
        setStartDate('');
        setEndDate('');
        setActionFilter('');
        setUserFilter('');
        setLimit(50);
        setTimeout(() => fetchLogs(), 100);
    };

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString();
    };

    const getActionBadgeClass = (action) => {
        if (action.startsWith('auth.')) return 'badge-auth';
        if (action.startsWith('firewall.')) return 'badge-firewall';
        if (action.startsWith('session.')) return 'badge-session';
        if (action.startsWith('backup.')) return 'badge-backup';
        return 'badge-default';
    };

    return (
        <div className="audit-logs-container">
            <div className="page-header">
                <h1>Audit Logs</h1>
                <p className="page-description">
                    View and filter all security-sensitive operations
                </p>
            </div>

            {/* Filters */}
            <div className="filters-card">
                <form onSubmit={handleSearch}>
                    <div className="filters-grid">
                        <div className="filter-group">
                            <label>Start Date</label>
                            <input
                                type="datetime-local"
                                value={startDate}
                                onChange={(e) => setStartDate(e.target.value)}
                            />
                        </div>

                        <div className="filter-group">
                            <label>End Date</label>
                            <input
                                type="datetime-local"
                                value={endDate}
                                onChange={(e) => setEndDate(e.target.value)}
                            />
                        </div>

                        <div className="filter-group">
                            <label>Action</label>
                            <input
                                type="text"
                                placeholder="e.g., firewall.add"
                                value={actionFilter}
                                onChange={(e) => setActionFilter(e.target.value)}
                            />
                        </div>

                        <div className="filter-group">
                            <label>User</label>
                            <input
                                type="text"
                                placeholder="e.g., admin"
                                value={userFilter}
                                onChange={(e) => setUserFilter(e.target.value)}
                            />
                        </div>

                        <div className="filter-group">
                            <label>Limit</label>
                            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
                                <option value={25}>25</option>
                                <option value={50}>50</option>
                                <option value={100}>100</option>
                                <option value={250}>250</option>
                            </select>
                        </div>
                    </div>

                    <div className="filter-actions">
                        <button type="button" onClick={handleReset} className="btn-secondary">
                            Reset Filters
                        </button>
                        <button type="submit" className="btn-primary">
                            Apply Filters
                        </button>
                    </div>
                </form>
            </div>

            {/* Logs Table */}
            <div className="logs-card glass-panel">
                {loading && <div className="loading">Loading audit logs...</div>}

                {error && <div className="error-message">{error}</div>}

                {!loading && !error && logs.length === 0 && (
                    <div className="empty-state">
                        No audit logs found. Try adjusting your filters.
                    </div>
                )}

                {!loading && !error && logs.length > 0 && (
                    <>
                        <div className="logs-count">
                            Showing {logs.length} log{logs.length !== 1 ? 's' : ''}
                        </div>

                        <div className="logs-table-container">
                            <table className="logs-table">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>User</th>
                                        <th>Action</th>
                                        <th>Resource</th>
                                        <th>IP Address</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {logs.map((log) => (
                                        <tr key={log.id}>
                                            <td className="timestamp">{formatTimestamp(log.timestamp)}</td>
                                            <td className="user">{log.user}</td>
                                            <td>
                                                <span className={`action-badge ${getActionBadgeClass(log.action)}`}>
                                                    {log.action}
                                                </span>
                                            </td>
                                            <td className="resource">{log.resource}</td>
                                            <td className="ip">{log.ip_address}</td>
                                            <td>
                                                <span className={`status-badge ${log.success ? 'status-success' : 'status-failure'}`}>
                                                    {log.success ? 'Success' : 'Failure'}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
};

export default AuditLogs;
