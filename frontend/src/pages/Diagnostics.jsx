import React, { useState, useEffect } from 'react';
import { Terminal, Activity, RefreshCw, Play, FileText, Gauge, ArrowDown, ArrowUp, Clock } from 'lucide-react';
import './Diagnostics.css';
import { authFetch, API_BASE_URL } from '../apiConfig';

const Diagnostics = () => {
    const [activeTool, setActiveTool] = useState('ping');
    const [target, setTarget] = useState('');
    const [output, setOutput] = useState('');
    const [running, setRunning] = useState(false);

    // Logs
    const [logs, setLogs] = useState('');
    const [loadingLogs, setLoadingLogs] = useState(false);

    // Speed Test
    const [speedTestRunning, setSpeedTestRunning] = useState(false);
    const [speedTestResult, setSpeedTestResult] = useState(null);
    const [speedTestHistory, setSpeedTestHistory] = useState([]);

    useEffect(() => {
        fetchLogs();
        fetchSpeedTestHistory();
    }, []);

    const fetchLogs = async () => {
        setLoadingLogs(true);
        try {
            const res = await authFetch('/api/system/logs?lines=100');
            if (res.ok) {
                const data = await res.json();
                setLogs(data.output || 'No logs found.');
            }
        } catch (err) {
            setLogs('Failed to fetch logs.');
        } finally {
            setLoadingLogs(false);
        }
    };

    const fetchSpeedTestHistory = async () => {
        try {
            const res = await authFetch(`${API_BASE_URL}/api/diagnostics/speedtest/history`);
            if (res.ok) {
                const data = await res.json();
                setSpeedTestHistory(data || []);
            }
        } catch (err) {
            console.error('Failed to fetch speed test history:', err);
        }
    };

    const runSpeedTest = async () => {
        setSpeedTestRunning(true);
        setSpeedTestResult(null);
        try {
            const res = await authFetch(`${API_BASE_URL}/api/diagnostics/speedtest`, {
                method: 'POST',
            });
            if (res.ok) {
                const data = await res.json();
                setSpeedTestResult(data);
                fetchSpeedTestHistory();
            }
        } catch (err) {
            setSpeedTestResult({ error: 'Failed to run speed test: ' + err.message });
        } finally {
            setSpeedTestRunning(false);
        }
    };

    const runTool = async () => {
        if (!target) return;
        setRunning(true);
        setOutput(`Running ${activeTool} to ${target}...\n`);

        try {
            const res = await authFetch(`/api/tools/${activeTool}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, count: 4 })
            });

            if (res.ok) {
                const data = await res.json();
                setOutput(prev => prev + (data.output || '') + (data.error ? `\nError: ${data.error}` : ''));
            } else {
                setOutput(prev => prev + `\nRequest failed: ${res.statusText}`);
            }
        } catch (err) {
            setOutput(prev => prev + `\nExecution error: ${err.message}`);
        } finally {
            setRunning(false);
        }
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter') runTool();
    };

    const formatSpeed = (mbps) => {
        if (!mbps) return '—';
        return mbps >= 1000 ? `${(mbps / 1000).toFixed(2)} Gbps` : `${mbps.toFixed(1)} Mbps`;
    };

    return (
        <div className="diagnostics-container">
            <div className="page-header">
                <div className="title-area">
                    <Activity size={28} className="text-secondary" />
                    <div>
                        <h2>Diagnostics</h2>
                        <p className="subtitle">Network tools, speed test, and system logs</p>
                    </div>
                </div>
            </div>

            <div className="diag-grid">
                {/* Speed Test */}
                <div className="glass-panel speedtest-panel">
                    <div className="speedtest-header">
                        <h3><Gauge size={18} style={{ display: 'inline', marginRight: '8px' }} />WAN Speed Test</h3>
                        <button
                            className="primary-btn"
                            onClick={runSpeedTest}
                            disabled={speedTestRunning}
                        >
                            {speedTestRunning ? (
                                <><RefreshCw size={16} className="spin" /> Testing...</>
                            ) : (
                                <><Play size={16} /> Run Test</>
                            )}
                        </button>
                    </div>

                    {speedTestRunning && (
                        <div className="speedtest-progress">
                            <div className="progress-bar">
                                <div className="progress-fill"></div>
                            </div>
                            <p>Running speed test — this may take 30-60 seconds...</p>
                        </div>
                    )}

                    {speedTestResult && !speedTestResult.error && (
                        <div className="speedtest-results">
                            <div className="speed-card download">
                                <ArrowDown size={20} />
                                <div className="speed-value">{formatSpeed(speedTestResult.download)}</div>
                                <div className="speed-label">Download</div>
                            </div>
                            <div className="speed-card upload">
                                <ArrowUp size={20} />
                                <div className="speed-value">{formatSpeed(speedTestResult.upload)}</div>
                                <div className="speed-label">Upload</div>
                            </div>
                            <div className="speed-card latency">
                                <Clock size={20} />
                                <div className="speed-value">{speedTestResult.ping?.toFixed(1) || '—'} ms</div>
                                <div className="speed-label">Latency</div>
                            </div>
                        </div>
                    )}

                    {speedTestResult && speedTestResult.error && (
                        <div className="speedtest-error">{speedTestResult.error}</div>
                    )}

                    {speedTestResult && speedTestResult.server && (
                        <div className="speedtest-server">Server: {speedTestResult.server}</div>
                    )}

                    {speedTestHistory.length > 0 && (
                        <div className="speedtest-history">
                            <h4>Recent Results</h4>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>↓ Download</th>
                                        <th>↑ Upload</th>
                                        <th>Latency</th>
                                        <th>Server</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {speedTestHistory.slice().reverse().map((r, i) => (
                                        <tr key={i}>
                                            <td>{new Date(r.timestamp).toLocaleString()}</td>
                                            <td>{formatSpeed(r.download)}</td>
                                            <td>{formatSpeed(r.upload)}</td>
                                            <td>{r.ping?.toFixed(1)} ms</td>
                                            <td>{r.server || '—'}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>

                {/* Network Tools */}
                <div className="glass-panel tools-panel">
                    <div className="tool-tabs">
                        <button
                            className={`tool-tab ${activeTool === 'ping' ? 'active' : ''}`}
                            onClick={() => setActiveTool('ping')}
                        >
                            Ping
                        </button>
                        <button
                            className={`tool-tab ${activeTool === 'traceroute' ? 'active' : ''}`}
                            onClick={() => setActiveTool('traceroute')}
                        >
                            Traceroute
                        </button>
                    </div>

                    <div className="input-group">
                        <div className="input-icon-wrapper" style={{ flex: 1 }}>
                            <Terminal size={18} className="input-icon" />
                            <input
                                type="text"
                                className="form-input"
                                placeholder={activeTool === 'ping' ? "Enter hostname or IP (e.g. 8.8.8.8)" : "Enter target for traceroute"}
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                onKeyDown={handleKeyDown}
                                disabled={running}
                            />
                        </div>
                        <button className="primary-btn" onClick={runTool} disabled={running || !target}>
                            {running ? <RefreshCw size={18} className="spin" /> : <Play size={18} />}
                            Run
                        </button>
                    </div>

                    <div className="console-output">
                        {output || "// Output will appear here..."}
                    </div>
                </div>

                {/* System Logs */}
                <div className="glass-panel logs-panel">
                    <div className="logs-controls">
                        <h3><FileText size={18} style={{ display: 'inline', marginRight: '8px' }} /> System Logs</h3>
                        <button className="icon-btn" onClick={fetchLogs} title="Refresh Logs">
                            <RefreshCw size={18} className={loadingLogs ? "spin" : ""} />
                        </button>
                    </div>
                    <div className="console-output">
                        {logs || "// No logs available"}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Diagnostics;
