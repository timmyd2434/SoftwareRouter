import React, { useState, useEffect } from 'react';
import { Terminal, Activity, RefreshCw, Play, FileText } from 'lucide-react';
import './Diagnostics.css';
import { authFetch } from '../apiConfig';

const Diagnostics = () => {
    const [activeTool, setActiveTool] = useState('ping');
    const [target, setTarget] = useState('');
    const [output, setOutput] = useState('');
    const [running, setRunning] = useState(false);

    // Logs
    const [logs, setLogs] = useState('');
    const [loadingLogs, setLoadingLogs] = useState(false);

    useEffect(() => {
        fetchLogs();
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

    return (
        <div className="diagnostics-container">
            <div className="page-header">
                <div className="title-area">
                    <Activity size={28} className="text-secondary" />
                    <div>
                        <h2>Diagnostics</h2>
                        <p className="subtitle">Network tools and system logs</p>
                    </div>
                </div>
            </div>

            <div className="diag-grid">
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
