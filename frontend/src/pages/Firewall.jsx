import React, { useEffect, useState } from 'react';
import { Shield, Plus, RefreshCw, X, Trash2 } from 'lucide-react';
import './Firewall.css';

const Firewall = () => {
    const [rules, setRules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [errorHeader, setErrorHeader] = useState(null);
    const [showModal, setShowModal] = useState(false);

    // State for editing
    const [isEditing, setIsEditing] = useState(false);
    const [editingHandle, setEditingHandle] = useState(null);

    // New Rule Form State
    const [newRule, setNewRule] = useState({
        family: 'inet',
        table: 'filter',
        chain: 'INPUT',
        raw: 'tcp dport 8080 accept',
        comment: ''
    });

    const [families] = useState(['inet', 'ip', 'ip6']);
    const [tables] = useState(['filter', 'nat', 'mangle']);
    const [chains] = useState(['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING']);

    // Derived lists from fetching rules
    const availableTables = React.useMemo(() => {
        const set = new Set(tables);
        rules.forEach(r => set.add(r.table));
        return Array.from(set).sort();
    }, [rules, tables]);

    const availableChains = React.useMemo(() => {
        const set = new Set(chains);
        rules.forEach(r => set.add(r.chain));
        return Array.from(set).sort();
    }, [rules, chains]);

    // Debug Log State
    const [debugLog, setDebugLog] = useState([]);

    const addLog = (msg) => {
        setDebugLog(prev => [...prev, `${new Date().toLocaleTimeString()} - ${msg}`]);
    };

    const openAddModal = () => {
        setIsEditing(false);
        setEditingHandle(null);
        setDebugLog([]); // Clear log

        // Auto-select valid defaults from existing rules
        let defaultFamily = 'inet';
        let defaultTable = 'filter';
        let defaultChain = 'INPUT';

        if (rules.length > 0) {
            // Pick the first rule's context as a valid baseline
            const r = rules[0];
            defaultFamily = r.family;
            defaultTable = r.table;
            defaultChain = r.chain;

            // Try to find an 'INPUT' chain if possible, as that's what users usually want
            const inputRule = rules.find(x => x.chain.includes('INPUT'));
            if (inputRule) {
                defaultFamily = inputRule.family;
                defaultTable = inputRule.table;
                defaultChain = inputRule.chain;
            }
        }

        // Delay log slightly to ensure modal is open or just pre-fill log
        // (State update batching might mean this log is cleared if we setDebugLog([]) right above)
        // actually setDebugLog([]) is functional update safe usually but let's just push initial state
        // setDebugLog([`${new Date().toLocaleTimeString()} - Defaults set to: ${defaultFamily} ${defaultTable} ${defaultChain}`]);

        setNewRule({
            family: defaultFamily,
            table: defaultTable,
            chain: defaultChain,
            raw: 'tcp dport 8080 accept',
            comment: ''
        });
        setShowModal(true);
    };

    const openEditModal = (rule) => {
        setIsEditing(true);
        setEditingHandle(rule.handle); // Store handle to delete later
        setDebugLog([]);

        setNewRule({
            family: rule.family || 'inet',
            table: rule.table,
            chain: rule.chain,
            raw: formatRule(rule.raw), // Convert JSON to readable string for editing
            comment: rule.comment || ''
        });
        setShowModal(true);
    };

    // Helper to make JSON rules readable
    const formatRule = (raw) => {
        try {
            // Check if it looks like JSON
            if (raw && raw.trim().startsWith('[')) {
                const json = JSON.parse(raw);
                // Simple parser for common NFT JSON structures
                return json.map(part => {
                    if (part.match) {
                        const p = part.match.left.payload;
                        const op = part.match.op === "==" ? "" : part.match.op;
                        const val = part.match.right;
                        return `${p.protocol} ${p.field} ${op} ${val}`.replace(/  /g, ' ');
                    }
                    if ('counter' in part) return '';
                    if ('accept' in part) return 'accept';
                    if ('drop' in part) return 'drop';
                    if ('reject' in part) return 'reject';
                    if ('return' in part) return 'return';
                    if ('masquerade' in part) return 'masquerade';
                    if (part.jump) return `jump ${part.jump.target}`;
                    if (part.goto) return `goto ${part.goto.target}`;
                    return JSON.stringify(part);
                }).filter(s => s).join(' ').trim();
            }
            return raw;
        } catch (e) {
            return raw; // Fallback
        }
    };

    const fetchRules = () => {
        setLoading(true);
        fetch('http://localhost:8080/api/firewall')
            .then(res => {
                if (res.headers.get("X-Start-Warning")) {
                    setErrorHeader(res.headers.get("X-Start-Warning"));
                } else {
                    setErrorHeader(null);
                }
                // Handle non-JSON, potentially empty responses (e.g. from pre-flight)
                return res.text().then(text => text ? JSON.parse(text) : []);
            })
            .then(data => {
                // Ensure data is array
                const rulesArray = Array.isArray(data) ? data : [];
                setRules(rulesArray);
                setLoading(false);
            })
            .catch(err => {
                console.error("Fetch error:", err);
                setLoading(false);
                setRules([]); // Fallback
            });
    };

    const handleSubmitRule = async () => {
        addLog("Submit clicked. Validating...");
        addLog(`Target: ${newRule.table} | ${newRule.chain}`);

        // If Editing: Delete the old rule first
        if (isEditing && editingHandle) {
            try {
                addLog(`Deleting old rule handle ${editingHandle}...`);
                const params = new URLSearchParams({
                    family: newRule.family,
                    table: newRule.table,
                    chain: newRule.chain,
                    handle: editingHandle
                });
                await fetch(`http://localhost:8080/api/firewall?${params}`, { method: 'DELETE' });
                addLog("Delete success.");
            } catch (err) {
                console.error("Failed to delete while editing:", err);
                addLog(`Delete failed: ${err.message}`);
                return;
            }
        }

        // Add the new rule
        try {
            addLog("Sending POST request to backend...");
            const res = await fetch('http://localhost:8080/api/firewall', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newRule)
            });

            addLog(`Response status: ${res.status}`);
            if (res.ok) {
                addLog("Success! Refreshing rules...");
                setTimeout(() => {
                    setShowModal(false);
                    fetchRules();
                }, 1000);
            } else {
                const text = await res.text();
                // If we failed to add but deleted old one, that's risky. 
                // In a prod system we'd use 'nft -f' transaction file.
                console.error("Backend error:", text);
                addLog(`Backend Error: ${text}`);
            }
        } catch (err) {
            console.error("Network error:", err);
            addLog(`Network Error: ${err.message}`);
        }
    };

    // Delete Confirmation State
    const [deleteTarget, setDeleteTarget] = useState(null);

    const handleDeleteRule = async (rule) => {
        // Only set target, do not perform action yet
        setDeleteTarget(rule);
    };

    const confirmDelete = async () => {
        if (!deleteTarget) return;

        try {
            const params = new URLSearchParams({
                family: deleteTarget.family || 'inet', // Default if missing from parsing
                table: deleteTarget.table,
                chain: deleteTarget.chain,
                handle: deleteTarget.handle
            });
            const res = await fetch(`http://localhost:8080/api/firewall?${params}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                fetchRules();
            } else {
                alert("Failed to delete rule");
            }
        } catch (err) {
            console.error(err);
        }
        setDeleteTarget(null);
    };

    useEffect(() => {
        fetchRules();
    }, []);

    return (
        <div className="firewall-container">

            {/* Inject Confirmation Modal */}
            {deleteTarget && (
                <div className="modal-overlay">
                    <div className="modal-content" style={{ width: '400px' }}>
                        <div className="modal-header">
                            <h3>Confirm Delete</h3>
                            <button className="close-btn" onClick={() => setDeleteTarget(null)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete this rule?</p>
                            <div className="code-block monospace">
                                {deleteTarget.table} {deleteTarget.chain} handle {deleteTarget.handle}
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setDeleteTarget(null)}>Cancel</button>
                            <button className="primary-btn" style={{ background: 'var(--danger, #ef4444)' }} onClick={confirmDelete}>
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <div className="fw-header">

                <div className="fw-title">
                    <Shield size={28} className="text-secondary" />
                    <div>
                        <h2>NFTables Policies</h2>
                        <p className="subtitle">Manage network filtering tables and chains</p>
                    </div>
                </div>
                <div className="header-actions">
                    <button className="icon-btn" onClick={fetchRules} title="Refresh Rules">
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                    <button className="primary-btn" onClick={openAddModal}>
                        <Plus size={18} />
                        Add Rule
                    </button>
                </div>
            </div>

            {errorHeader && (
                <div className="alert-box warning">
                    <strong>Note:</strong> {errorHeader}
                </div>
            )}

            <div className="firewall-table-container glass-panel">
                <table className="fw-table">
                    <thead>
                        <tr>
                            <th className="col-table">Table</th>
                            <th className="col-chain">Chain</th>
                            <th className="col-handle">Handle</th>
                            <th className="col-rule">Rule Details</th>
                            <th className="col-comment">Comment</th>
                            <th className="col-actions"></th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading && !rules.length ? (
                            <tr>
                                <td colSpan="6" className="empty-state-cell">Loading firewall ruleset...</td>
                            </tr>
                        ) : rules.length === 0 ? (
                            <tr>
                                <td colSpan="6" className="empty-state-cell">No active rules found in NFTables.</td>
                            </tr>
                        ) : (
                            rules.map((rule, idx) => (
                                <tr key={rule.handle || idx}>
                                    <td>{rule.table}</td>
                                    <td><span className="chain-badge">{rule.chain}</span></td>
                                    <td className="monospace muted">{rule.handle}</td>
                                    <td className="monospace code-block" title={rule.raw}>
                                        {formatRule(rule.raw)}
                                    </td>
                                    <td className="text-muted">{rule.comment || '-'}</td>
                                    <td>
                                        <div style={{ display: 'flex', gap: '4px' }}>
                                            <button
                                                className="icon-btn-sm"
                                                title="Edit Rule"
                                                style={{ position: 'relative', zIndex: 30 }}
                                                onClick={() => openEditModal(rule)}
                                            >
                                                {/* Edit Icon (Pencil) */}
                                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path></svg>
                                            </button>
                                            <button
                                                className="icon-btn-sm"
                                                title="Delete Rule"
                                                onClick={() => handleDeleteRule(rule)}
                                            >
                                                <Trash2 size={16} />
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>

            {/* Add/Edit Rule Modal */}
            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>{isEditing ? 'Edit Rule' : 'Add New Rule'}</h3>
                            <button className="close-btn" onClick={() => setShowModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            {/* Debug Box */}
                            <div style={{
                                background: '#111', color: '#4ade80',
                                padding: '8px', fontSize: '12px',
                                fontFamily: 'monospace', borderRadius: '4px',
                                marginBottom: '10px', height: '80px',
                                overflowY: 'auto', border: '1px solid #333'
                            }}>
                                <div>Status Log:</div>
                                {debugLog.length === 0 ? <div style={{ opacity: 0.5 }}>- Waiting -</div> : debugLog.map((l, i) => <div key={i}>{l}</div>)}
                            </div>

                            <div className="form-group">
                                <label>Unsure Family/Table? Use 'inet' 'filter' for standard firewall.</label>
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                                <div className="form-group">
                                    <label>Family</label>
                                    <select
                                        className="form-select"
                                        value={newRule.family}
                                        onChange={e => setNewRule({ ...newRule, family: e.target.value })}
                                    >
                                        {families.map(f => <option key={f} value={f}>{f}</option>)}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Table</label>
                                    <select
                                        className="form-select"
                                        value={newRule.table}
                                        onChange={e => setNewRule({ ...newRule, table: e.target.value })}
                                    >
                                        {availableTables.map(t => <option key={t} value={t}>{t}</option>)}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Chain</label>
                                    <select
                                        className="form-select"
                                        value={newRule.chain}
                                        onChange={e => setNewRule({ ...newRule, chain: e.target.value })}
                                    >
                                        {availableChains.map(c => <option key={c} value={c}>{c}</option>)}
                                    </select>
                                </div>
                            </div>

                            <div className="form-group">
                                <label>Rule Statement</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={newRule.raw}
                                    onChange={e => setNewRule({ ...newRule, raw: e.target.value })}
                                />
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleSubmitRule}>
                                {isEditing ? 'CONFIRM EDIT' : 'CONFIRM ADD'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Firewall;
