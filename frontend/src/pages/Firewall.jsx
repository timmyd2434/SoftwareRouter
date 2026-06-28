import React, { useEffect, useState } from 'react';
import { Shield, Plus, RefreshCw, X, Trash2 } from 'lucide-react';
import './Firewall.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

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

    const [_families] = useState(['inet', 'ip', 'ip6']);
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

    // Aliases State
    const [aliases, setAliases] = useState([]);
    const [showAliasModal, setShowAliasModal] = useState(false);
    const [editingAlias, setEditingAlias] = useState(null);
    const [aliasForm, setAliasForm] = useState({
        name: '',
        type: 'ip',
        values: '',
        description: ''
    });

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
                const expressions = JSON.parse(raw);
                const parts = [];

                for (const expr of expressions) {
                    const formatted = formatExpression(expr);
                    if (formatted) parts.push(formatted);
                }

                return parts.join(' ').trim() || raw;
            }
            return raw;
        } catch {
            return raw; // Fallback
        }
    };

    // Helper to format individual NFTables expressions
    const formatExpression = (expr) => {
        // Match expression (e.g., iifname "eth0", tcp dport 22)
        if (expr.match) {
            const { left, op, right } = expr.match;
            const leftStr = formatMatchLeft(left);
            const rightStr = formatMatchRight(right);
            const opStr = op === '==' ? '' : ` ${op}`;
            return `${leftStr}${opStr} ${rightStr}`;
        }

        // Verdict expressions
        if ('accept' in expr) return 'accept';
        if ('drop' in expr) return 'drop';
        if ('reject' in expr) return 'reject';
        if ('return' in expr) return 'return';

        // Jump/Goto
        if (expr.jump) return `jump ${expr.jump.target}`;
        if (expr.goto) return `goto ${expr.goto.target}`;

        // Masquerade
        if ('masquerade' in expr) return 'masquerade';

        // DNAT/SNAT
        if (expr.dnat) {
            const addr = expr.dnat.addr ? formatMatchRight(expr.dnat.addr) : '';
            const port = expr.dnat.port ? `:${expr.dnat.port}` : '';
            return `dnat to ${addr}${port}`;
        }
        if (expr.snat) {
            const addr = expr.snat.addr ? formatMatchRight(expr.snat.addr) : '';
            const port = expr.snat.port ? `:${expr.snat.port}` : '';
            return `snat to ${addr}${port}`;
        }

        // Counter (usually silent in nftables syntax, but we can show it)
        if (expr.counter) {
            return `counter packets ${expr.counter.packets || 0} bytes ${expr.counter.bytes || 0}`;
        }

        // Limit
        if (expr.limit) {
            return `limit rate ${expr.limit.rate}/${expr.limit.per}`;
        }

        // CT (connection tracking)
        if (expr.ct) {
            if (expr.ct.key) return `ct ${expr.ct.key}`;
            if (expr.ct.state) return `ct state ${expr.ct.state}`;
            if (expr.ct.status) return `ct status ${expr.ct.status}`;
        }

        // Log
        if (expr.log) {
            return `log ${expr.log.prefix ? `prefix "${expr.log.prefix}"` : ''}`;
        }

        // If we can't parse it, return nothing (skip)
        return '';
    };

    // Format the left side of a match expression
    const formatMatchLeft = (left) => {
        // Meta expressions (iifname, oifname, etc.)
        if (left.meta) {
            return left.meta.key;
        }

        // Payload expressions (tcp dport, ip saddr, etc.)
        if (left.payload) {
            const { protocol, field } = left.payload;
            return `${protocol} ${field}`;
        }

        // CT state/status
        if (left.ct) {
            if (left.ct.key) return `ct ${left.ct.key}`;
            if (left.ct.state) return `ct state`;
            if (left.ct.status) return `ct status`;
        }

        return JSON.stringify(left);
    };

    // Format the right side of a match expression
    const formatMatchRight = (right) => {
        // Simple values
        if (typeof right === 'string' || typeof right === 'number') {
            return `"${right}"`;
        }

        // Array of values (e.g., ct state established,related)
        if (Array.isArray(right)) {
            return right.join(',');
        }

        // Prefix notation (CIDR)
        if (right.prefix) {
            return `${right.prefix.addr}/${right.prefix.len}`;
        }

        // Range
        if (right.range) {
            return `${right.range[0]}-${right.range[1]}`;
        }

        // Set
        if (right.set) {
            return `{ ${right.set.join(', ')} }`;
        }

        return JSON.stringify(right);
    };


    const fetchRules = () => {
        setLoading(true);
        authFetch(API_ENDPOINTS.FIREWALL)
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
        // Clear previous logs at the start of each attempt
        setDebugLog([]);

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
                await authFetch(`${API_ENDPOINTS.FIREWALL}?${params}`, { method: 'DELETE' });
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
            const res = await authFetch(API_ENDPOINTS.FIREWALL, {
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
                console.error("Backend error:", text);
                addLog(`Backend Error: ${text}`);
                // Don't close modal - let user see error and retry
            }
        } catch (err) {
            console.error("Network error:", err);
            addLog(`Network Error: ${err.message}`);
            // Don't close modal - let user see error and retry
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
            const res = await authFetch(`${API_ENDPOINTS.FIREWALL}?${params}`, {
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

    // Alias Functions
    const fetchAliases = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.FIREWALL_ALIASES);
            const data = await res.json();
            setAliases(Array.isArray(data) ? data : []);
        } catch (err) {
            console.error("Failed to fetch aliases:", err);
            setAliases([]);
        }
    };

    const openAddAliasModal = () => {
        setEditingAlias(null);
        setAliasForm({ name: '', type: 'ip', values: '', description: '' });
        setShowAliasModal(true);
    };

    const openEditAliasModal = (alias) => {
        setEditingAlias(alias);
        setAliasForm({
            name: alias.name,
            type: alias.type,
            values: alias.values.join('\n'),
            description: alias.description || ''
        });
        setShowAliasModal(true);
    };

    const handleSaveAlias = async () => {
        // Validate name
        if (!aliasForm.name || !aliasForm.name.match(/^[A-Z][A-Z0-9_]*$/)) {
            alert("Alias name must start with uppercase letter and contain only uppercase letters, numbers, and underscores");
            return;
        }

        // Parse values
        const values = aliasForm.values.split('\n')
            .map(v => v.trim())
            .filter(v => v !== '');

        if (values.length === 0) {
            alert("Please provide at least one value");
            return;
        }

        const payload = {
            name: aliasForm.name,
            type: aliasForm.type,
            values: values,
            description: aliasForm.description
        };

        try {
            const method = editingAlias ? 'PUT' : 'POST';
            const res = await authFetch(API_ENDPOINTS.FIREWALL_ALIASES, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                setShowAliasModal(false);
                fetchAliases();
                fetchRules(); // Refresh rules as firewall was regenerated
            } else {
                const text = await res.text();
                alert(`Failed to save alias: ${text}`);
            }
        } catch (err) {
            console.error("Error saving alias:", err);
            alert(`Error: ${err.message}`);
        }
    };

    const handleDeleteAlias = async (name) => {
        if (!confirm(`Delete alias "${name}"? This will regenerate the firewall.`)) {
            return;
        }

        try {
            const res = await authFetch(`${API_ENDPOINTS.FIREWALL_ALIASES}?name=${encodeURIComponent(name)}`, {
                method: 'DELETE'
            });

            if (res.ok) {
                fetchAliases();
                fetchRules();
            } else {
                const text = await res.text();
                alert(`Failed to delete alias: ${text}`);
            }
        } catch (err) {
            console.error("Error deleting alias:", err);
            alert(`Error: ${err.message}`);
        }
    };

    useEffect(() => {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        fetchRules();
        fetchAliases();
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

            {/* Aliases Section */}
            <div className="glass-panel" style={{ marginBottom: 'var(--space-6)' }}>
                <div style={{ padding: 'var(--space-6)', borderBottom: '1px solid var(--glass-border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                            <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Firewall Aliases</h3>
                            <p style={{ margin: '4px 0 0 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                Named groups of IPs, networks, or ports (use $ALIAS_NAME in rules)
                            </p>
                        </div>
                        <button className="primary-btn" onClick={openAddAliasModal}>
                            <Plus size={18} />
                            Add Alias
                        </button>
                    </div>
                </div>
                <div style={{ overflowX: 'auto' }}>
                    <table className="fw-table">
                        <thead>
                            <tr>
                                <th style={{ width: '200px' }}>Name</th>
                                <th style={{ width: '100px' }}>Type</th>
                                <th>Values</th>
                                <th style={{ width: '250px' }}>Description</th>
                                <th style={{ width: '100px' }}></th>
                            </tr>
                        </thead>
                        <tbody>
                            {aliases.length === 0 ? (
                                <tr>
                                    <td colSpan="5" className="empty-state-cell">
                                        No aliases defined. Create an alias to group IPs, networks, or ports.
                                    </td>
                                </tr>
                            ) : (
                                aliases.map((alias) => (
                                    <tr key={alias.name}>
                                        <td className="monospace" style={{ color: '#a78bfa', fontWeight: '600' }}>
                                            ${alias.name}
                                        </td>
                                        <td>
                                            <span className="chain-badge">
                                                {alias.type.toUpperCase()}
                                            </span>
                                        </td>
                                        <td className="monospace code-block" style={{ fontSize: '0.85rem' }}>
                                            {alias.values.length} {alias.type === 'port' ? 'port(s)' : alias.type === 'network' ? 'network(s)' : 'address(es)'}
                                        </td>
                                        <td className="text-muted">{alias.description || '-'}</td>
                                        <td>
                                            <div style={{ display: 'flex', gap: '4px', justifyContent: 'center' }}>
                                                <button
                                                    className="icon-btn-sm"
                                                    title="Edit Alias"
                                                    onClick={() => openEditAliasModal(alias)}
                                                >
                                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path></svg>
                                                </button>
                                                <button
                                                    className="icon-btn-sm"
                                                    title="Delete Alias"
                                                    onClick={() => handleDeleteAlias(alias.name)}
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
            </div>

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
                                padding: '12px', fontSize: '13px',
                                fontFamily: 'monospace', borderRadius: '4px',
                                marginBottom: '12px', minHeight: '100px',
                                maxHeight: '150px',
                                overflowY: 'auto', border: '1px solid #333',
                                lineHeight: '1.5',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word'
                            }}>
                                <div style={{ fontWeight: 'bold', marginBottom: '6px' }}>Status Log:</div>
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
                                        <option value="inet">inet (IPv4 + IPv6 - Recommended)</option>
                                        <option value="ip">ip (IPv4 only)</option>
                                        <option value="ip6">ip6 (IPv6 only)</option>
                                    </select>
                                    <small style={{ color: '#888', fontSize: '12px' }}>Use 'inet' for rules that apply to both IP versions</small>
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
                            <div className="form-group">
                                <label>Comment</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="Optional description for this rule"
                                    value={newRule.comment}
                                    onChange={e => setNewRule({ ...newRule, comment: e.target.value })}
                                />
                            </div>

                            {/* IPv6 Examples Section */}
                            <div style={{ marginTop: '16px', padding: '12px', background: '#1a1a2e', borderRadius: '6px', border: '1px solid #333' }}>
                                <strong style={{ color: '#a78bfa', fontSize: '13px' }}>IPv6 Rule Examples:</strong>
                                <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                    <code style={{ fontSize: '11px', padding: '4px 6px', background: '#0d0d1a', borderRadius: '3px', color: '#4ade80' }}>
                                        ip6 saddr 2001:db8::/32 accept
                                    </code>
                                    <code style={{ fontSize: '11px', padding: '4px 6px', background: '#0d0d1a', borderRadius: '3px', color: '#4ade80' }}>
                                        tcp dport 80 accept comment "works with inet family"
                                    </code>
                                    <code style={{ fontSize: '11px', padding: '4px 6px', background: '#0d0d1a', borderRadius: '3px', color: '#4ade80' }}>
                                        ip6 nexthdr icmpv6 accept comment "ICMPv6"
                                    </code>
                                </div>
                                <small style={{ color: '#888', fontSize: '11px', marginTop: '6px', display: 'block' }}>
                                    Note: ICMPv6 is already allowed by default (required for IPv6)
                                </small>
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

            {/* Alias Add/Edit Modal */}
            {showAliasModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>{editingAlias ? 'Edit Alias' : 'Add New Alias'}</h3>
                            <button className="close-btn" onClick={() => setShowAliasModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Alias Name</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="TRUSTED_SERVERS"
                                    value={aliasForm.name}
                                    onChange={e => setAliasForm({ ...aliasForm, name: e.target.value.toUpperCase() })}
                                    disabled={editingAlias !== null}
                                />
                                <small style={{ color: '#888', fontSize: '12px' }}>Uppercase letters, numbers, and underscores only</small>
                            </div>

                            <div className="form-group">
                                <label>Type</label>
                                <select
                                    className="form-select"
                                    value={aliasForm.type}
                                    onChange={e => setAliasForm({ ...aliasForm, type: e.target.value })}
                                >
                                    <option value="ip">IP Address</option>
                                    <option value="network">Network (CIDR)</option>
                                    <option value="port">Port</option>
                                </select>
                            </div>

                            <div className="form-group">
                                <label>Values (one per line)</label>
                                <textarea
                                    className="form-input"
                                    rows="6"
                                    placeholder={aliasForm.type === 'ip' ? '192.168.1.10\n192.168.1.20' : aliasForm.type === 'network' ? '192.168.0.0/24\n10.0.0.0/8' : '80\n443\n8080-8090'}
                                    value={aliasForm.values}
                                    onChange={e => setAliasForm({ ...aliasForm, values: e.target.value })}
                                />
                            </div>

                            <div className="form-group">
                                <label>Description (Optional)</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="Servers allowed admin access"
                                    value={aliasForm.description}
                                    onChange={e => setAliasForm({ ...aliasForm, description: e.target.value })}
                                />
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowAliasModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleSaveAlias}>
                                {editingAlias ? 'SAVE CHANGES' : 'CREATE ALIAS'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Firewall;
