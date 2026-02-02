import React, { useEffect, useState } from 'react';
import { Route, Plus, RefreshCw, X, Trash2, ArrowRight } from 'lucide-react';
import './Routing.css';
import { API_ENDPOINTS, authFetch } from '../apiConfig';

const Routing = () => {
    const [routes, setRoutes] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);

    const [newRoute, setNewRoute] = useState({
        destination: '',
        gateway: '',
        metric: 0,
        comment: ''
    });

    const fetchRoutes = async () => {
        setLoading(true);
        try {
            const res = await authFetch(API_ENDPOINTS.ROUTES || '/api/routes');
            if (res.ok) {
                const data = await res.json();
                setRoutes(data || []);
            }
        } catch (err) {
            console.error("Failed to fetch routes:", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchRoutes();
    }, []);

    const handleSubmit = async () => {
        try {
            const res = await authFetch(API_ENDPOINTS.ROUTES || '/api/routes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    destination: newRoute.destination,
                    gateway: newRoute.gateway,
                    metric: parseInt(newRoute.metric),
                    comment: newRoute.comment
                })
            });

            if (res.ok) {
                setShowModal(false);
                setNewRoute({ destination: '', gateway: '', metric: 0, comment: '' });
                fetchRoutes();
            } else {
                alert("Failed to add route");
            }
        } catch (err) {
            console.error(err);
        }
    };

    const handleDelete = async (id) => {
        if (!window.confirm("Delete this route?")) return;
        try {
            const res = await authFetch(`${API_ENDPOINTS.ROUTES || '/api/routes'}?id=${id}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                fetchRoutes();
            }
        } catch (err) {
            console.error(err);
        }
    };

    return (
        <div className="routing-container">
            <div className="page-header">
                <div className="title-area">
                    <Route size={28} className="text-secondary" />
                    <div>
                        <h2>Static Routes</h2>
                        <p className="subtitle">Manage custom routing table entries</p>
                    </div>
                </div>
                <div className="actions">
                    <button className="icon-btn" onClick={fetchRoutes}>
                        <RefreshCw size={20} className={loading ? "spin" : ""} />
                    </button>
                    <button className="primary-btn" onClick={() => setShowModal(true)}>
                        <Plus size={18} />
                        Add Route
                    </button>
                </div>
            </div>

            <div className="glass-panel table-container">
                <table className="routing-table">
                    <thead>
                        <tr>
                            <th>Destination</th>
                            <th>Gateway</th>
                            <th>Metric</th>
                            <th>Comment</th>
                            <th style={{ width: '60px' }}></th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading && !routes.length ? (
                            <tr><td colSpan="5" className="text-center p-4">Loading routes...</td></tr>
                        ) : routes.length === 0 ? (
                            <tr><td colSpan="5" className="text-center p-4 text-muted">No static routes defined</td></tr>
                        ) : (
                            routes.map(route => (
                                <tr key={route.id}>
                                    <td className="monospace font-bold">{route.destination}</td>
                                    <td className="monospace">{route.gateway}</td>
                                    <td>{route.metric}</td>
                                    <td className="text-muted">{route.comment || '-'}</td>
                                    <td>
                                        <button className="icon-btn-sm danger" onClick={() => handleDelete(route.id)}>
                                            <Trash2 size={16} />
                                        </button>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>

            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Add Static Route</h3>
                            <button className="close-btn" onClick={() => setShowModal(false)}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="modal-body">
                            <div className="form-group">
                                <label>Destination Network (CIDR)</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="e.g. 10.20.0.0/24"
                                    value={newRoute.destination}
                                    onChange={e => setNewRoute({ ...newRoute, destination: e.target.value })}
                                />
                            </div>
                            <div className="form-group">
                                <label>Gateway IP</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="e.g. 192.168.1.1"
                                    value={newRoute.gateway}
                                    onChange={e => setNewRoute({ ...newRoute, gateway: e.target.value })}
                                />
                            </div>
                            <div className="form-group">
                                <label>Metric</label>
                                <input
                                    type="number"
                                    className="form-input"
                                    value={newRoute.metric}
                                    onChange={e => setNewRoute({ ...newRoute, metric: e.target.value })}
                                />
                            </div>
                            <div className="form-group">
                                <label>Comment</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    placeholder="Optional description"
                                    value={newRoute.comment}
                                    onChange={e => setNewRoute({ ...newRoute, comment: e.target.value })}
                                />
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="cancel-btn" onClick={() => setShowModal(false)}>Cancel</button>
                            <button className="primary-btn" onClick={handleSubmit}>Add Route</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Routing;
