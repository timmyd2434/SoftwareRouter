import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from './Sidebar';
import { API_ENDPOINTS, authFetch } from '../../apiConfig';
import { Menu, Bell, User } from 'lucide-react';
import './MainLayout.css';

const MainLayout = ({ children, onLogout }) => {
    const [recentAlerts, setRecentAlerts] = useState([]);
    const [alertsLoading, setAlertsLoading] = useState(true);
    const [showAlerts, setShowAlerts] = useState(false);
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const currentUser = localStorage.getItem('sr_user') || 'Admin';
    const navigate = useNavigate();

    useEffect(() => {
        const fetchAlerts = async () => {
            try {
                const res = await authFetch(API_ENDPOINTS.SECURITY_ALERTS);
                if (res.ok) {
                    const data = await res.json();
                    // Sort by timestamp descending (newest first)
                    const sorted = (data || []).reverse();
                    setRecentAlerts(sorted);
                }
            } catch (err) {
                console.error("Failed to fetch alerts", err);
            } finally {
                setAlertsLoading(false);
            }
        };

        fetchAlerts();
        // Poll every 30 seconds
        const interval = setInterval(fetchAlerts, 30000);
        return () => clearInterval(interval);
    }, []);

    // Count high severity alerts (Severity 1 or 2)
    const highSeverityCount = recentAlerts.filter(a => a.severity <= 2).length;

    return (
        <div className="layout-container">
            <Sidebar
                isOpen={sidebarOpen}
                toggleSidebar={() => setSidebarOpen(!sidebarOpen)}
                onLogout={onLogout}
            />

            <main className="main-wrapper">
                <header className="top-header">
                    <button className="menu-btn" onClick={() => setSidebarOpen(true)}>
                        <Menu size={24} />
                    </button>

                    <div className="header-title">
                        {/* Dynamic title could go here */}
                        <h1>Overview</h1>
                    </div>

                    <div className="header-actions">
                        <div
                            className="alerts-wrapper"
                            onMouseEnter={() => setShowAlerts(true)}
                            onMouseLeave={() => setShowAlerts(false)}
                        >
                            <button className="icon-btn" onClick={() => navigate('/security')}>
                                <Bell size={20} />
                                {highSeverityCount > 0 && <span className="badge">{highSeverityCount}</span>}
                            </button>

                            {/* Alerts Tooltip / Comment Bubble */}
                            {showAlerts && (
                                <div className="alerts-dropdown">
                                    <div className="dropdown-header">
                                        <strong>Recent Security Alerts</strong>
                                    </div>
                                    <div className="dropdown-content">
                                        {alertsLoading ? (
                                            <div className="dropdown-item">Loading...</div>
                                        ) : recentAlerts.length === 0 ? (
                                            <div className="dropdown-item">No recent alerts ✅</div>
                                        ) : (
                                            recentAlerts.slice(0, 5).map((alert, idx) => (
                                                <div key={idx} className="dropdown-item alert-preview">
                                                    <span className={`severity-dot sev-${alert.severity}`}></span>
                                                    <div className="alert-text">
                                                        <span className="alert-sig">{alert.signature}</span>
                                                        <span className="alert-time">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                                                    </div>
                                                </div>
                                            ))
                                        )}
                                    </div>
                                    <div className="dropdown-footer">
                                        <span>Click bell to view all details</span>
                                    </div>
                                </div>
                            )}
                        </div>

                        <div className="user-profile" onClick={onLogout} title="Click to Logout">
                            <div className="user-info">
                                <span className="username">Administrator - {currentUser}</span>
                            </div>
                            <div className="avatar">{currentUser.charAt(0).toUpperCase()}</div>
                        </div>
                    </div>
                </header>

                <div className="content-area">
                    {children}
                </div>
            </main>
        </div>
    );
};

export default MainLayout;
