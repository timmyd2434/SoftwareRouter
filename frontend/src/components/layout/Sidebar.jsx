import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Network, ShieldCheck, Activity, Settings, Menu, X, LogOut, Lock, Server, Globe, ExternalLink, Box, ArrowRight, FileText, Monitor, Route } from 'lucide-react';
import './Sidebar.css';

const Sidebar = ({ isOpen, toggleSidebar, onLogout }) => {
    const navItems = [
        { icon: LayoutDashboard, label: 'Dashboard', path: '/' },
        { icon: Monitor, label: 'Devices', path: '/clients' },
        { icon: Network, label: 'Interfaces', path: '/interfaces' },
        { icon: Route, label: 'Routing', path: '/routing' },
        { icon: ShieldCheck, label: 'Firewall', path: '/firewall' },
        { icon: Activity, label: 'Traffic', path: '/traffic' },
        { icon: Lock, label: 'Security', path: '/security' },
        { icon: FileText, label: 'Audit Logs', path: '/audit-logs' },
        { icon: Globe, label: 'Remote Access', path: '/remote-access' },
        { icon: Server, label: 'Services', path: '/services' },
        { icon: ShieldCheck, label: 'DNS Analytics', path: '/dns-analytics' },
        { icon: ArrowRight, label: 'Port Forwarding', path: '/port-forwarding' },
        { icon: Settings, label: 'Settings', path: '/settings' },
        {
            icon: Box,
            label: 'UniFi Controller',
            path: `https://${window.location.hostname}:8443`,
            external: true
        },
    ];

    return (
        <>
            <aside className={`sidebar ${isOpen ? 'open' : ''}`}>
                <div className="sidebar-header">
                    <div className="logo-area">
                        <div className="logo-icon">SR</div>
                        <span className="logo-text">SoftRouter</span>
                    </div>
                    <button className="mobile-close" onClick={toggleSidebar}>
                        <X size={24} />
                    </button>
                </div>

                <nav className="sidebar-nav">
                    {navItems.map((item) => (
                        item.external ? (
                            <a
                                key={item.label}
                                href={item.path}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="nav-item external"
                            >
                                <item.icon size={20} className="nav-icon" />
                                <span className="nav-label">{item.label}</span>
                                <ExternalLink size={14} className="external-indicator" />
                            </a>
                        ) : (
                            <NavLink
                                key={item.path}
                                to={item.path}
                                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                            >
                                <item.icon size={20} className="nav-icon" />
                                <span className="nav-label">{item.label}</span>
                            </NavLink>
                        )
                    ))}
                </nav>

                <div className="sidebar-footer">
                    <button className="logout-btn" onClick={onLogout}>
                        <LogOut size={20} />
                        <span>Sign Out</span>
                    </button>
                    <div className="status-indicator online">
                        <span className="dot"></span>
                        System Online
                    </div>
                </div>
            </aside>

            {/* Overlay for mobile */}
            {isOpen && <div className="sidebar-overlay" onClick={toggleSidebar}></div>}
        </>
    );
};

export default Sidebar;
