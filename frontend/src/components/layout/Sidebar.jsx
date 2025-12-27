import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Network, ShieldCheck, Activity, Settings, Menu, X, LogOut, Lock, Server } from 'lucide-react';
import './Sidebar.css';

const Sidebar = ({ isOpen, toggleSidebar, onLogout }) => {
    const navItems = [
        { icon: LayoutDashboard, label: 'Dashboard', path: '/' },
        { icon: Network, label: 'Interfaces', path: '/interfaces' },
        { icon: ShieldCheck, label: 'Firewall', path: '/firewall' },
        { icon: Activity, label: 'Traffic', path: '/traffic' },
        { icon: Lock, label: 'Security', path: '/security' },
        { icon: Globe, label: 'Remote Access', path: '/remote-access' },
        { icon: Server, label: 'Services', path: '/services' },
        { icon: Settings, label: 'Settings', path: '/settings' },
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
                        <NavLink
                            key={item.path}
                            to={item.path}
                            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                        >
                            <item.icon size={20} className="nav-icon" />
                            <span className="nav-label">{item.label}</span>
                        </NavLink>
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
