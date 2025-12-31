import React, { useState } from 'react';
import Sidebar from './Sidebar';
import { Menu, Bell, User } from 'lucide-react';
import './MainLayout.css';

const MainLayout = ({ children, onLogout }) => {
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const currentUser = localStorage.getItem('sr_user') || 'Admin';

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
                        <button className="icon-btn">
                            <Bell size={20} />
                            <span className="badge">2</span>
                        </button>
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
