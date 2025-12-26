import React, { useState } from 'react';
import Sidebar from './Sidebar';
import { Menu, Bell, User } from 'lucide-react';
import './MainLayout.css';

const MainLayout = ({ children }) => {
    const [sidebarOpen, setSidebarOpen] = useState(false);

    return (
        <div className="layout-container">
            <Sidebar isOpen={sidebarOpen} toggleSidebar={() => setSidebarOpen(!sidebarOpen)} />

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
                        <div className="user-profile">
                            <div className="avatar">A</div>
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
