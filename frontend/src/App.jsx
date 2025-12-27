import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import Dashboard from './pages/Dashboard';
import Interfaces from './pages/Interfaces';
import Firewall from './pages/Firewall';
import Services from './pages/Services';
import Traffic from './pages/Traffic';
import Security from './pages/Security';
import Login from './pages/Login';
import Settings from './pages/Settings';
import './App.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('sr_token'));

  const handleLogin = (data) => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('sr_token');
    localStorage.removeItem('sr_user');
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <Router>
      <MainLayout onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/interfaces" element={<Interfaces />} />
          <Route path="/firewall" element={<Firewall />} />
          <Route path="/traffic" element={<Traffic />} />
          <Route path="/security" element={<Security />} />
          <Route path="/services" element={<Services />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </MainLayout>
    </Router>
  );
}

export default App;
