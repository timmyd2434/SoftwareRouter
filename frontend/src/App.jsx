import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import Dashboard from './pages/Dashboard';
import Interfaces from './pages/Interfaces';
import Firewall from './pages/Firewall';
import TrafficControl from './pages/TrafficControl';
import TrafficStats from './pages/TrafficStats';
import Diagnostics from './pages/Diagnostics';
import Services from './pages/Services';
import Traffic from './pages/Traffic';
import Security from './pages/Security';
import Login from './pages/Login';
import Settings from './pages/Settings';
import RemoteAccess from './pages/RemoteAccess';
import DNSAnalytics from './pages/DNSAnalytics';
import PortForwarding from './pages/PortForwarding';
import Routing from './pages/Routing';
import MultiWAN from './pages/MultiWAN';
import DynamicRouting from './pages/DynamicRouting';
import AuditLogs from './pages/AuditLogs';
import Clients from './pages/Clients';
import SetupWizard from './components/SetupWizard';
import './App.css';

// Tier 4: Session timeout configuration (30 minutes of inactivity)
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('sr_token'));
  const [lastActivity, setLastActivity] = useState(Date.now());
  const [showWizard, setShowWizard] = useState(false);

  const handleLogin = (data) => {
    setIsAuthenticated(true);
    setLastActivity(Date.now());
  };

  const handleLogout = async () => {
    try {
      // Call logout endpoint (Tier 4: Session management)
      const token = localStorage.getItem('sr_token');
      if (token) {
        await fetch('/api/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }).catch(() => {
          // Ignore errors - logout locally regardless
        });
      }
    } finally {
      // Always clear local storage and log out
      localStorage.removeItem('sr_token');
      localStorage.removeItem('sr_user');
      setIsAuthenticated(false);
    }
  };

  // Tier 4: Track user activity and auto-logout after idle timeout
  useEffect(() => {
    if (!isAuthenticated) return;

    const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart'];

    const resetActivity = () => {
      setLastActivity(Date.now());
    };

    // Add event listeners for activity tracking
    activityEvents.forEach(event => {
      document.addEventListener(event, resetActivity);
    });

    // Check for idle timeout every minute
    const timeoutCheck = setInterval(() => {
      const idleTime = Date.now() - lastActivity;
      if (idleTime > SESSION_TIMEOUT_MS) {
        console.log('Session timed out due to inactivity');
        handleLogout();
      }
    }, 60000); // Check every minute

    return () => {
      activityEvents.forEach(event => {
        document.removeEventListener(event, resetActivity);
      });
      clearInterval(timeoutCheck);
    };
  }, [isAuthenticated, lastActivity]);

  // Tier 4: Check if setup wizard is needed (first boot with no WAN configured)
  useEffect(() => {
    if (isAuthenticated) {
      fetch('/api/system/needs-setup')
        .then(r => r.json())
        .then(data => {
          if (data.needs_setup) {
            setShowWizard(true);
          }
        })
        .catch(err => console.error('Failed to check setup status:', err));
    }
  }, [isAuthenticated]);

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <Router>
      <SetupWizard
        show={showWizard}
        onComplete={() => {
          setShowWizard(false);
          // Optionally reload to apply new firewall rules
          window.location.reload();
        }}
      />
      <MainLayout onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/clients" element={<Clients />} />
          <Route path="/interfaces" element={<Interfaces />} />
          <Route path="/firewall" element={<Firewall />} />
          <Route path="/traffic" element={<TrafficControl />} />
          <Route path="/stats" element={<TrafficStats />} />
          <Route path="/diagnostics" element={<Diagnostics />} />
          <Route path="/security" element={<Security />} />
          <Route path="/remote-access" element={<RemoteAccess />} />
          <Route path="/services" element={<Services />} />
          <Route path="/dns-analytics" element={<DNSAnalytics />} />
          <Route path="/port-forwarding" element={<PortForwarding />} />
          <Route path="/routing" element={<Routing />} />
          <Route path="/multi-wan" element={<MultiWAN />} />
          <Route path="/dynamic-routing" element={<DynamicRouting />} />
          <Route path="/audit-logs" element={<AuditLogs />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </MainLayout>
    </Router>
  );
}

export default App;
