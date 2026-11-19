import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import { clearCSRFToken } from './apiConfig';
import Dashboard from './pages/Dashboard';
import Interfaces from './pages/Interfaces';
import Firewall from './pages/Firewall';
import TrafficControl from './pages/TrafficControl';
import TrafficStats from './pages/TrafficStats';
import Diagnostics from './pages/Diagnostics';
import Services from './pages/Services';
import Traffic from './pages/Traffic';
import DeviceTraffic from './pages/DeviceTraffic';
import Security from './pages/Security';
import ParentalControls from './pages/ParentalControls';
import Login from './pages/Login';
import Settings from './pages/Settings';
import RemoteAccess from './pages/RemoteAccess';
import DNSAnalytics from './pages/DNSAnalytics';
import PortForwarding from './pages/PortForwarding';
import GuestAccess from './pages/GuestAccess';
import Routing from './pages/Routing';
import MultiWAN from './pages/MultiWAN';
import DynamicRouting from './pages/DynamicRouting';
import AuditLogs from './pages/AuditLogs';
import Clients from './pages/Clients';
import WakeOnLAN from './pages/WakeOnLAN';
import GeoBlocking from './pages/GeoBlocking';
import Bonding from './pages/Bonding';
import Scheduling from './pages/Scheduling';
import Notifications from './pages/Notifications';
import SetupWizard from './components/SetupWizard';
import './App.css';

// Tier 4: Session timeout configuration (30 minutes of inactivity)
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

function App() {
  // null = still probing the cookie session, true/false afterwards
  const [isAuthenticated, setIsAuthenticated] = useState(null);
  const [lastActivity, setLastActivity] = useState(Date.now());
  const [showWizard, setShowWizard] = useState(false);

  const handleLogin = () => {
    setIsAuthenticated(true);
    setLastActivity(Date.now());
  };

  // Probe the cookie session once on load (plain fetch: a 401 must not trigger a reload loop)
  useEffect(() => {
    fetch('/api/status', { credentials: 'include' })
      .then(r => setIsAuthenticated(r.ok))
      .catch(() => setIsAuthenticated(false));
  }, []);

  const handleLogout = async () => {
    try {
      let csrfToken = null;
      try {
        const csrfRes = await fetch('/api/csrf-token', { credentials: 'include' });
        if (csrfRes.ok) {
          csrfToken = (await csrfRes.json()).token;
        }
      } catch {
        // Ignore CSRF fetch errors during logout
      }

      await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
        },
      }).catch(() => {
        // Ignore errors - logout locally regardless
      });
    } finally {
      localStorage.removeItem('sr_user');
      clearCSRFToken();
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
      fetch('/api/system/needs-setup', { credentials: 'include' })
        .then(r => r.json())
        .then(data => {
          if (data.needs_setup) {
            setShowWizard(true);
          }
        })
        .catch(err => console.error('Failed to check setup status:', err));
    }
  }, [isAuthenticated]);

  if (isAuthenticated === null) {
    return null; // probing session
  }

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
          <Route path="/device-traffic" element={<DeviceTraffic />} />
          <Route path="/stats" element={<TrafficStats />} />
          <Route path="/diagnostics" element={<Diagnostics />} />
          <Route path="/security" element={<Security />} />
          <Route path="/remote-access" element={<RemoteAccess />} />
          <Route path="/services" element={<Services />} />
          <Route path="/dns-analytics" element={<DNSAnalytics />} />
          <Route path="/port-forwarding" element={<PortForwarding />} />
          <Route path="/guest-access" element={<GuestAccess />} />
          <Route path="/routing" element={<Routing />} />
          <Route path="/multi-wan" element={<MultiWAN />} />
          <Route path="/dynamic-routing" element={<DynamicRouting />} />
          <Route path="/audit-logs" element={<AuditLogs />} />
          <Route path="/wake-on-lan" element={<WakeOnLAN />} />
          <Route path="/geoblocking" element={<GeoBlocking />} />
          <Route path="/bonding" element={<Bonding />} />
          <Route path="/scheduling" element={<Scheduling />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/parental-controls" element={<ParentalControls />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </MainLayout>
    </Router>
  );
}

export default App;
