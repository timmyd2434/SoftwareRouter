import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import Dashboard from './pages/Dashboard';
import Interfaces from './pages/Interfaces';
import Firewall from './pages/Firewall';
import Services from './pages/Services';
import Traffic from './pages/Traffic';
import Security from './pages/Security';
import './App.css';

function App() {
  return (
    <Router>
      <MainLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/interfaces" element={<Interfaces />} />
          <Route path="/firewall" element={<Firewall />} />
          <Route path="/traffic" element={<Traffic />} />
          <Route path="/security" element={<Security />} />
          <Route path="/settings" element={<Services />} />
        </Routes>
      </MainLayout>
    </Router>
  );
}

export default App;
