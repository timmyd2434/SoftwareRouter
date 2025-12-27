import React, { useState } from 'react';
import { Shield, Lock, User, AlertCircle, Loader2 } from 'lucide-react';
import { API_ENDPOINTS } from '../apiConfig';
import './Login.css';

const Login = ({ onLogin }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const res = await fetch(`${window.location.protocol}//${window.location.hostname}:8080/api/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (res.ok) {
                const data = await res.json();
                localStorage.setItem('sr_token', data.token);
                localStorage.setItem('sr_user', data.user);
                onLogin(data);
            } else {
                setError('Invalid username or password');
            }
        } catch (err) {
            setError('Failed to connect to the server');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="login-container">
            <div className="login-glass-card">
                <div className="login-header">
                    <div className="logo-badge">
                        <Shield size={32} />
                    </div>
                    <h1>SoftRouter Control</h1>
                    <p>Secure Interface Management</p>
                </div>

                <form onSubmit={handleSubmit} className="login-form">
                    <div className="input-group">
                        <User className="input-icon" size={20} />
                        <input
                            type="text"
                            placeholder="Username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                        />
                    </div>

                    <div className="input-group">
                        <Lock className="input-icon" size={20} />
                        <input
                            type="password"
                            placeholder="Password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
                    </div>

                    {error && (
                        <div className="login-error">
                            <AlertCircle size={16} />
                            <span>{error}</span>
                        </div>
                    )}

                    <button
                        type="submit"
                        className="login-btn"
                        disabled={loading}
                    >
                        {loading ? (
                            <Loader2 size={20} className="spin" />
                        ) : (
                            'Authorize Session'
                        )}
                    </button>

                    <div className="login-footer">
                        <p>Authorized personnel only</p>
                    </div>
                </form>
            </div>

            <div className="login-background">
                <div className="blob blob-1"></div>
                <div className="blob blob-2"></div>
            </div>
        </div>
    );
};

export default Login;
