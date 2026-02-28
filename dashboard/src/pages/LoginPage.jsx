import React, { useState } from 'react';
import axios from 'axios';
import API_BASE from '../config/api';
import { Shield, Mail, Lock, ArrowRight } from 'lucide-react';

const LoginPage = ({ onLogin, onToggleForm }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const formData = new FormData();
            formData.append('username', email);
            formData.append('password', password);

            const response = await axios.post(`${API_BASE}/login/access-token`, formData);
            const token = response.data.access_token;
            localStorage.setItem('token', token);
            onLogin(token);
        } catch (err) {
            setError(err.response?.data?.detail || 'Invalid email or password. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-card">
                <div className="logo-symbol">
                    <Shield size={32} />
                </div>
                <h2>Welcome Back</h2>
                <p>Enter your details to access your security vault</p>

                {error && (
                    <div className="warning-alert danger" style={{ background: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.3)', color: '#ef4444' }}>
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit}>
                    <div className="auth-input-group">
                        <label>Email Address</label>
                        <div className="auth-input-wrapper">
                            <Mail className="input-icon" size={18} />
                            <input
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                placeholder="name@company.com"
                                required
                            />
                        </div>
                    </div>

                    <div className="auth-input-group">
                        <label>Secure Password</label>
                        <div className="auth-input-wrapper">
                            <Lock className="input-icon" size={18} />
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="••••••••"
                                required
                            />
                        </div>
                    </div>

                    <button type="submit" disabled={loading} className="btn-auth">
                        {loading ? 'Securing Session...' : (
                            <>
                                Authenticate Dashboard <ArrowRight size={18} style={{ marginLeft: '8px' }} />
                            </>
                        )}
                    </button>
                </form>

                <div className="auth-footer">
                    New to CyberGuard?
                    <a href="#" onClick={(e) => { e.preventDefault(); onToggleForm(); }}>
                        Register Workspace
                    </a>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
