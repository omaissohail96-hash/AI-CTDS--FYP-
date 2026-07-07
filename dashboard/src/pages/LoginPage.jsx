import React, { useState } from 'react';
import axios from 'axios';
import API_BASE from '../config/api';
import { Shield, Mail, Lock, ArrowRight } from 'lucide-react';

const LoginPage = ({ onLogin, onToggleForm }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    
    // MFA state
    const [requiresMfa, setRequiresMfa] = useState(false);
    const [mfaCode, setMfaCode] = useState('');
    const [mfaToken, setMfaToken] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        if (requiresMfa) {
            try {
                // Verify MFA login
                const response = await axios.post(`${API_BASE}/mfa/verify-login`, 
                    { code: mfaCode },
                    { headers: { Authorization: `Bearer ${mfaToken}` } }
                );
                const token = response.data.access_token;
                localStorage.setItem('token', token);
                onLogin(token);
            } catch (err) {
                setError(err.response?.data?.detail || 'Invalid MFA code. Please try again.');
            } finally {
                setLoading(false);
            }
            return;
        }

        try {
            const formData = new FormData();
            formData.append('username', email);
            formData.append('password', password);

            const response = await axios.post(`${API_BASE}/login/access-token`, formData);
            if (response.data.token_type === 'mfa') {
                setRequiresMfa(true);
                setMfaToken(response.data.access_token);
            } else {
                const token = response.data.access_token;
                localStorage.setItem('token', token);
                onLogin(token);
            }
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
                    {!requiresMfa ? (
                        <>
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
                        </>
                    ) : (
                        <div className="auth-input-group">
                            <label>MFA Code</label>
                            <div className="auth-input-wrapper">
                                <Shield className="input-icon" size={18} />
                                <input
                                    type="text"
                                    value={mfaCode}
                                    onChange={(e) => setMfaCode(e.target.value)}
                                    placeholder="000000"
                                    required
                                    maxLength="8"
                                    style={{ letterSpacing: '2px', textAlign: 'center' }}
                                />
                            </div>
                            <small style={{display: 'block', marginTop: '8px', color: '#6b7280'}}>Enter the 6-digit code from your authenticator app.</small>
                        </div>
                    )}

                    <button type="submit" disabled={loading} className="btn-auth">
                        {loading ? 'Securing Session...' : (
                            <>
                                {requiresMfa ? 'Verify Security Code' : 'Authenticate Dashboard'} <ArrowRight size={18} style={{ marginLeft: '8px' }} />
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
