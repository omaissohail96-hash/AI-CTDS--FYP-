import React, { useState } from 'react';
import axios from 'axios';
import API_BASE from '../config/api';
import { ShieldAlert, Mail, Lock, Building, User, ArrowRight } from 'lucide-react';

const RegisterPage = ({ onLogin, onToggleForm }) => {
    const [formData, setFormData] = useState({
        email: '',
        password: '',
        full_name: '',
        workspace_name: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const response = await axios.post(`${API_BASE}/register`, formData);
            const token = response.data.access_token;
            localStorage.setItem('token', token);
            onLogin(token);
        } catch (err) {
            setError(err.response?.data?.detail || 'Registration failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-card">
                <div className="logo-symbol">
                    <ShieldAlert size={32} />
                </div>
                <h2>Create Workspace</h2>
                <p>Deploy your private security infrastructure in seconds</p>

                {error && (
                    <div className="warning-alert danger" style={{ background: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.3)', color: '#ef4444' }}>
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit}>
                    <div className="auth-input-group">
                        <label>Administrator Name</label>
                        <div className="auth-input-wrapper">
                            <User className="input-icon" size={18} />
                            <input
                                name="full_name"
                                value={formData.full_name}
                                onChange={handleChange}
                                placeholder="John Doe"
                                required
                            />
                        </div>
                    </div>

                    <div className="auth-input-group">
                        <label>Business Email</label>
                        <div className="auth-input-wrapper">
                            <Mail className="input-icon" size={18} />
                            <input
                                name="email"
                                type="email"
                                value={formData.email}
                                onChange={handleChange}
                                placeholder="john@company.ai"
                                required
                            />
                        </div>
                    </div>

                    <div className="auth-input-group">
                        <label>Workspace Name</label>
                        <div className="auth-input-wrapper">
                            <Building className="input-icon" size={18} />
                            <input
                                name="workspace_name"
                                value={formData.workspace_name}
                                onChange={handleChange}
                                placeholder="Global Threat Watch"
                                required
                            />
                        </div>
                    </div>

                    <div className="auth-input-group">
                        <label>Master Password</label>
                        <div className="auth-input-wrapper">
                            <Lock className="input-icon" size={18} />
                            <input
                                name="password"
                                type="password"
                                value={formData.password}
                                onChange={handleChange}
                                placeholder="••••••••"
                                required
                            />
                        </div>
                    </div>

                    <button type="submit" disabled={loading} className="btn-auth">
                        {loading ? 'Deploying Tenant...' : (
                            <>
                                Create Secure Account <ArrowRight size={18} style={{ marginLeft: '8px' }} />
                            </>
                        )}
                    </button>
                </form>

                <div className="auth-footer">
                    Already have a vault?
                    <a href="#" onClick={(e) => { e.preventDefault(); onToggleForm(); }}>
                        Authenticate Now
                    </a>
                </div>
            </div>
        </div>
    );
};

export default RegisterPage;
