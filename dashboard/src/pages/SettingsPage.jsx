import React, { useState, useEffect } from 'react';
import axios from 'axios';
import API_BASE from '../config/api';

const SettingsPage = () => {
    const [apiKey, setApiKey] = useState(null);
    const [keys, setKeys] = useState([]);
    const [label, setLabel] = useState('Production Key');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        fetchKeys();
    }, []);

    const fetchKeys = async () => {
        try {
            const token = localStorage.getItem('token');
            const response = await axios.get(`${API_BASE}/workspace/keys`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setKeys(response.data);
        } catch (err) {
            console.error('Failed to fetch keys');
        }
    };

    const generateKey = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            const response = await axios.post(`${API_BASE}/workspace/keys`, { label }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setApiKey(response.data.api_key);
            fetchKeys();
        } catch (err) {
            alert('Failed to generate key');
        } finally {
            setLoading(false);
        }
    };

    const revokeKey = async (keyId) => {
        if (!window.confirm('Are you sure? This will break any existing integrations using this key.')) return;
        try {
            const token = localStorage.getItem('token');
            await axios.delete(`${API_BASE}/workspace/keys/${keyId}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            fetchKeys();
        } catch (err) {
            alert('Failed to revoke key');
        }
    };

    return (
        <div className="page-container fadeIn">
            <header className="page-header">
                <div>
                    <h1>Settings & Workspace</h1>
                    <p>Manage your API keys and subscription identity</p>
                </div>
            </header>

            <div className="dashboard-grid">
                <div className="glass-card full-width">
                    <h3>API Key Management</h3>
                    <p>Use these keys to access CyberGuard AI from your external automated systems.</p>

                    <div className="api-key-creation">
                        <input
                            type="text"
                            className="glass-input"
                            value={label}
                            onChange={(e) => setLabel(e.target.value)}
                            placeholder="Key Label"
                        />
                        <button className="btn-primary" onClick={generateKey} disabled={loading}>
                            {loading ? 'Generating...' : 'Generate New Key'}
                        </button>
                    </div>

                    {apiKey && (
                        <div className="warning-alert">
                            <strong>New API Key:</strong> <code>{apiKey}</code>
                            <p>Copy this now! It will not be shown again for security reasons.</p>
                            <button className="btn-secondary" onClick={() => setApiKey(null)}>I've saved it</button>
                        </div>
                    )}

                    <div className="key-list">
                        <h4>Active Keys</h4>
                        {keys.length === 0 ? <p>No API keys generated yet.</p> : (
                            <table className="glass-table">
                                <thead>
                                    <tr>
                                        <th>Label</th>
                                        <th>Created</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {keys.map(key => (
                                        <tr key={key.id}>
                                            <td>{key.label}</td>
                                            <td>{new Date(key.created_at).toLocaleDateString()}</td>
                                            <td><span className={`badge ${key.is_active ? 'success' : 'danger'}`}>Active</span></td>
                                            <td>
                                                <button className="btn-small danger" onClick={() => revokeKey(key.id)}>Revoke</button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SettingsPage;
