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
                    <div className="glass-card full-width" style={{ marginTop: '20px' }}>
                        <h3>🔌 API Integration Guide</h3>
                        <p style={{ color: 'var(--text-secondary)', marginBottom: '20px' }}>
                            Integrate CyberGuard AI directly into your custom applications and automated security workflows.
                        </p>

                        <div className="integration-sections" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '30px' }}>
                            <div className="guide-section">
                                <h4>📧 Email Security (Python)</h4>
                                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
                                    Scan incoming mail for phishing and malicious payloads.
                                </p>
                                <pre className="code-block">
                                    {`import requests

API_URL = "http://localhost:8000/api/v1/agent/analyze"
HEADERS = {"X-API-KEY": "YOUR_API_KEY"}

payload = {
    "type": "email",
    "data": {
        "subject": "Security Alert",
        "body": "Your account has been compromise. Click here: http://evil.com"
    }
}

response = requests.post(API_URL, json=payload, headers=HEADERS)
print(response.json())`}
                                </pre>
                            </div>

                            <div className="guide-section">
                                <h4>🌐 Web Protection (JS/Fetch)</h4>
                                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
                                    Validate user links and form data in real-time.
                                </p>
                                <pre className="code-block">
                                    {`const checkSecurity = async (url) => {
  const response = await fetch('http://localhost:8000/api/v1/agent/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-KEY': 'YOUR_API_KEY'
    },
    body: JSON.stringify({ type: 'url', data: url })
  });
  
  const result = await response.json();
  console.log("Risk Score:", result.agent_verdict.score);
};`}
                                </pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SettingsPage;
