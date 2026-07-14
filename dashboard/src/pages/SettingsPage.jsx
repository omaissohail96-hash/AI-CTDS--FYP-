import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Key, Clock, ShieldAlert, Cpu, Terminal, RefreshCw, Trash2, Check, Settings } from 'lucide-react';
import API_BASE from '../config/api';
import PageHeader from '../components/PageHeader';

const SettingsPage = () => {
    const [apiKey, setApiKey] = useState(null);
    const [keys, setKeys] = useState([]);
    const [label, setLabel] = useState('Production Key');
    const [loading, setLoading] = useState(false);
    const [copied, setCopied] = useState(false);

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

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="space-y-6">
            <PageHeader
                icon={Settings}
                iconColor="#A78BFA"
                title="Settings & API Keys"
                subtitle="Manage workspace API credentials and integrate with external pipelines"
                badges={[
                    { label: 'JWT Secured', variant: 'purple' },
                    { label: 'REST API', variant: 'info' },
                ]}
            />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                
                {/* Credentials Management Card */}
                <div className="glass-card lg:col-span-6 p-6 space-y-6">
                    <div>
                        <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-1">API Key Management</h3>
                        <p className="text-xs text-gray-400">Credentials created below authorize remote pipelines (CI/CD, Webhooks) to interact with CyberGuard models.</p>
                    </div>

                    <div className="flex gap-3">
                        <input
                            type="text"
                            className="glass-input"
                            value={label}
                            onChange={(e) => setLabel(e.target.value)}
                            placeholder="Key Label (e.g., Staging-Pipeline)"
                        />
                        <button className="btn btn-primary px-6" onClick={generateKey} disabled={loading}>
                            {loading ? <RefreshCw size={15} className="animate-spin" /> : <Key size={15} />}
                            {loading ? 'Generating...' : 'Create Key'}
                        </button>
                    </div>

                    {apiKey && (
                        <div className="p-4 bg-cyber-warning/5 border border-cyber-warning/20 rounded-xl space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-xs font-bold text-cyber-warning tracking-wider uppercase">NEW API CREDENTIAL</span>
                                <button 
                                    onClick={() => copyToClipboard(apiKey)} 
                                    className="text-[10px] text-accent font-bold hover:underline flex items-center gap-1"
                                >
                                    {copied ? <Check size={12} className="text-cyber-success" /> : null}
                                    {copied ? 'Copied' : 'Copy Value'}
                                </button>
                            </div>
                            <code className="block bg-black/40 border border-white/5 p-3 rounded-lg text-xs font-mono text-cyber-success break-all select-all">
                                {apiKey}
                            </code>
                            <p className="text-[10px] text-gray-400 leading-normal">
                                <strong className="text-white">CRITICAL:</strong> Please save this credential. For defense guidelines, we do not persist plain-text hashes, meaning this credential cannot be retrieved again.
                            </p>
                        </div>
                    )}

                    <div className="space-y-3">
                        <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Active Workspace Keys</h4>
                        {keys.length === 0 ? (
                            <div className="text-xs text-gray-500 font-mono italic p-4 bg-black/10 border border-white/5 rounded-xl">No active keys generated yet.</div>
                        ) : (
                            <div className="border border-white/5 rounded-xl overflow-hidden">
                                <table className="glass-table">
                                    <thead>
                                        <tr>
                                            <th>Label</th>
                                            <th>Created</th>
                                            <th>Status</th>
                                            <th className="text-right">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {keys.map(key => (
                                            <tr key={key.id}>
                                                <td className="font-bold text-white">{key.label}</td>
                                                <td className="font-mono text-xs">{new Date(key.created_at).toLocaleDateString()}</td>
                                                <td>
                                                    <span className="badge badge-success">Active</span>
                                                </td>
                                                <td className="text-right">
                                                    <button 
                                                        className="btn-action danger" 
                                                        onClick={() => revokeKey(key.id)}
                                                        title="Revoke Key"
                                                    >
                                                        <Trash2 size={13} />
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>

                {/* Integration Guide Card */}
                <div className="glass-card lg:col-span-6 p-6 space-y-6">
                    <div>
                        <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-1">🔌 API Integration Guide</h3>
                        <p className="text-xs text-gray-400">Trigger detection logic natively via standard HTTP integrations.</p>
                    </div>

                    <div className="space-y-4">
                        <div className="space-y-2">
                            <div className="flex items-center justify-between text-xs">
                                <span className="font-bold text-white font-mono">📧 Phishing Detection (Python)</span>
                                <span className="text-gray-500 font-mono">application/json</span>
                            </div>
                            <pre className="code-block text-[11px] p-4 bg-black/35 rounded-xl border border-white/5 overflow-x-auto">
{`import requests

API_URL = "http://localhost:8000/api/v1/agent/analyze"
HEADERS = {"X-API-KEY": "YOUR_API_KEY"}

payload = {
    "type": "email",
    "data": {
        "subject": "System Upgrade Notification",
        "body": "Urgent security patch. Click http://evil.com"
    }
}

response = requests.post(API_URL, json=payload, headers=HEADERS)
print(response.json())`}
                            </pre>
                        </div>

                        <div className="space-y-2">
                            <div className="flex items-center justify-between text-xs">
                                <span className="font-bold text-white font-mono">🌐 Web Application Shield (JS Fetch)</span>
                                <span className="text-gray-500 font-mono">application/json</span>
                            </div>
                            <pre className="code-block text-[11px] p-4 bg-black/35 rounded-xl border border-white/5 overflow-x-auto">
{`const verifyLogon = async (url) => {
  const res = await fetch('http://localhost:8000/api/v1/agent/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-KEY': 'YOUR_API_KEY'
    },
    body: JSON.stringify({ type: 'url', data: url })
  });
  const data = await res.json();
  console.log("Risk Score:", data.agent_verdict.score);
};`}
                            </pre>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
};

export default SettingsPage;
