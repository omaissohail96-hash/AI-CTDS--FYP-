import React, { useState } from 'react';
import axios from 'axios';
import API_BASE from '../config/api';

const WebAttackScanner = () => {
    const [logData, setLogData] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleScan = async (e) => {
        if (e) e.preventDefault();
        setLoading(true);
        setResult(null);
        try {
            const token = localStorage.getItem('token');
            const response = await axios.post(`${API_BASE}/agent/analyze`,
                { type: 'web', data: logData },
                { headers: { Authorization: `Bearer ${token}` } }
            );
            setResult(response.data);
        } catch (error) {
            console.error('Scan failed:', error);
            alert('Scan failed. Session expired?');
            setResult({ success: false, attack_type: 'ERROR', confidence: 0, severity: 'UNKNOWN' });
        } finally {
            setLoading(false);
        }
    };

    const isSafe = result?.agent_verdict?.label?.toLowerCase() === 'safe';

    return (
        <div className="scanner-card fadeIn">
            <div className="scanner-header">
                <div className="scanner-icon">🛡️</div>
                <div>
                    <div className="scanner-title">Web Attack Scanner</div>
                    <div className="scanner-subtitle">Analyze HTTP logs for injections & XSS</div>
                </div>
            </div>

            <div className="input-group">
                <label className="input-label">HTTP Log Entry / URL Query</label>
                <textarea
                    className="input-field"
                    placeholder="GET /admin?id=1' OR '1'='1 --"
                    value={logData}
                    onChange={(e) => setLogData(e.target.value)}
                />
            </div>

            <button
                className="btn btn-primary btn-full"
                onClick={handleScan}
                disabled={loading}
            >
                {loading ? <span className="loading-spinner"></span> : '🔍 Scan Web Activity'}
            </button>

            {result && (
                <div className={`result-container ${isSafe ? 'safe' : 'danger'}`}>
                    <div className="result-header">
                        <span className="result-icon">{isSafe ? '✅' : '🚨'}</span>
                        <span className={`result-title ${isSafe ? 'safe' : 'danger'}`}>
                            {result.agent_verdict?.label}
                        </span>
                    </div>
                    <div className="result-details">
                        <div className="result-row">
                            <span>Risk Score</span>
                            <span>{result.agent_verdict?.score}%</span>
                        </div>
                        <div className="result-row">
                            <span>Severity</span>
                            <span>{result.agent_verdict?.label}</span>
                        </div>
                    </div>
                    <div className="confidence-bar">
                        <div
                            className={`confidence-fill ${isSafe ? 'safe' : 'danger'}`}
                            style={{ width: `${result.agent_verdict?.score}%` }}
                        ></div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default WebAttackScanner;
