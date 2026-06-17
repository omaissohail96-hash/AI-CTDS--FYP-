import React, { useState } from 'react';
import axios from 'axios';
import API_BASE from '../config/api';

const NetworkScanner = () => {
    const [pcapData, setPcapData] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleScan = async (e) => {
        if (e) e.preventDefault();
        setLoading(true);
        setResult(null);
        try {
            const token = localStorage.getItem('token');

            // Attempt to parse JSON input
            let payloadData;
            try {
                payloadData = typeof pcapData === 'string' ? JSON.parse(pcapData) : pcapData;
            } catch (e) {
                alert('Invalid JSON format. Please check your input.');
                setLoading(false);
                return;
            }

            const response = await axios.post(`${API_BASE}/agent/analyze`,
                { type: 'network', data: payloadData },
                { headers: { Authorization: `Bearer ${token}` } }
            );
            setResult(response.data);
        } catch (error) {
            console.error('Scan failed:', error);
            if (error.response?.status === 401) {
                alert('Session expired. Please login again.');
            } else {
                alert('Scan failed. Please check the network features format.');
            }
            setResult({ success: false, agent_verdict: { label: 'ERROR', score: 0 } });
        } finally {
            setLoading(false);
        }
    };

    const isSafe = result?.agent_verdict?.label?.toLowerCase() === 'safe';

    return (
        <div className="scanner-card fadeIn">
            <div className="scanner-header">
                <div className="scanner-icon">🌐</div>
                <div>
                    <div className="scanner-title">Network Monitor</div>
                    <div className="scanner-subtitle">Detect intrusions & anomalies</div>
                </div>
            </div>

            <div className="input-group">
                <label className="input-label">Network Flow Features (JSON)</label>
                <textarea
                    className="input-field"
                    placeholder='{"Destination Port": 80, "Flow Duration": 1000, ...}'
                    value={pcapData}
                    onChange={(e) => setPcapData(e.target.value)}
                />
            </div>

            <button
                className="btn btn-primary btn-full"
                onClick={handleScan}
                disabled={loading}
            >
                {loading ? <span className="loading-spinner"></span> : '🔍 Analyze Network Flow'}
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

export default NetworkScanner;
