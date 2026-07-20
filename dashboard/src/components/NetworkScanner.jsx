import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Network, ScanLine, CheckCircle, AlertTriangle, Loader } from 'lucide-react';
import axios from 'axios';
import API_BASE from '../config/api';
import FeedbackButtons from './FeedbackButtons';
import ScanLimitNotice, { getScanError } from './ScanLimitNotice';

const NetworkScanner = () => {
    const [pcapData, setPcapData] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [scanError, setScanError] = useState(null);

    const handleScan = async (e) => {
        if (e) e.preventDefault();
        setLoading(true);
        setResult(null);
        setScanError(null);
        try {
            const token = localStorage.getItem('token');
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
            setScanError(getScanError(error));
        } finally {
            setLoading(false);
        }
    };

    const isSafe = result?.agent_verdict?.label?.toLowerCase() === 'safe';
    const riskScore = result?.agent_verdict?.score || 0;

    return (
        <div className="scanner-card">
            <div className="scanner-header">
                <div className="scanner-icon">
                    <Network size={18} style={{ color: '#5AA9FF' }} />
                </div>
                <div>
                    <div className="scanner-title">Network IDS</div>
                    <div className="scanner-subtitle">Detect intrusions &amp; anomalies</div>
                </div>
            </div>

            <form onSubmit={handleScan}>
                <div className="input-group" style={{ marginBottom: '12px' }}>
                    <label className="input-label">Network Flow Features (JSON)</label>
                    <textarea
                        className="input-field"
                        placeholder={'{"Destination Port": 80, "Flow Duration": 1000, ...}'}
                        value={pcapData}
                        onChange={(e) => setPcapData(e.target.value)}
                        rows={5}
                        style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                    />
                </div>

                <motion.button
                    type="submit"
                    className="btn-scan"
                    disabled={loading}
                    whileHover={!loading ? { scale: 1.02 } : {}}
                    whileTap={!loading ? { scale: 0.98 } : {}}
                    style={{ background: 'linear-gradient(135deg, #5AA9FF, #3B82F6)' }}
                >
                    {loading ? (
                        <><Loader size={16} style={{ animation: 'spin 0.8s linear infinite' }} /> Analyzing...</>
                    ) : (
                        <><ScanLine size={16} /> Analyze Network Flow</>
                    )}
                </motion.button>
            </form>
            <ScanLimitNotice error={scanError} />

            <AnimatePresence>
                {result && (
                    <motion.div
                        className={`result-container ${isSafe ? 'safe' : 'danger'}`}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.25 }}
                    >
                        <div className="result-header">
                            {isSafe
                                ? <CheckCircle size={20} style={{ color: '#36D399' }} />
                                : <AlertTriangle size={20} style={{ color: '#FF3D57' }} />
                            }
                            <span className={`result-title ${isSafe ? 'safe' : 'danger'}`}>
                                {result.agent_verdict?.label || 'Unknown'}
                            </span>
                        </div>
                        <div className="result-details">
                            <div className="result-row">
                                <span>Risk Score</span>
                                <span style={{ color: riskScore >= 75 ? '#FF3D57' : riskScore >= 50 ? '#FF5A36' : '#36D399', fontWeight: 700 }}>
                                    {riskScore}%
                                </span>
                            </div>
                            <div className="result-row">
                                <span>Classification</span>
                                <span>{result.agent_verdict?.label}</span>
                            </div>
                        </div>
                        <div className="confidence-bar">
                            <motion.div
                                className={`confidence-fill ${isSafe ? 'safe' : 'danger'}`}
                                initial={{ width: 0 }}
                                animate={{ width: `${riskScore}%` }}
                                transition={{ duration: 0.8, ease: 'easeOut' }}
                            />
                        </div>
                        <FeedbackButtons scanId={result.scan_id} />
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default NetworkScanner;
