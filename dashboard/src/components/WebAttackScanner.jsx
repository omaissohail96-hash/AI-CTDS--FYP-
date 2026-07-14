import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, ScanLine, CheckCircle, AlertTriangle, Loader } from 'lucide-react';
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
    const riskScore = result?.agent_verdict?.score || 0;

    return (
        <div className="scanner-card">
            <div className="scanner-header">
                <div className="scanner-icon">
                    <ShieldAlert size={18} style={{ color: '#FF3D57' }} />
                </div>
                <div>
                    <div className="scanner-title">Web Attack Scanner</div>
                    <div className="scanner-subtitle">Analyze HTTP logs for injections &amp; XSS</div>
                </div>
            </div>

            <form onSubmit={handleScan}>
                <div className="input-group" style={{ marginBottom: '12px' }}>
                    <label className="input-label">HTTP Log Entry / URL Query</label>
                    <textarea
                        className="input-field"
                        placeholder={"GET /admin?id=1' OR '1'='1 --"}
                        value={logData}
                        onChange={(e) => setLogData(e.target.value)}
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
                    style={{ background: 'linear-gradient(135deg, #FF3D57, #FF5A36)' }}
                >
                    {loading ? (
                        <><Loader size={16} style={{ animation: 'spin 0.8s linear infinite' }} /> Scanning...</>
                    ) : (
                        <><ScanLine size={16} /> Scan Web Activity</>
                    )}
                </motion.button>
            </form>

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
                            {result.attack_type && result.attack_type !== 'ERROR' && (
                                <div className="result-row">
                                    <span>Attack Type</span>
                                    <span className="badge badge-high">{result.attack_type}</span>
                                </div>
                            )}
                        </div>
                        <div className="confidence-bar">
                            <motion.div
                                className={`confidence-fill ${isSafe ? 'safe' : 'danger'}`}
                                initial={{ width: 0 }}
                                animate={{ width: `${riskScore}%` }}
                                transition={{ duration: 0.8, ease: 'easeOut' }}
                            />
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default WebAttackScanner;
