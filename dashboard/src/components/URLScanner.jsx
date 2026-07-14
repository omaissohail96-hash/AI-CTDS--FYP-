import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Globe, ScanLine, Shield, AlertTriangle, CheckCircle, Loader } from 'lucide-react'
import API_BASE from '../config/api'
import axios from 'axios'

const URLScanner = () => {
    const [url, setUrl] = useState('')
    const [result, setResult] = useState(null)
    const [loading, setLoading] = useState(false)

    const handleScan = async (e) => {
        e.preventDefault()
        if (!url.trim()) return
        setLoading(true)
        setResult(null)

        try {
            const token = localStorage.getItem('token')
            const response = await axios.post(`${API_BASE}/agent/analyze`,
                { type: 'url', data: url },
                { headers: { Authorization: `Bearer ${token}` } }
            )
            setResult(response.data)
        } catch (error) {
            console.error('Scan failed:', error)
            alert('Scan failed. Please check your connection.')
            setResult({ success: false, attack_type: 'ERROR', confidence: 0, severity: 'UNKNOWN' })
        } finally {
            setLoading(false)
        }
    }

    const isSafe = result?.agent_verdict?.label?.toLowerCase() === 'safe'
    const riskScore = result?.agent_verdict?.score || 0

    return (
        <div className="scanner-card">
            <div className="scanner-header">
                <div className="scanner-icon">
                    <Globe size={18} style={{ color: '#FF5A36' }} />
                </div>
                <div>
                    <div className="scanner-title">URL Scanner</div>
                    <div className="scanner-subtitle">Detect phishing &amp; malicious URLs</div>
                </div>
            </div>

            <form onSubmit={handleScan}>
                <div className="input-group" style={{ marginBottom: '12px' }}>
                    <label className="input-label">Enter URL to Scan</label>
                    <input
                        type="text"
                        className="input-field"
                        placeholder="https://example.com"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                    />
                </div>

                <motion.button
                    type="submit"
                    className="btn-scan"
                    disabled={loading || !url.trim()}
                    whileHover={!loading && url.trim() ? { scale: 1.02 } : {}}
                    whileTap={!loading && url.trim() ? { scale: 0.98 } : {}}
                >
                    {loading ? (
                        <><Loader size={16} style={{ animation: 'spin 0.8s linear infinite' }} /> Scanning...</>
                    ) : (
                        <><ScanLine size={16} /> Scan URL</>
                    )}
                </motion.button>
            </form>

            <AnimatePresence>
                {result && (
                    <motion.div
                        className={`result-container ${isSafe ? 'safe' : 'danger'}`}
                        initial={{ opacity: 0, y: 10, scale: 0.97 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
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
                        <div style={{ marginTop: '8px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: '#9CA3AF', marginBottom: '4px' }}>
                                <span>Risk Level</span>
                                <span>{riskScore}%</span>
                            </div>
                            <div className="confidence-bar">
                                <motion.div
                                    className={`confidence-fill ${isSafe ? 'safe' : 'danger'}`}
                                    initial={{ width: 0 }}
                                    animate={{ width: `${riskScore}%` }}
                                    transition={{ duration: 0.8, ease: 'easeOut' }}
                                />
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    )
}

export default URLScanner
