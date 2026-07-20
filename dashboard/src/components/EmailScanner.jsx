import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Mail, ScanLine, CheckCircle, AlertTriangle, Loader, Paperclip } from 'lucide-react'
import API_BASE from '../config/api'
import axios from 'axios'
import FeedbackButtons from './FeedbackButtons'
import ScanLimitNotice, { getScanError } from './ScanLimitNotice'

const EmailScanner = () => {
    const [subject, setSubject] = useState('')
    const [body, setBody] = useState('')
    const [result, setResult] = useState(null)
    const [loading, setLoading] = useState(false)
    const [scanError, setScanError] = useState(null)

    const handleScan = async (e) => {
        e.preventDefault()
        if (!subject.trim() && !body.trim()) return
        setLoading(true)
        setResult(null)
        setScanError(null)

        try {
            const token = localStorage.getItem('token')
            const response = await axios.post(`${API_BASE}/agent/analyze`,
                { type: 'email', data: { subject, body } },
                { headers: { Authorization: `Bearer ${token}` } }
            )
            setResult(response.data)
        } catch (error) {
            console.error('Scan failed:', error)
            setScanError(getScanError(error))
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
                    <Mail size={18} style={{ color: '#FF8C42' }} />
                </div>
                <div>
                    <div className="scanner-title">Email Scanner</div>
                    <div className="scanner-subtitle">Analyze emails for phishing attempts</div>
                </div>
            </div>

            <form onSubmit={handleScan}>
                <div className="input-group" style={{ marginBottom: '10px' }}>
                    <label className="input-label">Email Subject</label>
                    <input
                        type="text"
                        className="input-field"
                        placeholder="Enter email subject..."
                        value={subject}
                        onChange={(e) => setSubject(e.target.value)}
                    />
                </div>

                <div className="input-group" style={{ marginBottom: '12px' }}>
                    <label className="input-label">Email Body</label>
                    <textarea
                        className="input-field"
                        placeholder="Paste email content here..."
                        value={body}
                        onChange={(e) => setBody(e.target.value)}
                        rows={4}
                    />
                </div>

                <motion.button
                    type="submit"
                    className="btn-scan"
                    disabled={loading || (!subject.trim() && !body.trim())}
                    whileHover={!loading ? { scale: 1.02 } : {}}
                    whileTap={!loading ? { scale: 0.98 } : {}}
                >
                    {loading ? (
                        <><Loader size={16} style={{ animation: 'spin 0.8s linear infinite' }} /> Analyzing...</>
                    ) : (
                        <><ScanLine size={16} /> Analyze Email</>
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
    )
}

export default EmailScanner
