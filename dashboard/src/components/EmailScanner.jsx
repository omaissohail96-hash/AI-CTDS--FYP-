import { useState } from 'react'
import API_BASE from '../config/api'
import axios from 'axios' // Added axios import

const EmailScanner = () => { // Changed function declaration
    const [subject, setSubject] = useState('')
    const [body, setBody] = useState('')
    const [result, setResult] = useState(null)
    const [loading, setLoading] = useState(false)

    const handleScan = async (e) => { // Added 'e' parameter
        e.preventDefault(); // Added preventDefault
        if (!subject.trim() && !body.trim()) return // Kept this check as it's still relevant for the button's disabled state
        setLoading(true)
        setResult(null) // Kept this to clear previous results

        try {
            const token = localStorage.getItem('token'); // Added token retrieval
            const response = await axios.post(`${API_BASE}/agent/analyze`, // Changed to axios.post and new endpoint
                { type: 'email', data: { subject, body } }, // Changed body structure
                { headers: { Authorization: `Bearer ${token}` } } // Added Authorization header
            );
            setResult(response.data); // Updated to use response.data directly from axios
        } catch (error) {
            console.error('Scan failed:', error); // Updated error logging
            alert('Scan failed. Please login again.'); // Added alert
            setResult({ success: false, attack_type: 'ERROR', confidence: 0, severity: 'UNKNOWN' }) // Kept a fallback result
        } finally { // Added finally block
            setLoading(false); // Moved setLoading(false) to finally
        }
    }

    const isSafe = result?.agent_verdict?.label?.toLowerCase() === 'safe';

    return (
        <div className="scanner-card">
            <div className="scanner-header">
                <div className="scanner-icon">📧</div>
                <div>
                    <div className="scanner-title">Email Scanner</div>
                    <div className="scanner-subtitle">Analyze emails for phishing attempts</div>
                </div>
            </div>

            <div className="input-group">
                <label className="input-label">Email Subject</label>
                <input
                    type="text"
                    className="input-field"
                    placeholder="Enter email subject..."
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                />
            </div>

            <div className="input-group">
                <label className="input-label">Email Body</label>
                <textarea
                    className="input-field"
                    placeholder="Paste email content here..."
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                />
            </div>

            <button
                className="btn btn-primary btn-full"
                onClick={handleScan}
                disabled={loading || (!subject.trim() && !body.trim())}
            >
                {loading ? <span className="loading-spinner"></span> : '🔍 Analyze Email'}
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
    )
}

export default EmailScanner
