import { useState } from 'react'
import API_BASE from '../config/api'
import axios from 'axios' // Added axios import

const URLScanner = () => { // Changed function declaration to arrow function
    const [url, setUrl] = useState('')
    const [result, setResult] = useState(null)
    const [loading, setLoading] = useState(false)

    const handleScan = async (e) => { // Added 'e' parameter
        e.preventDefault() // Added preventDefault
        if (!url.trim()) return
        setLoading(true)
        setResult(null)

        try {
            const token = localStorage.getItem('token') // Get token from localStorage
            const response = await axios.post(`${API_BASE}/agent/analyze`, // Changed to axios.post and new endpoint
                { type: 'url', data: url }, // New body structure
                { headers: { Authorization: `Bearer ${token}` } } // Added Authorization header
            )
            setResult(response.data) // Directly use response.data
        } catch (error) {
            console.error('Scan failed:', error) // New error logging
            alert('Scan failed. Please check your connection.') // New user alert
            setResult({ success: false, attack_type: 'ERROR', confidence: 0, severity: 'UNKNOWN' }) // Keep original error result structure
        } finally { // Added finally block
            setLoading(false)
        }
    }

    const isSafe = result?.agent_verdict?.label?.toLowerCase() === 'safe';

    return (
        <div className="scanner-card">
            <div className="scanner-header">
                <div className="scanner-icon">🔗</div>
                <div>
                    <div className="scanner-title">URL Scanner</div>
                    <div className="scanner-subtitle">Detect phishing & malicious URLs</div>
                </div>
            </div>

            <div className="input-group">
                <label className="input-label">Enter URL to scan</label>
                <input
                    type="text"
                    className="input-field"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleScan()}
                />
            </div>

            <button
                className="btn btn-primary btn-full"
                onClick={handleScan}
                disabled={loading || !url.trim()}
            >
                {loading ? <span className="loading-spinner"></span> : '🔍 Scan URL'}
            </button>

            {result && (
                <div className={`result-container ${isSafe ? 'safe' : 'danger'}`}>
                    <div className="result-header">
                        <span className="result-icon">{isSafe ? '✅' : '⚠️'}</span>
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

export default URLScanner
