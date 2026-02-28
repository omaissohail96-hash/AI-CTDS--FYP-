import React, { useState, useEffect } from 'react';
import axios from 'axios';
import API_BASE from '../config/api';
import { URLScanner, EmailScanner, NetworkScanner, WebAttackScanner } from '../components';

const DashboardPage = () => {
    const [stats, setStats] = useState({
        totalScans: 0,
        quotaUsed: 0,
        quotaLimit: 100,
        threatsFound: 0
    });

    useEffect(() => {
        const fetchHistory = async () => {
            try {
                const token = localStorage.getItem('token');
                const response = await axios.get(`${API_BASE}/agent/history`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                const history = response.data;
                const threats = history.filter(h => h.risk_score > 50).length;

                setStats({
                    totalScans: history.length,
                    quotaUsed: history.length,
                    quotaLimit: 100, // This could be fetched from a workspace info endpoint
                    threatsFound: threats
                });
            } catch (err) {
                console.error('Failed to fetch usage stats');
            }
        };
        fetchHistory();
    }, []);

    const quotaPercentage = Math.min((stats.quotaUsed / stats.quotaLimit) * 100, 100);

    return (
        <div className="fadeIn">
            <div className="page-header">
                <h1 className="page-title">SaaS Security Dashboard</h1>
                <p className="page-subtitle">Multi-tenant threat detection gateway</p>
            </div>

            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-value">{stats.totalScans}</div>
                    <div className="stat-label">Total Scans</div>
                </div>
                <div className="stat-card">
                    <div className="stat-value">{stats.threatsFound}</div>
                    <div className="stat-label">Threats Mitigated</div>
                    <div className={`badge ${stats.threatsFound > 0 ? 'danger' : 'success'}`} style={{ marginTop: '5px' }}>
                        {stats.threatsFound > 0 ? 'Action Required' : 'Safe Environment'}
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-value">{stats.quotaLimit}</div>
                    <div className="stat-label">Monthly Quota</div>
                </div>
                <div className="stat-card">
                    <div className="stat-label">Usage Integrity</div>
                    <div className="confidence-bar" style={{ height: '12px', marginTop: '10px' }}>
                        <div
                            className="confidence-fill safe"
                            style={{ width: `${quotaPercentage}%`, background: 'var(--gradient-primary)' }}
                        ></div>
                    </div>
                    <div className="stat-label" style={{ fontSize: '0.7rem', textAlign: 'right', marginTop: '5px' }}>
                        {stats.quotaUsed} / {stats.quotaLimit} Scans
                    </div>
                </div>
            </div>

            <div className="scanner-section">
                <URLScanner />
                <EmailScanner />
                <NetworkScanner />
                <WebAttackScanner />
            </div>
        </div>
    );
};

export default DashboardPage;
