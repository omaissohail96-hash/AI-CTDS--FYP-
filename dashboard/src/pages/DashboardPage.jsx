import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import {
    BarChart,
    Bar,
    CartesianGrid,
    Cell,
    PieChart,
    Pie,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis
} from 'recharts';
import { Activity, AlertTriangle, Brain, Download, ShieldAlert, Siren, Zap } from 'lucide-react';

import API_BASE from '../config/api';
import { URLScanner, EmailScanner, NetworkScanner, WebAttackScanner, CriticalAlertsWidget, AlertTimeline } from '../components';

const severityPalette = {
    SAFE: '#10b981',
    SUSPICIOUS: '#f59e0b',
    HIGH: '#f97316',
    CRITICAL: '#ef4444'
};

const DashboardPage = () => {
    const [summary, setSummary] = useState(null);
    const [distribution, setDistribution] = useState(null);
    const [recentScans, setRecentScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedScan, setSelectedScan] = useState(null);
    const [timeRange, setTimeRange] = useState(0); // 0 = All Time, 24 = 24h, 168 = 7d, 720 = 30d

    useEffect(() => {
        let active = true;

        const fetchAnalytics = async () => {
            try {
                const token = localStorage.getItem('token');
                const headers = { Authorization: `Bearer ${token}` };
                const [summaryResponse, recentResponse, distributionResponse] = await Promise.all([
                    axios.get(`${API_BASE}/stats/threat-summary?hours=${timeRange}`, { headers }),
                    axios.get(`${API_BASE}/stats/recent-scans?limit=8`, { headers }),
                    axios.get(`${API_BASE}/stats/threat-distribution?hours=${timeRange}`, { headers })
                ]);

                if (!active) return;

                setSummary(summaryResponse.data);
                setRecentScans(recentResponse.data);
                setDistribution(distributionResponse.data);
            } catch (err) {
                console.error('Failed to fetch dashboard analytics', err);
            } finally {
                if (active) {
                    setLoading(false);
                }
            }
        };

        fetchAnalytics();
        const intervalId = window.setInterval(fetchAnalytics, 15000);

        return () => {
            active = false;
            window.clearInterval(intervalId);
        };
    }, [timeRange]);


    const stats = useMemo(() => {
        if (!summary) {
            return [
                { label: 'Total Scans', value: 0, icon: Activity },
                { label: 'Critical Alerts', value: 0, icon: Siren },
                { label: 'Threat Hits', value: 0, icon: ShieldAlert },
                { label: 'API Requests', value: 0, icon: Zap }
            ];
        }

        return [
            { label: 'Total Scans', value: summary.total_scans, icon: Activity },
            { label: 'Critical Alerts', value: summary.severity_counts.CRITICAL || 0, icon: Siren },
            {
                label: 'Threat Hits',
                value: (summary.severity_counts.HIGH || 0) + (summary.severity_counts.CRITICAL || 0),
                icon: ShieldAlert
            },
            { label: 'API Requests', value: summary.api_usage.requests || 0, icon: Zap }
        ];
    }, [summary]);

    const severityChartData = useMemo(() => {
        if (!summary) return [];
        return Object.entries(summary.severity_counts).map(([name, value]) => ({
            name,
            value
        }));
    }, [summary]);

    const scoreDistribution = distribution?.score_distribution || [];
    const topAttackTypes = summary?.top_attack_types || [];

    const downloadReport = async () => {
        const token = localStorage.getItem('token');
        const response = await axios.get(`${API_BASE}/reports/security-report?hours=${timeRange}`, {
            headers: { Authorization: `Bearer ${token}` },
            responseType: 'blob'
        });
        const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
        const link = document.createElement('a');
        link.href = url;
        link.download = `cyberguard-security-report-${timeRange === 0 ? 'all-time' : `${timeRange}h`}.pdf`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
    };

    return (
        <div className="fadeIn">
            <div className="page-header">
                <div>
                    <h1 className="page-title">Real-Time Threat Monitoring</h1>
                    <p className="page-subtitle">
                        Live analytics across severity, attack types, usage, and recent detections
                        {summary?.fallback_used ? ` using the latest available ${summary.effective_window_hours}h window` : ''}
                    </p>
                </div>
                <div className="header-actions" style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    <select
                        value={timeRange}
                        onChange={(e) => setTimeRange(Number(e.target.value))}
                        className="select-control"
                        style={{
                            background: 'rgba(255, 255, 255, 0.05)',
                            border: '1px solid rgba(255, 255, 255, 0.08)',
                            borderRadius: '8px',
                            color: '#e2e8f0',
                            padding: '8px 12px',
                            fontSize: '14px',
                            cursor: 'pointer',
                            outline: 'none',
                            backdropFilter: 'blur(10px)'
                        }}
                    >
                        <option value={0} style={{ background: '#12121a', color: '#e2e8f0' }}>All Time</option>
                        <option value={24} style={{ background: '#12121a', color: '#e2e8f0' }}>Last 24 Hours</option>
                        <option value={168} style={{ background: '#12121a', color: '#e2e8f0' }}>Last 7 Days</option>
                        <option value={720} style={{ background: '#12121a', color: '#e2e8f0' }}>Last 30 Days</option>
                    </select>
                    <button className="btn btn-primary" onClick={downloadReport}>
                        <Download size={18} /> PDF Report
                    </button>
                </div>
            </div>


            <div className="stats-grid">
                {stats.map(({ label, value, icon: Icon }) => (
                    <div className="stat-card" key={label}>
                        <div className="analytics-stat-head">
                            <span className="analytics-stat-icon"><Icon size={20} /></span>
                            <span className="stat-label">{label}</span>
                        </div>
                        <div className="stat-value">{value}</div>
                    </div>
                ))}
            </div>

            {/* Alert Widgets */}
            <div className="alerts-widget-grid">
                <CriticalAlertsWidget />
                <AlertTimeline limit={8} />
            </div>

            <div className="analytics-grid">
                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title">Threat Score Distribution</div>
                    </div>
                    <div className="chart-shell">
                        <ResponsiveContainer width="100%" height={280}>
                            <BarChart data={scoreDistribution}>
                                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                                <XAxis dataKey="range" stroke="#94a3b8" />
                                <YAxis stroke="#94a3b8" allowDecimals={false} />
                                <Tooltip
                                    contentStyle={{
                                        background: 'rgba(18,18,26,0.95)',
                                        border: '1px solid rgba(255,255,255,0.08)',
                                        borderRadius: '12px'
                                    }}
                                />
                                <Bar dataKey="count" radius={[10, 10, 0, 0]}>
                                    {scoreDistribution.map((entry) => (
                                        <Cell
                                            key={entry.range}
                                            fill={
                                                entry.range === '0-30' ? severityPalette.SAFE :
                                                    entry.range === '31-60' ? severityPalette.SUSPICIOUS :
                                                        entry.range === '61-85' ? severityPalette.HIGH : severityPalette.CRITICAL
                                            }
                                        />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title">Severity Breakdown</div>
                    </div>
                    <div className="chart-shell">
                        <ResponsiveContainer width="100%" height={280}>
                            <PieChart>
                                <Pie data={severityChartData} dataKey="value" nameKey="name" innerRadius={65} outerRadius={105} paddingAngle={4}>
                                    {severityChartData.map((entry) => (
                                        <Cell key={entry.name} fill={severityPalette[entry.name] || '#06b6d4'} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{
                                        background: 'rgba(18,18,26,0.95)',
                                        border: '1px solid rgba(255,255,255,0.08)',
                                        borderRadius: '12px'
                                    }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="severity-legend">
                        {severityChartData.map((entry) => (
                            <div className="severity-pill" key={entry.name}>
                                <span className="severity-dot" style={{ background: severityPalette[entry.name] || '#06b6d4' }}></span>
                                <span>{entry.name}</span>
                                <strong>{entry.value}</strong>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title">Top Detected Attack Types</div>
                    </div>
                    <div className="threat-list">
                        {topAttackTypes.length === 0 ? (
                            <div className="empty-state">No attack data available yet.</div>
                        ) : topAttackTypes.map((item) => (
                            <div className="threat-row" key={item.attack_type}>
                                <div>
                                    <div className="threat-name">{item.attack_type}</div>
                                    <div className="threat-meta">Observed in recent scan activity</div>
                                </div>
                                <span className="badge danger">{item.count}</span>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title"><Brain size={20} /> Threat Explanation Panel</div>
                    </div>
                    {recentScans[0]?.explanation?.explanation ? (
                        <div className="explanation-panel">
                            <p>{recentScans[0].explanation.explanation}</p>
                            <strong>{recentScans[0].explanation.confidence_level} confidence</strong>
                            <span>{recentScans[0].explanation.recommended_action}</span>
                        </div>
                    ) : (
                        <div className="empty-state">Run a scan to generate analyst explanations.</div>
                    )}
                </div>
            </div>

            <div className="card analytics-panel mitre-visualization-panel">
                <div className="card-header">
                    <div className="card-title">MITRE ATT&CK Visualization</div>
                </div>
                <div className="mitre-grid">
                    {recentScans.flatMap((scan) => scan.mitre_mappings || []).slice(0, 8).map((mapping, index) => (
                        <div className="mitre-card" key={`${mapping.technique_id}-${index}`}>
                            <strong>{mapping.technique_id}</strong>
                            <span>{mapping.technique}</span>
                            <small>{mapping.tactic}</small>
                        </div>
                    ))}
                    {recentScans.flatMap((scan) => scan.mitre_mappings || []).length === 0 && (
                        <div className="empty-state">ATT&CK mappings will appear after detections are analyzed.</div>
                    )}
                </div>
            </div>

            <div className="card analytics-panel recent-scans-panel">
                <div className="card-header">
                    <div className="card-title">Recent Scans</div>
                </div>
                <div className="table-shell">
                    <table className="glass-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Vector</th>
                                <th>Entity</th>
                                <th>Attack Type</th>
                                <th>Verdict</th>
                                <th>Risk</th>
                                <th>Signals</th>
                            </tr>
                        </thead>
                        <tbody>
                            {recentScans.length === 0 ? (
                                <tr>
                                    <td colSpan="7" className="empty-table-cell">
                                        {loading ? 'Loading analytics...' : 'No recent scans available.'}
                                    </td>
                                </tr>
                            ) : recentScans.map((scan) => (
                                <tr key={scan.id} onClick={() => setSelectedScan(scan)} className="clickable-row">
                                    <td>{scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Unknown'}</td>
                                    <td>{scan.input_type?.toUpperCase()}</td>
                                    <td>{scan.entity || 'N/A'}</td>
                                    <td>{scan.attack_type || 'UNKNOWN'}</td>
                                    <td>
                                        <span className={`badge ${scan.verdict === 'SAFE' ? 'success' : 'danger'}`}>
                                            {scan.verdict}
                                        </span>
                                    </td>
                                    <td>{scan.risk_score}</td>
                                    <td>
                                        <div className="signal-flags">
                                            {scan.intelligence_hit && <span className="signal-flag">Intel</span>}
                                            {scan.correlation_hit && <span className="signal-flag">Correlation</span>}
                                            {scan.prevention_triggered && <span className="signal-flag">IDS Rule</span>}
                                            {(scan.mitre_mappings || []).length > 0 && <span className="signal-flag">MITRE</span>}
                                            {!scan.intelligence_hit && !scan.correlation_hit && !scan.prevention_triggered && (
                                                <span className="signal-flag muted">Baseline</span>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            <div className="scanner-section">
                <URLScanner />
                <EmailScanner />
                <NetworkScanner />
                <WebAttackScanner />
            </div>

            {selectedScan && (
                <div className="modal-backdrop" onClick={() => setSelectedScan(null)}>
                    <div className="incident-modal" onClick={(event) => event.stopPropagation()}>
                        <div className="card-header">
                            <div className="card-title">Incident Details</div>
                            <button className="btn" onClick={() => setSelectedScan(null)}>Close</button>
                        </div>
                        <div className="investigation-summary">
                            <div><span>Entity</span><strong>{selectedScan.entity || 'N/A'}</strong></div>
                            <div><span>Attack</span><strong>{selectedScan.attack_type || 'UNKNOWN'}</strong></div>
                            <div><span>Risk</span><strong>{selectedScan.risk_score}</strong></div>
                            <div><span>Verdict</span><strong>{selectedScan.verdict}</strong></div>
                        </div>
                        <section className="detail-section">
                            <h3>Threat Explanation</h3>
                            <p>{selectedScan.explanation?.explanation || 'No explanation stored.'}</p>
                            <strong>Recommended action</strong>
                            <p>{selectedScan.explanation?.recommended_action || 'Review manually.'}</p>
                        </section>
                        <section className="detail-section">
                            <h3>MITRE ATT&CK</h3>
                            <div className="mitre-grid">
                                {(selectedScan.mitre_mappings || []).map((mapping) => (
                                    <div className="mitre-card" key={mapping.technique_id}>
                                        <strong>{mapping.technique_id}</strong>
                                        <span>{mapping.technique}</span>
                                        <small>{mapping.tactic}</small>
                                        <p>{mapping.description}</p>
                                    </div>
                                ))}
                            </div>
                        </section>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DashboardPage;
