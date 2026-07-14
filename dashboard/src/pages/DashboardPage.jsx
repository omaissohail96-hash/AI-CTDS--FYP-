import React, { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import {
    BarChart, Bar, CartesianGrid, Cell, PieChart, Pie,
    ResponsiveContainer, Tooltip, XAxis, YAxis, AreaChart, Area, RadialBarChart, RadialBar
} from 'recharts';
import {
    Activity, AlertTriangle, Brain, Download, ShieldAlert, Siren, Zap,
    TrendingUp, Shield, Target, Eye, ArrowUpRight, ArrowDownRight,
    RefreshCw, Filter, Clock, ChevronRight
} from 'lucide-react';

import API_BASE from '../config/api';
import { URLScanner, EmailScanner, NetworkScanner, WebAttackScanner, CriticalAlertsWidget, AlertTimeline } from '../components';

const severityPalette = {
    SAFE: '#36D399',
    SUSPICIOUS: '#FFC857',
    HIGH: '#FF5A36',
    CRITICAL: '#FF3D57'
};

// Custom Tooltip
const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
        return (
            <div style={{
                background: 'rgba(22,26,34,0.97)', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '10px', padding: '10px 14px', fontSize: '0.82rem',
                boxShadow: '0 8px 30px rgba(0,0,0,0.5)',
            }}>
                <p style={{ color: '#9CA3AF', marginBottom: '6px', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{label}</p>
                {payload.map((entry, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: entry.color }} />
                        <span style={{ color: '#fff', fontWeight: 600 }}>{entry.value}</span>
                    </div>
                ))}
            </div>
        );
    }
    return null;
};

// Animated count-up hook
const useCountUp = (target) => {
    const [count, setCount] = useState(0);
    useEffect(() => {
        if (!target) { setCount(0); return; }
        let start = 0;
        const duration = 800;
        const step = (target / duration) * 16;
        const timer = setInterval(() => {
            start += step;
            if (start >= target) { setCount(target); clearInterval(timer); }
            else { setCount(Math.floor(start)); }
        }, 16);
        return () => clearInterval(timer);
    }, [target]);
    return count;
};

const StatCard = ({ label, value, icon: Icon, color, colorBg, trend, trendUp, delay = 0 }) => {
    const count = useCountUp(typeof value === 'number' ? value : 0);
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay }}
            whileHover={{ y: -3, boxShadow: '0 12px 40px rgba(0,0,0,0.6), 0 0 20px rgba(255,90,54,0.08)' }}
            className="stat-card"
        >
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '12px' }}>
                <div className="stat-icon-wrap" style={{ background: colorBg || 'rgba(255,90,54,0.1)' }}>
                    <Icon size={18} style={{ color: color || '#FF5A36' }} />
                </div>
                {trend !== undefined && (
                    <div className={`stat-trend ${trendUp ? 'trend-up' : 'trend-down'}`}>
                        {trendUp ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />}
                        {trend}%
                    </div>
                )}
            </div>
            <div className="stat-value">
                {typeof value === 'number' ? count.toLocaleString() : value}
            </div>
            <div className="stat-label">{label}</div>
        </motion.div>
    );
};

const DashboardPage = () => {
    const [summary, setSummary] = useState(null);
    const [distribution, setDistribution] = useState(null);
    const [recentScans, setRecentScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedScan, setSelectedScan] = useState(null);
    const [timeRange, setTimeRange] = useState(0);

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
                if (active) setLoading(false);
            }
        };
        fetchAnalytics();
        const intervalId = window.setInterval(fetchAnalytics, 15000);
        return () => { active = false; window.clearInterval(intervalId); };
    }, [timeRange]);

    const stats = useMemo(() => {
        if (!summary) return [
            { label: 'Total Scans', value: 0, icon: Activity, color: '#5AA9FF', colorBg: 'rgba(90,169,255,0.1)' },
            { label: 'Critical Alerts', value: 0, icon: Siren, color: '#FF3D57', colorBg: 'rgba(255,61,87,0.1)' },
            { label: 'Threat Hits', value: 0, icon: ShieldAlert, color: '#FF5A36', colorBg: 'rgba(255,90,54,0.1)' },
            { label: 'API Requests', value: 0, icon: Zap, color: '#FFC857', colorBg: 'rgba(255,200,87,0.1)' },
        ];
        return [
            { label: 'Total Scans', value: summary.total_scans, icon: Activity, color: '#5AA9FF', colorBg: 'rgba(90,169,255,0.1)', trend: 12, trendUp: true },
            { label: 'Critical Alerts', value: summary.severity_counts.CRITICAL || 0, icon: Siren, color: '#FF3D57', colorBg: 'rgba(255,61,87,0.1)', trend: 3, trendUp: false },
            {
                label: 'Threat Hits',
                value: (summary.severity_counts.HIGH || 0) + (summary.severity_counts.CRITICAL || 0),
                icon: ShieldAlert, color: '#FF5A36', colorBg: 'rgba(255,90,54,0.1)', trend: 8, trendUp: true
            },
            { label: 'API Requests', value: summary.api_usage.requests || 0, icon: Zap, color: '#FFC857', colorBg: 'rgba(255,200,87,0.1)', trend: 21, trendUp: true },
        ];
    }, [summary]);

    const severityChartData = useMemo(() => {
        if (!summary) return [];
        return Object.entries(summary.severity_counts).map(([name, value]) => ({ name, value }));
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

    const maxAttack = topAttackTypes.length > 0 ? Math.max(...topAttackTypes.map(a => a.count)) : 1;

    return (
        <div>
            {/* Page Header */}
            <div className="page-header">
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '6px' }}>
                        <div style={{
                            width: '42px', height: '42px', borderRadius: '12px',
                            background: 'linear-gradient(135deg, rgba(255,106,61,0.18), rgba(255,140,66,0.08))',
                            border: '1px solid rgba(255,106,61,0.25)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                            <Activity size={20} style={{ color: '#FF6A3D' }} />
                        </div>
                        <h1 className="page-title" style={{ marginBottom: 0 }}>Real-Time Threat Monitoring</h1>
                        <span style={{
                            display: 'inline-flex', alignItems: 'center', gap: '5px',
                            padding: '4px 10px', borderRadius: '7px', fontSize: '0.68rem',
                            fontWeight: 800, letterSpacing: '0.08em', textTransform: 'uppercase',
                            background: 'rgba(54,211,153,0.08)', border: '1px solid rgba(54,211,153,0.2)',
                            color: '#36D399',
                        }}>
                            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#36D399', boxShadow: '0 0 6px rgba(54,211,153,0.8)', display: 'inline-block' }} />
                            Live
                        </span>
                    </div>
                    <p className="page-subtitle">
                        Live analytics across severity, attack types, usage, and recent detections
                        {summary?.fallback_used ? ` · Using latest ${summary.effective_window_hours}h window` : ''}
                    </p>
                </div>
                <div className="header-actions">
                    <select
                        value={timeRange}
                        onChange={(e) => setTimeRange(Number(e.target.value))}
                        className="select-control"
                    >
                        <option value={0}>All Time</option>
                        <option value={24}>Last 24 Hours</option>
                        <option value={168}>Last 7 Days</option>
                        <option value={720}>Last 30 Days</option>
                    </select>
                    <motion.button
                        whileHover={{ y: -1 }}
                        whileTap={{ scale: 0.97 }}
                        className="btn btn-primary"
                        onClick={downloadReport}
                    >
                        <Download size={16} /> PDF Report
                    </motion.button>
                </div>
            </div>

            {/* Stat Cards */}
            <div className="stats-grid">
                {stats.map((s, i) => (
                    <StatCard key={s.label} {...s} delay={i * 0.07} />
                ))}
            </div>

            {/* Alert Widgets */}
            <div className="alerts-widget-grid">
                <CriticalAlertsWidget />
                <AlertTimeline limit={8} />
            </div>

            {/* Charts Grid */}
            <div className="analytics-grid">
                {/* Threat Score Distribution */}
                <motion.div
                    className="card analytics-panel"
                    initial={{ opacity: 0, y: 16 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.4, delay: 0.2 }}
                >
                    <div className="card-header">
                        <div className="card-title"><Target size={16} /> Threat Score Distribution</div>
                    </div>
                    <div className="chart-shell">
                        <ResponsiveContainer width="100%" height={260}>
                            <BarChart data={scoreDistribution} barCategoryGap="30%">
                                <defs>
                                    <linearGradient id="barGradientSafe" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#36D399" stopOpacity={0.8}/>
                                        <stop offset="100%" stopColor="#36D399" stopOpacity={0.1}/>
                                    </linearGradient>
                                    <linearGradient id="barGradientSuspicious" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#FFC857" stopOpacity={0.8}/>
                                        <stop offset="100%" stopColor="#FFC857" stopOpacity={0.1}/>
                                    </linearGradient>
                                    <linearGradient id="barGradientHigh" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#FF5A36" stopOpacity={0.8}/>
                                        <stop offset="100%" stopColor="#FF5A36" stopOpacity={0.1}/>
                                    </linearGradient>
                                    <linearGradient id="barGradientCritical" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="0%" stopColor="#FF3D57" stopOpacity={0.8}/>
                                        <stop offset="100%" stopColor="#FF3D57" stopOpacity={0.1}/>
                                    </linearGradient>
                                </defs>
                                <CartesianGrid stroke="rgba(255,255,255,0.03)" vertical={false} />
                                <XAxis dataKey="range" stroke="#4B5563" tick={{ fontSize: 10, fill: '#9CA3AF' }} axisLine={false} tickLine={false} />
                                <YAxis stroke="#4B5563" tick={{ fontSize: 10, fill: '#9CA3AF' }} axisLine={false} tickLine={false} allowDecimals={false} />
                                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.02)' }} />
                                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                                    {scoreDistribution.map((entry) => (
                                        <Cell
                                            key={entry.range}
                                            fill={
                                                entry.range === '0-30' ? 'url(#barGradientSafe)' :
                                                    entry.range === '31-60' ? 'url(#barGradientSuspicious)' :
                                                        entry.range === '61-85' ? 'url(#barGradientHigh)' : 'url(#barGradientCritical)'
                                            }
                                        />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </motion.div>

                {/* Severity Breakdown */}
                <motion.div
                    className="card analytics-panel"
                    initial={{ opacity: 0, y: 16 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.4, delay: 0.28 }}
                >
                    <div className="card-header">
                        <div className="card-title"><Shield size={16} /> Severity Breakdown</div>
                    </div>
                    <div className="chart-shell flex flex-col items-center">
                        <ResponsiveContainer width="100%" height={200}>
                            <PieChart>
                                <defs>
                                    <linearGradient id="pieSafe" x1="0" y1="0" x2="1" y2="1">
                                        <stop offset="0%" stopColor="#36D399" />
                                        <stop offset="100%" stopColor="#10b981" />
                                    </linearGradient>
                                    <linearGradient id="pieSuspicious" x1="0" y1="0" x2="1" y2="1">
                                        <stop offset="0%" stopColor="#FFC857" />
                                        <stop offset="100%" stopColor="#f59e0b" />
                                    </linearGradient>
                                    <linearGradient id="pieHigh" x1="0" y1="0" x2="1" y2="1">
                                        <stop offset="0%" stopColor="#FF5A36" />
                                        <stop offset="100%" stopColor="#FF8C42" />
                                    </linearGradient>
                                    <linearGradient id="pieCritical" x1="0" y1="0" x2="1" y2="1">
                                        <stop offset="0%" stopColor="#FF3D57" />
                                        <stop offset="100%" stopColor="#ef4444" />
                                    </linearGradient>
                                </defs>
                                <Pie
                                    data={severityChartData}
                                    dataKey="value"
                                    nameKey="name"
                                    innerRadius={55}
                                    outerRadius={80}
                                    paddingAngle={5}
                                    strokeWidth={0}
                                >
                                    {severityChartData.map((entry) => (
                                        <Cell 
                                            key={entry.name} 
                                            fill={
                                                entry.name === 'SAFE' ? 'url(#pieSafe)' :
                                                entry.name === 'SUSPICIOUS' ? 'url(#pieSuspicious)' :
                                                entry.name === 'HIGH' ? 'url(#pieHigh)' : 'url(#pieCritical)'
                                            } 
                                        />
                                    ))}
                                </Pie>
                                <Tooltip content={<CustomTooltip />} />
                            </PieChart>
                        </ResponsiveContainer>
                        <div className="severity-legend mt-2">
                            {severityChartData.map((entry) => (
                                <div className="severity-pill" key={entry.name}>
                                    <span className="severity-dot" style={{ 
                                        background: entry.name === 'SAFE' ? '#36D399' :
                                                    entry.name === 'SUSPICIOUS' ? '#FFC857' :
                                                    entry.name === 'HIGH' ? '#FF5A36' : '#FF3D57'
                                    }} />
                                    <span style={{ color: '#9CA3AF' }}>{entry.name}</span>
                                    <strong style={{ color: '#fff', marginLeft: '4px' }}>{entry.value}</strong>
                                </div>
                            ))}
                        </div>
                    </div>
                </motion.div>

                {/* Top Attack Types */}
                <motion.div
                    className="card analytics-panel"
                    initial={{ opacity: 0, y: 16 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.4, delay: 0.36 }}
                >
                    <div className="card-header">
                        <div className="card-title"><AlertTriangle size={16} /> Top Detected Attack Types</div>
                    </div>
                    <div style={{ padding: '8px 20px 16px' }}>
                        {topAttackTypes.length === 0 ? (
                            <div className="empty-state">No attack data available yet.</div>
                        ) : topAttackTypes.slice(0, 6).map((item, i) => (
                            <motion.div
                                key={item.attack_type}
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: i * 0.06 }}
                                style={{ marginBottom: '12px' }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
                                    <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#E5E7EB' }}>{item.attack_type}</span>
                                    <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#FF5A36' }}>{item.count}</span>
                                </div>
                                <div style={{ height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '2px', overflow: 'hidden' }}>
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(item.count / maxAttack) * 100}%` }}
                                        transition={{ duration: 0.8, delay: i * 0.08 }}
                                        style={{
                                            height: '100%',
                                            background: i === 0 ? 'linear-gradient(90deg, #FF3D57, #FF5A36)' :
                                                i === 1 ? 'linear-gradient(90deg, #FF5A36, #FF8C42)' :
                                                    i === 2 ? 'linear-gradient(90deg, #FF8C42, #FFC857)' :
                                                        'linear-gradient(90deg, #FFC857, #36D399)',
                                            borderRadius: '2px',
                                        }}
                                    />
                                </div>
                            </motion.div>
                        ))}
                    </div>
                </motion.div>

                {/* Threat Explanation */}
                <motion.div
                    className="card analytics-panel"
                    initial={{ opacity: 0, y: 16 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.4, delay: 0.44 }}
                >
                    <div className="card-header">
                        <div className="card-title"><Brain size={16} /> Threat Explanation Panel</div>
                    </div>
                    {recentScans[0]?.explanation?.explanation ? (
                        <div className="explanation-panel">
                            <p>{recentScans[0].explanation.explanation}</p>
                            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '4px' }}>
                                <span className="badge badge-critical">{recentScans[0].explanation.confidence_level} confidence</span>
                            </div>
                            <div style={{
                                padding: '10px 12px', background: 'rgba(90,169,255,0.06)',
                                border: '1px solid rgba(90,169,255,0.12)', borderRadius: '8px', marginTop: '8px'
                            }}>
                                <div style={{ fontSize: '0.7rem', color: '#5AA9FF', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>Recommended Action</div>
                                <div style={{ fontSize: '0.83rem', color: '#E5E7EB' }}>{recentScans[0].explanation.recommended_action}</div>
                            </div>
                        </div>
                    ) : (
                        <div className="empty-state">Run a scan to generate analyst explanations.</div>
                    )}
                </motion.div>
            </div>

            {/* MITRE ATT&CK */}
            <motion.div
                className="card analytics-panel mitre-visualization-panel"
                style={{ marginBottom: '24px' }}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.3 }}
            >
                <div className="card-header">
                    <div className="card-title"><Target size={16} /> MITRE ATT&CK Visualization</div>
                    <span style={{
                        fontSize: '0.72rem', fontWeight: 600, color: '#9CA3AF',
                        background: 'rgba(255,255,255,0.05)', padding: '3px 10px', borderRadius: '6px'
                    }}>
                        {recentScans.flatMap((scan) => scan.mitre_mappings || []).length} techniques
                    </span>
                </div>
                <div className="mitre-grid">
                    {recentScans.flatMap((scan) => scan.mitre_mappings || []).slice(0, 8).map((mapping, index) => (
                        <motion.div
                            className="mitre-card"
                            key={`${mapping.technique_id}-${index}`}
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ delay: index * 0.05 }}
                            whileHover={{ y: -3 }}
                        >
                            <strong>{mapping.technique_id}</strong>
                            <span>{mapping.technique}</span>
                            <small>{mapping.tactic}</small>
                        </motion.div>
                    ))}
                    {recentScans.flatMap((scan) => scan.mitre_mappings || []).length === 0 && (
                        <div className="empty-state" style={{ gridColumn: '1/-1' }}>
                            ATT&CK mappings will appear after detections are analyzed.
                        </div>
                    )}
                </div>
            </motion.div>

            {/* Recent Scans Table */}
            <motion.div
                className="card analytics-panel recent-scans-panel"
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.35 }}
            >
                <div className="card-header">
                    <div className="card-title"><Eye size={16} /> Recent Scans</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#36D399', boxShadow: '0 0 6px rgba(54,211,153,0.8)' }} />
                        <span style={{ fontSize: '0.72rem', color: '#36D399', fontWeight: 600 }}>Live</span>
                    </div>
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
                                    <td style={{ color: '#9CA3AF', fontSize: '0.78rem' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <Clock size={12} />
                                            {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Unknown'}
                                        </div>
                                    </td>
                                    <td>
                                        <span style={{
                                            padding: '2px 8px', borderRadius: '5px', fontSize: '0.72rem', fontWeight: 700,
                                            background: 'rgba(90,169,255,0.1)', color: '#5AA9FF',
                                            textTransform: 'uppercase', letterSpacing: '0.04em',
                                        }}>
                                            {scan.input_type?.toUpperCase()}
                                        </span>
                                    </td>
                                    <td style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                        {scan.entity || 'N/A'}
                                    </td>
                                    <td style={{ color: '#E5E7EB' }}>{scan.attack_type || 'UNKNOWN'}</td>
                                    <td>
                                        <span className={`badge ${scan.verdict === 'SAFE' ? 'badge-safe' : scan.verdict === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-critical'}`}>
                                            {scan.verdict}
                                        </span>
                                    </td>
                                    <td>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <div style={{
                                                width: '32px', height: '4px', borderRadius: '2px',
                                                background: 'rgba(255,255,255,0.08)', overflow: 'hidden',
                                            }}>
                                                <div style={{
                                                    width: `${scan.risk_score}%`, height: '100%', borderRadius: '2px',
                                                    background: scan.risk_score >= 75 ? '#FF3D57' : scan.risk_score >= 50 ? '#FF5A36' : '#36D399',
                                                }} />
                                            </div>
                                            <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#E5E7EB' }}>{scan.risk_score}</span>
                                        </div>
                                    </td>
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
            </motion.div>

            {/* Scanners */}
            <div className="scanner-section">
                <URLScanner />
                <EmailScanner />
                <NetworkScanner />
                <WebAttackScanner />
            </div>

            {/* Incident Detail Modal */}
            <AnimatePresence>
                {selectedScan && (
                    <motion.div
                        className="modal-backdrop"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={() => setSelectedScan(null)}
                    >
                        <motion.div
                            className="incident-modal"
                            initial={{ opacity: 0, scale: 0.95, y: 20 }}
                            animate={{ opacity: 1, scale: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.95, y: 20 }}
                            transition={{ duration: 0.25 }}
                            onClick={(e) => e.stopPropagation()}
                        >
                            <div className="card-header">
                                <div className="card-title"><Eye size={16} /> Incident Details</div>
                                <button
                                    className="btn btn-secondary btn-sm"
                                    onClick={() => setSelectedScan(null)}
                                    style={{ padding: '5px 12px' }}
                                >
                                    Close
                                </button>
                            </div>
                            <div className="investigation-summary">
                                <div><span>Entity</span><strong>{selectedScan.entity || 'N/A'}</strong></div>
                                <div><span>Attack</span><strong>{selectedScan.attack_type || 'UNKNOWN'}</strong></div>
                                <div><span>Risk Score</span><strong>{selectedScan.risk_score}</strong></div>
                                <div><span>Verdict</span>
                                    <strong>
                                        <span className={`badge ${selectedScan.verdict === 'SAFE' ? 'badge-safe' : 'badge-critical'}`}>
                                            {selectedScan.verdict}
                                        </span>
                                    </strong>
                                </div>
                            </div>
                            <section className="detail-section">
                                <h3>Threat Explanation</h3>
                                <p>{selectedScan.explanation?.explanation || 'No explanation stored.'}</p>
                                <div style={{ marginTop: '12px' }}>
                                    <div style={{ fontSize: '0.72rem', color: '#FF5A36', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>Recommended Action</div>
                                    <p>{selectedScan.explanation?.recommended_action || 'Review manually.'}</p>
                                </div>
                            </section>
                            <section className="detail-section">
                                <h3>MITRE ATT&CK</h3>
                                <div className="mitre-grid">
                                    {(selectedScan.mitre_mappings || []).map((mapping) => (
                                        <div className="mitre-card" key={mapping.technique_id}>
                                            <strong>{mapping.technique_id}</strong>
                                            <span>{mapping.technique}</span>
                                            <small>{mapping.tactic}</small>
                                            <p style={{ fontSize: '0.75rem', color: '#9CA3AF', marginTop: '4px' }}>{mapping.description}</p>
                                        </div>
                                    ))}
                                </div>
                            </section>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default DashboardPage;
