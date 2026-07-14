import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import {
    Area,
    AreaChart,
    Bar,
    BarChart,
    CartesianGrid,
    Cell,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis
} from 'recharts';
import { Activity, AlertTriangle, BrainCircuit, Clock, Globe2, Users, Eye } from 'lucide-react';

import API_BASE from '../config/api';
import PageHeader from '../components/PageHeader';

const riskColors = {
    NORMAL: '#10b981',
    SUSPICIOUS: '#f59e0b',
    HIGH: '#f97316',
    CRITICAL: '#ef4444'
};

const UserBehaviorAnalyticsPage = () => {
    const [stats, setStats] = useState(null);
    const [users, setUsers] = useState([]);
    const [anomalies, setAnomalies] = useState([]);
    const [riskScores, setRiskScores] = useState([]);
    const [selectedUser, setSelectedUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let active = true;
        const fetchUba = async () => {
            try {
                const token = localStorage.getItem('token');
                const headers = { Authorization: `Bearer ${token}` };
                const [statsResponse, usersResponse, anomaliesResponse, riskResponse] = await Promise.all([
                    axios.get(`${API_BASE}/uba/stats`, { headers }),
                    axios.get(`${API_BASE}/uba/users?limit=10`, { headers }),
                    axios.get(`${API_BASE}/uba/anomalies?limit=50`, { headers }),
                    axios.get(`${API_BASE}/uba/risk-scores`, { headers })
                ]);
                if (!active) return;
                setStats(statsResponse.data);
                setUsers(usersResponse.data);
                setAnomalies(anomaliesResponse.data);
                setRiskScores(riskResponse.data);
            } catch (error) {
                console.error('Failed to fetch UBA analytics', error);
            } finally {
                if (active) setLoading(false);
            }
        };

        fetchUba();
        const intervalId = window.setInterval(fetchUba, 15000);
        return () => {
            active = false;
            window.clearInterval(intervalId);
        };
    }, []);

    const dashboardStats = useMemo(() => ([
        { label: 'Users Monitored', value: stats?.total_users_monitored || 0, icon: Users },
        { label: 'Events 7d', value: stats?.events_7d || 0, icon: Activity },
        { label: 'Anomalies 7d', value: stats?.anomalies_7d || 0, icon: AlertTriangle },
        { label: 'Avg Risk', value: stats?.average_workspace_risk || 0, icon: BrainCircuit }
    ]), [stats]);

    const loginHeatmap = useMemo(() => {
        const buckets = Array.from({ length: 24 }, (_, hour) => ({ hour: `${hour}:00`, count: 0 }));
        anomalies.forEach((event) => {
            if (!event.timestamp || !['login_success', 'login_failed'].includes(event.event_type)) return;
            buckets[new Date(event.timestamp).getHours()].count += 1;
        });
        return buckets;
    }, [anomalies]);

    const locationData = useMemo(() => {
        const counts = {};
        anomalies.forEach((event) => {
            const location = event.location || 'Unknown';
            counts[location] = (counts[location] || 0) + 1;
        });
        return Object.entries(counts).map(([location, count]) => ({ location, count })).slice(0, 8);
    }, [anomalies]);

    const apiTrend = useMemo(() => {
        const counts = {};
        anomalies.forEach((event) => {
            const day = event.timestamp ? new Date(event.timestamp).toLocaleDateString() : 'Unknown';
            counts[day] = counts[day] || { day, api: 0, auth: 0 };
            if (['api_request', 'api_key_usage', 'agent_analysis'].includes(event.event_type)) counts[day].api += 1;
            if (event.event_type.includes('login')) counts[day].auth += 1;
        });
        return Object.values(counts).slice(-7);
    }, [anomalies]);

    const selectedUserEvents = useMemo(() => {
        if (!selectedUser) return anomalies.slice(0, 8);
        return anomalies.filter((event) => event.user_id === selectedUser.user_id).slice(0, 8);
    }, [anomalies, selectedUser]);

    return (
        <div className="fadeIn">
            <PageHeader
                icon={Users}
                iconColor="#5AA9FF"
                title="User Behavior Analytics"
                subtitle="Continuous account behavior monitoring for insider threat and account takeover detection."
                badges={[
                    { label: 'UBA Engine', variant: 'info' },
                    { label: 'Live Monitoring', variant: 'success' },
                ]}
            />
            <div className="stats-grid">
                {dashboardStats.map(({ label, value, icon: Icon }) => (
                    <div className="stat-card" key={label}>
                        <div className="analytics-stat-head">
                            <span className="analytics-stat-icon"><Icon size={20} /></span>
                            <span className="stat-label">{label}</span>
                        </div>
                        <div className="stat-value">{value}</div>
                    </div>
                ))}
            </div>

            <div className="uba-grid">
                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title">User Risk Scores</div>
                    </div>
                    <div className="threat-list">
                        {riskScores.length === 0 ? (
                            <div className="empty-state">{loading ? 'Loading UBA data...' : 'No user behavior events recorded yet.'}</div>
                        ) : riskScores.slice(0, 8).map((item) => (
                            <button className="uba-user-row" key={item.user_id || 'anonymous'} onClick={() => setSelectedUser(item)} type="button">
                                <div>
                                    <div className="threat-name">{item.user_id || 'API key activity'}</div>
                                    <div className="threat-meta">Baseline {item.baseline_risk_score} | Last seen {item.last_seen ? new Date(item.last_seen).toLocaleString() : 'N/A'}</div>
                                </div>
                                <span className="badge" style={{ background: riskColors[item.risk_level] || '#64748b' }}>{item.risk_score}</span>
                            </button>
                        ))}
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title">Top Anomalous Users</div>
                    </div>
                    <div className="threat-list">
                        {users.length === 0 ? (
                            <div className="empty-state">No anomalous users in the current window.</div>
                        ) : users.map((user) => (
                            <button className="uba-user-row" key={user.user_id} onClick={() => setSelectedUser(user)} type="button">
                                <div>
                                    <div className="threat-name">{user.email}</div>
                                    <div className="threat-meta">{user.event_count} behavior events</div>
                                </div>
                                <span className={`badge ${user.risk_level === 'NORMAL' ? 'success' : 'danger'}`}>{user.risk_level}</span>
                            </button>
                        ))}
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title"><Clock size={20} /> Login Activity Heatmap</div>
                    </div>
                    <div className="chart-shell">
                        <ResponsiveContainer width="100%" height={260}>
                            <BarChart data={loginHeatmap}>
                                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                                <XAxis dataKey="hour" stroke="#94a3b8" interval={2} />
                                <YAxis stroke="#94a3b8" allowDecimals={false} />
                                <Tooltip contentStyle={{ background: 'rgba(18,18,26,0.95)', border: '1px solid rgba(255,255,255,0.08)' }} />
                                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                                    {loginHeatmap.map((entry) => <Cell key={entry.hour} fill={entry.count > 0 ? '#06b6d4' : 'rgba(148,163,184,0.28)'} />)}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title"><Globe2 size={20} /> Geographic Access</div>
                    </div>
                    <div className="geo-access-list">
                        {locationData.length === 0 ? (
                            <div className="empty-state">No geographic anomalies recorded.</div>
                        ) : locationData.map((item) => (
                            <div className="usage-row" key={item.location}>
                                <span>{item.location}</span>
                                <strong>{item.count}</strong>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title">API Usage Trends</div>
                    </div>
                    <div className="chart-shell">
                        <ResponsiveContainer width="100%" height={260}>
                            <AreaChart data={apiTrend}>
                                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                                <XAxis dataKey="day" stroke="#94a3b8" />
                                <YAxis stroke="#94a3b8" allowDecimals={false} />
                                <Tooltip contentStyle={{ background: 'rgba(18,18,26,0.95)', border: '1px solid rgba(255,255,255,0.08)' }} />
                                <Area type="monotone" dataKey="api" stroke="#8b5cf6" fill="rgba(139,92,246,0.24)" />
                                <Area type="monotone" dataKey="auth" stroke="#06b6d4" fill="rgba(6,182,212,0.18)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title">Behavioral Anomaly Timeline</div>
                    </div>
                    <div className="timeline-list">
                        {selectedUserEvents.length === 0 ? (
                            <div className="empty-state">No suspicious activity timeline yet.</div>
                        ) : selectedUserEvents.map((event) => (
                            <div className="timeline-item" key={event.id}>
                                <span>{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown time'}</span>
                                <strong>{event.event_type.replaceAll('_', ' ')}</strong>
                                <small>{event.explanation?.explanation || 'Behavior event recorded.'}</small>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            <div className="card analytics-panel recent-scans-panel">
                <div className="card-header">
                    <div className="card-title">Recent Suspicious Activities</div>
                </div>
                <div className="table-shell">
                    <table className="glass-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>User</th>
                                <th>Event</th>
                                <th>IP</th>
                                <th>Location</th>
                                <th>Risk</th>
                                <th>Explanation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {anomalies.length === 0 ? (
                                <tr><td colSpan="7" className="empty-table-cell">No UBA anomalies recorded.</td></tr>
                            ) : anomalies.slice(0, 20).map((event) => (
                                <tr key={event.id}>
                                    <td>{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown'}</td>
                                    <td>{event.user_id || 'API key'}</td>
                                    <td>{event.event_type}</td>
                                    <td>{event.ip_address || 'N/A'}</td>
                                    <td>{event.location || 'N/A'}</td>
                                    <td><span className="badge danger">{event.anomaly_score}</span></td>
                                    <td>{event.explanation?.explanation || 'N/A'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default UserBehaviorAnalyticsPage;
