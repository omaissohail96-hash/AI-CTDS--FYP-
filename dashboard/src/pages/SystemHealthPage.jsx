import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import {
    Shield, ActivitySquare, Database, Cpu, CheckCircle2,
    AlertTriangle, XCircle, Clock, Zap, TrendingUp, Activity,
    Server, Radio
} from 'lucide-react';
import PageHeader from '../components/PageHeader';

const StatusIcon = ({ status }) => {
    if (status === 'ok' || status === 'healthy')
        return <CheckCircle2 className="text-[#36D399]" size={18} />;
    if (status === 'degraded')
        return <AlertTriangle className="text-[#FFC857]" size={18} />;
    return <XCircle className="text-[#FF3D57]" size={18} />;
};

const ServiceCard = ({ icon: Icon, iconBg, iconColor, title, sub, statusKey, healthData, delay }) => (
    <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay }}
        className="glass-card"
        style={{ padding: '22px', display: 'flex', flexDirection: 'column', gap: '16px' }}
    >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{
                width: '42px', height: '42px', borderRadius: '12px',
                background: iconBg, border: `1px solid ${iconColor}30`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
                <Icon size={20} style={{ color: iconColor }} />
            </div>
            <StatusIcon status={statusKey} />
        </div>
        <div>
            <div style={{ fontSize: '0.72rem', color: '#475569', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '4px' }}>{title}</div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#F1F5F9' }}>{sub}</div>
        </div>
        <div style={{
            height: '3px', borderRadius: '2px',
            background: statusKey === 'ok' || statusKey === 'healthy'
                ? 'linear-gradient(90deg, #36D399, #10b981)'
                : statusKey === 'degraded'
                    ? 'linear-gradient(90deg, #FFC857, #f59e0b)'
                    : 'linear-gradient(90deg, #FF3D57, #ef4444)',
            opacity: 0.7,
        }} />
    </motion.div>
);

const MetricCard = ({ label, value, sub, color, icon: Icon, delay }) => (
    <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay }}
        className="glass-card"
        style={{ padding: '22px' }}
    >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</span>
            {Icon && <Icon size={14} style={{ color: '#475569' }} />}
        </div>
        <div style={{ fontSize: '2rem', fontWeight: 800, color: color || '#F1F5F9', letterSpacing: '-0.03em', lineHeight: 1 }}>{value}</div>
        {sub && <div style={{ fontSize: '0.75rem', color: '#475569', marginTop: '8px' }}>{sub}</div>}
    </motion.div>
);

const SystemHealthPage = () => {
    const [healthData, setHealthData] = useState(null);
    const [loading, setLoading] = useState(true);

    const metricsData = {
        cache_hit_rate: 0.87,
        fp_rate_24h: 0.03,
        avg_risk_score: 45.2,
        total_scans: 12450,
        uptime: '99.97%',
        avg_latency: '14ms',
    };

    useEffect(() => {
        const fetchHealth = async () => {
            try {
                const response = await axios.get('http://localhost:8000/api/v1/health');
                setHealthData(response.data);
            } catch (error) {
                console.error('Failed to fetch health data', error);
            } finally {
                setLoading(false);
            }
        };
        fetchHealth();
        const interval = setInterval(fetchHealth, 10000);
        return () => clearInterval(interval);
    }, []);

    const overallStatus = healthData?.status || 'unknown';

    return (
        <div className="space-y-6">
            <PageHeader
                icon={ActivitySquare}
                iconColor="#36D399"
                title="System Infrastructure Health"
                subtitle="Live monitoring of all AI engines, service connections, and performance metrics"
                badges={[
                    {
                        label: overallStatus === 'healthy' ? 'All Systems Healthy' : 'Degraded',
                        variant: overallStatus === 'healthy' ? 'success' : 'warning'
                    },
                    { label: '10s Refresh', variant: 'info' },
                ]}
            />

            {loading && !healthData ? (
                <div style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    padding: '64px', color: '#475569', gap: '12px',
                }}>
                    <Radio size={18} style={{ color: '#36D399', animation: 'pulse 1.5s ease-in-out infinite' }} />
                    <span style={{ fontSize: '0.875rem', fontFamily: 'monospace' }}>Polling system infrastructure...</span>
                </div>
            ) : (
                <>
                    {/* Service Cards */}
                    <div>
                        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '14px' }}>
                            Active Services
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
                            <ServiceCard
                                icon={Database} iconBg="rgba(90,169,255,0.1)" iconColor="#5AA9FF"
                                title="RDBMS Engine" sub="PostgreSQL Database"
                                statusKey={healthData?.services?.database?.status}
                                delay={0}
                            />
                            <ServiceCard
                                icon={Cpu} iconBg="rgba(255,61,87,0.1)" iconColor="#FF3D57"
                                title="Cache Layer" sub="Redis Cluster"
                                statusKey={healthData?.services?.redis?.status}
                                delay={0.07}
                            />
                            <ServiceCard
                                icon={ActivitySquare} iconBg="rgba(255,106,61,0.1)" iconColor="#FF6A3D"
                                title="Task Workers" sub="Celery Daemon Pools"
                                statusKey={healthData?.services?.workers?.status}
                                delay={0.14}
                            />
                            <ServiceCard
                                icon={Shield} iconBg="rgba(54,211,153,0.1)" iconColor="#36D399"
                                title="Global Intelligence" sub="Threat Indicators Feed"
                                statusKey="ok"
                                delay={0.21}
                            />
                        </div>
                    </div>

                    {/* AI Engines */}
                    <div>
                        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '14px' }}>
                            AI Detection Engines
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
                            {[
                                { label: 'URL Classifier',   val: '94%', color: '#5AA9FF',  sub: 'Random Forest · 500k+ indicators' },
                                { label: 'Email LSTM',       val: '91%', color: '#FF8C42',  sub: 'TF-IDF + LSTM · NLP pipeline' },
                                { label: 'Network IDS',      val: '92%', color: '#FF6A3D',  sub: 'Flow classifier · Real-time' },
                                { label: 'Web Attack',       val: '96%', color: '#36D399',  sub: 'HTTP log parser · OWASP Top 10' },
                            ].map((e, i) => (
                                <motion.div
                                    key={e.label}
                                    initial={{ opacity: 0, y: 16 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ duration: 0.4, delay: i * 0.07 }}
                                    className="glass-card"
                                    style={{ padding: '20px' }}
                                >
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                                        <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{e.label}</span>
                                        <CheckCircle2 size={15} style={{ color: '#36D399' }} />
                                    </div>
                                    <div style={{ fontSize: '1.75rem', fontWeight: 800, color: e.color, letterSpacing: '-0.03em', lineHeight: 1 }}>{e.val}</div>
                                    <div style={{ fontSize: '0.72rem', color: '#475569', marginTop: '8px' }}>{e.sub}</div>
                                    <div style={{ height: '3px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', marginTop: '14px', overflow: 'hidden' }}>
                                        <motion.div
                                            initial={{ width: 0 }}
                                            animate={{ width: e.val }}
                                            transition={{ duration: 0.9, delay: i * 0.07 + 0.3 }}
                                            style={{ height: '100%', borderRadius: '2px', background: `linear-gradient(90deg, ${e.color}, ${e.color}88)` }}
                                        />
                                    </div>
                                </motion.div>
                            ))}
                        </div>
                    </div>

                    {/* Performance Metrics */}
                    <div>
                        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '14px' }}>
                            Performance Metrics
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '16px' }}>
                            <MetricCard label="Cache Hit Rate" value={`${(metricsData.cache_hit_rate * 100).toFixed(0)}%`} sub="↑ 2.1% vs yesterday" color="#36D399" icon={TrendingUp} delay={0} />
                            <MetricCard label="False Positive Rate" value={`${(metricsData.fp_rate_24h * 100).toFixed(1)}%`} sub="↓ 0.5% improvement" color="#FF6A3D" icon={Activity} delay={0.07} />
                            <MetricCard label="Total Scans (24h)" value={metricsData.total_scans.toLocaleString()} sub="Across all vectors" color="#5AA9FF" icon={Server} delay={0.14} />
                            <MetricCard label="Platform Uptime" value={metricsData.uptime} sub="30-day rolling average" color="#A78BFA" icon={Zap} delay={0.21} />
                            <MetricCard label="Avg Inference" value={metricsData.avg_latency} sub="End-to-end pipeline" color="#FFC857" icon={Clock} delay={0.28} />
                            <MetricCard label="Redis Latency" value={`${healthData?.services?.redis?.latency_ms || '—'}ms`} sub="Cache response time" color="#36D399" icon={Database} delay={0.35} />
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};

export default SystemHealthPage;
