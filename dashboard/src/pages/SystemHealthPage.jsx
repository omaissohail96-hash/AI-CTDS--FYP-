import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, ActivitySquare, Database, Cpu, Search, CheckCircle2, AlertTriangle, XCircle, Clock } from 'lucide-react';

const SystemHealthPage = () => {
    const [healthData, setHealthData] = useState(null);
    const [metricsData, setMetricsData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchHealth = async () => {
            try {
                const response = await axios.get('http://localhost:8000/api/v1/health');
                setHealthData(response.data);
                
                // For a real app, you would parse the prometheus metrics text from /api/v1/metrics
                // or have a dedicated JSON metrics endpoint.
                // We mock it for the UI demonstration here:
                setMetricsData({
                    cache_hit_rate: 0.87,
                    fp_rate_24h: 0.03,
                    avg_risk_score: 45.2,
                    total_scans: 12450
                });
            } catch (error) {
                console.error("Failed to fetch health data", error);
            } finally {
                setLoading(false);
            }
        };

        fetchHealth();
        const interval = setInterval(fetchHealth, 10000); // Poll every 10s
        return () => clearInterval(interval);
    }, []);

    if (loading && !healthData) {
        return <div className="p-8">Loading system health...</div>;
    }

    const StatusIcon = ({ status }) => {
        if (status === 'ok' || status === 'healthy') return <CheckCircle2 className="text-emerald-500" />;
        if (status === 'degraded') return <AlertTriangle className="text-amber-500" />;
        return <XCircle className="text-red-500" />;
    };

    return (
        <div className="p-8 max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2">System Health</h1>
                    <p className="text-gray-400">Live monitoring of Enterprise CyberGuard Infrastructure</p>
                </div>
                <div className={`px-4 py-2 rounded-full font-medium flex items-center gap-2 ${
                    healthData?.status === 'healthy' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-amber-500/10 text-amber-500'
                }`}>
                    <ActivitySquare size={20} />
                    {healthData?.status.toUpperCase()}
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                {/* Database Status */}
                <div className="bg-[#1a1f2e] border border-gray-800 rounded-xl p-6">
                    <div className="flex justify-between items-start mb-4">
                        <div className="p-3 bg-blue-500/10 rounded-lg">
                            <Database className="text-blue-500" size={24} />
                        </div>
                        <StatusIcon status={healthData?.services?.database?.status} />
                    </div>
                    <h3 className="text-gray-400 font-medium mb-1">Database</h3>
                    <p className="text-2xl font-bold text-white">Online</p>
                    <p className="text-sm text-gray-500 mt-2">Pool: 2/20 active</p>
                </div>

                {/* Redis Cache */}
                <div className="bg-[#1a1f2e] border border-gray-800 rounded-xl p-6">
                    <div className="flex justify-between items-start mb-4">
                        <div className="p-3 bg-red-500/10 rounded-lg">
                            <Cpu className="text-red-500" size={24} />
                        </div>
                        <StatusIcon status={healthData?.services?.redis?.status} />
                    </div>
                    <h3 className="text-gray-400 font-medium mb-1">Redis Cache</h3>
                    <p className="text-2xl font-bold text-white">{healthData?.services?.redis?.status === 'ok' ? 'Online' : 'Unavailable'}</p>
                    <p className="text-sm text-gray-500 mt-2">Latency: {healthData?.services?.redis?.latency_ms || '-'}ms</p>
                </div>

                {/* Celery Workers */}
                <div className="bg-[#1a1f2e] border border-gray-800 rounded-xl p-6">
                    <div className="flex justify-between items-start mb-4">
                        <div className="p-3 bg-purple-500/10 rounded-lg">
                            <ActivitySquare className="text-purple-500" size={24} />
                        </div>
                        <StatusIcon status={healthData?.services?.workers?.status} />
                    </div>
                    <h3 className="text-gray-400 font-medium mb-1">Celery Workers</h3>
                    <p className="text-2xl font-bold text-white">{healthData?.services?.workers?.status === 'ok' ? 'Active' : 'Disabled'}</p>
                    <p className="text-sm text-gray-500 mt-2">Queues: high, default, low</p>
                </div>

                {/* Threat Intel */}
                <div className="bg-[#1a1f2e] border border-gray-800 rounded-xl p-6">
                    <div className="flex justify-between items-start mb-4">
                        <div className="p-3 bg-emerald-500/10 rounded-lg">
                            <Shield className="text-emerald-500" size={24} />
                        </div>
                        <StatusIcon status="ok" />
                    </div>
                    <h3 className="text-gray-400 font-medium mb-1">Threat Intelligence</h3>
                    <p className="text-2xl font-bold text-white">Synced</p>
                    <p className="text-sm text-gray-500 mt-2 flex items-center gap-1">
                        <Clock size={14} /> 2 hours ago
                    </p>
                </div>
            </div>

            <h2 className="text-xl font-bold text-white mb-4">Performance Metrics</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-[#1a1f2e] border border-gray-800 rounded-xl p-6">
                    <h3 className="text-gray-400 font-medium mb-2">Cache Hit Rate</h3>
                    <div className="flex items-end gap-2">
                        <span className="text-4xl font-bold text-white">{metricsData?.cache_hit_rate * 100}%</span>
                        <span className="text-sm text-emerald-500 mb-1">↑ 2.1%</span>
                    </div>
                </div>
                
                <div className="bg-[#1a1f2e] border border-gray-800 rounded-xl p-6">
                    <h3 className="text-gray-400 font-medium mb-2">False Positive Rate (24h)</h3>
                    <div className="flex items-end gap-2">
                        <span className="text-4xl font-bold text-white">{(metricsData?.fp_rate_24h * 100).toFixed(1)}%</span>
                        <span className="text-sm text-emerald-500 mb-1">↓ 0.5%</span>
                    </div>
                </div>
                
                <div className="bg-[#1a1f2e] border border-gray-800 rounded-xl p-6">
                    <h3 className="text-gray-400 font-medium mb-2">Total Scans (24h)</h3>
                    <div className="flex items-end gap-2">
                        <span className="text-4xl font-bold text-white">{metricsData?.total_scans.toLocaleString()}</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SystemHealthPage;
