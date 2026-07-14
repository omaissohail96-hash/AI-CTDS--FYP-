import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { CheckSquare, XCircle, CheckCircle, AlertTriangle, Shield, Clock, ChevronDown, ChevronUp, Eye } from 'lucide-react';
import PageHeader from '../components/PageHeader';

const ReviewQueuePage = () => {
    const [queueItems, setQueueItems] = useState([]);
    const [loading, setLoading] = useState(true);
    const [expandedItem, setExpandedItem] = useState(null);
    const [actionNotes, setActionNotes] = useState('');
    const [metrics, setMetrics] = useState({ review_queue_pending: 0, fp_rate: 0 });

    const fetchQueue = async () => {
        try {
            const res = await axios.get('http://localhost:8000/api/v1/fp/review-queue', { withCredentials: true });
            setQueueItems(res.data.items);
            
            const metricsRes = await axios.get('http://localhost:8000/api/v1/fp/metrics', { withCredentials: true });
            setMetrics(metricsRes.data);
        } catch (error) {
            console.error("Failed to fetch review queue", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchQueue();
    }, []);

    const handleAction = async (id, action) => {
        try {
            await axios.post(`http://localhost:8000/api/v1/fp/reports/${id}/${action}`, { notes: actionNotes }, { withCredentials: true });
            setActionNotes('');
            setExpandedItem(null);
            fetchQueue(); // Refresh list
        } catch (error) {
            console.error(`Failed to ${action} item`, error);
        }
    };

    if (loading) return <div className="p-8 text-center text-gray-400 font-mono animate-pulse">Loading human review queue...</div>;

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <PageHeader
                    icon={Eye}
                    iconColor="#FBBF24"
                    title="Human Review Queue"
                    subtitle="Review high-risk entities that did not meet multi-signal blocking thresholds but require analyst attention."
                    badges={[]}
                />
                <div className="flex gap-4">
                    <div className="glass-card px-4 py-2 border-l-2 border-l-cyber-warning flex items-center gap-3">
                        <div>
                            <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider block">PENDING</span>
                            <div className="text-lg font-extrabold text-white">{metrics.review_queue_pending}</div>
                        </div>
                    </div>
                    <div className="glass-card px-4 py-2 border-l-2 border-l-cyber-success flex items-center gap-3">
                        <div>
                            <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider block">FP RATE</span>
                            <div className="text-lg font-extrabold text-white">{(metrics.fp_rate * 100).toFixed(1)}%</div>
                        </div>
                    </div>
                </div>
            </div>

            {queueItems.length === 0 ? (
                <div className="glass-card p-12 text-center text-gray-400">
                    <CheckSquare size={48} className="mx-auto text-cyber-success mb-4 animate-bounce" />
                    <h2 className="text-lg font-bold text-white mb-2">Queue is Empty</h2>
                    <p className="text-sm">All pending block telemetry has been reviewed and verified by security analysts.</p>
                </div>
            ) : (
                <div className="space-y-3">
                    {queueItems.map((item) => (
                        <div key={item.id} className="glass-card overflow-hidden">
                            <div 
                                className="p-4 flex items-center justify-between cursor-pointer hover:bg-white/5 transition-colors"
                                onClick={() => setExpandedItem(expandedItem === item.id ? null : item.id)}
                            >
                                <div className="flex items-center gap-4">
                                    <div className={`w-1 h-10 rounded-full ${item.risk_score >= 85 ? 'bg-cyber-danger' : 'bg-accent'}`}></div>
                                    <div>
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className="font-mono font-bold text-sm text-white">{item.entity}</span>
                                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white/5 border border-white/5 text-cyber-info uppercase tracking-wider">{item.entity_type}</span>
                                        </div>
                                        <div className="text-xs text-gray-500 flex items-center gap-4 font-mono">
                                            <span className="flex items-center gap-1"><AlertTriangle size={13} className="text-cyber-warning"/> Risk: {item.risk_score}%</span>
                                            <span className="flex items-center gap-1"><Clock size={13}/> {new Date(item.created_at).toLocaleString()}</span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div className="flex items-center gap-6">
                                    <div className="flex gap-2">
                                        {item.signals?.map((sig, i) => (
                                            <span key={i} className="px-2 py-0.5 bg-[#FF5A36]/10 text-accent border border-[#FF5A36]/15 rounded text-[10px] font-semibold uppercase tracking-wider">{sig.replace(/_/g, ' ')}</span>
                                        ))}
                                    </div>
                                    {expandedItem === item.id ? <ChevronDown className="text-gray-400 rotate-180 transition-transform duration-200" /> : <ChevronDown className="text-gray-400 transition-transform duration-200" />}
                                </div>
                            </div>
                            
                            {expandedItem === item.id && (
                                <div className="p-6 border-t border-white/5 bg-black/15">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-6">
                                        <div>
                                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Risk Contributions</h4>
                                            <div className="space-y-2 border border-white/5 p-3 rounded-xl bg-black/10 font-mono text-xs">
                                                {Object.entries(item.risk_contributions || {}).map(([pillar, val]) => (
                                                    <div key={pillar} className="flex justify-between items-center py-1">
                                                        <span className="text-gray-400 capitalize">{pillar.replace('_', ' ')}</span>
                                                        <span className="text-white font-bold">{val} pts</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                        <div>
                                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Analyst Action Verdict</h4>
                                            <textarea 
                                                className="input-field text-sm"
                                                rows="3"
                                                placeholder="Provide rationalization for confirmation or false positive report..."
                                                value={actionNotes}
                                                onChange={(e) => setActionNotes(e.target.value)}
                                            ></textarea>
                                        </div>
                                    </div>
                                    
                                    <div className="flex justify-end gap-3 pt-4 border-t border-white/5">
                                        <button 
                                            onClick={() => handleAction(item.id, 'approve')}
                                            className="btn btn-success btn-sm font-bold"
                                        >
                                            <CheckCircle size={15} /> Confirm False Positive (Whitelist)
                                        </button>
                                        <button 
                                            onClick={() => handleAction(item.id, 'reject')}
                                            className="btn btn-danger btn-sm font-bold"
                                        >
                                            <Shield size={15} /> Confirm Attack (Block Entity)
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default ReviewQueuePage;
