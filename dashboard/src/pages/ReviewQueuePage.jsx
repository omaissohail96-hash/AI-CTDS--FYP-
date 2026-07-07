import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { CheckSquare, XCircle, CheckCircle, AlertTriangle, Shield, Clock, ChevronDown, ChevronUp } from 'lucide-react';

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

    if (loading) return <div className="p-8">Loading human review queue...</div>;

    return (
        <div className="p-8 max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2">Human Review Queue</h1>
                    <p className="text-gray-400">Review high-risk entities that did not meet multi-signal block criteria.</p>
                </div>
                <div className="flex gap-4">
                    <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg px-4 py-2 text-center">
                        <div className="text-sm text-gray-400">Pending Review</div>
                        <div className="text-xl font-bold text-amber-500">{metrics.review_queue_pending}</div>
                    </div>
                    <div className="bg-[#1a1f2e] border border-gray-800 rounded-lg px-4 py-2 text-center">
                        <div className="text-sm text-gray-400">FP Rate</div>
                        <div className="text-xl font-bold text-emerald-500">{(metrics.fp_rate * 100).toFixed(1)}%</div>
                    </div>
                </div>
            </div>

            {queueItems.length === 0 ? (
                <div className="bg-[#1a1f2e] border border-gray-800 rounded-xl p-12 text-center">
                    <CheckSquare size={48} className="mx-auto text-emerald-500 mb-4" />
                    <h2 className="text-xl font-bold text-white mb-2">Queue is Empty</h2>
                    <p className="text-gray-400">All pending automated blocks have been reviewed.</p>
                </div>
            ) : (
                <div className="space-y-4">
                    {queueItems.map((item) => (
                        <div key={item.id} className="bg-[#1a1f2e] border border-gray-800 rounded-xl overflow-hidden transition-all duration-200">
                            <div 
                                className="p-4 flex items-center justify-between cursor-pointer hover:bg-white/5"
                                onClick={() => setExpandedItem(expandedItem === item.id ? null : item.id)}
                            >
                                <div className="flex items-center gap-4">
                                    <div className={`w-2 h-12 rounded-full ${item.risk_score >= 85 ? 'bg-red-500' : 'bg-orange-500'}`}></div>
                                    <div>
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className="font-mono font-bold text-white">{item.entity}</span>
                                            <span className="px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-300 uppercase">{item.entity_type}</span>
                                        </div>
                                        <div className="text-sm text-gray-400 flex items-center gap-3">
                                            <span className="flex items-center gap-1"><AlertTriangle size={14} className="text-amber-500"/> Risk: {item.risk_score}</span>
                                            <span className="flex items-center gap-1"><Clock size={14}/> {new Date(item.created_at).toLocaleString()}</span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div className="flex items-center gap-6">
                                    <div className="flex gap-2">
                                        {item.signals?.map((sig, i) => (
                                            <span key={i} className="px-2 py-1 bg-purple-500/10 text-purple-400 rounded text-xs">{sig.replace(/_/g, ' ')}</span>
                                        ))}
                                    </div>
                                    {expandedItem === item.id ? <ChevronUp className="text-gray-500" /> : <ChevronDown className="text-gray-500" />}
                                </div>
                            </div>
                            
                            {expandedItem === item.id && (
                                <div className="p-6 border-t border-gray-800 bg-black/20">
                                    <div className="grid grid-cols-2 gap-8 mb-6">
                                        <div>
                                            <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Risk Contributions</h4>
                                            <div className="space-y-2">
                                                {Object.entries(item.risk_contributions || {}).map(([pillar, val]) => (
                                                    <div key={pillar} className="flex justify-between items-center text-sm">
                                                        <span className="text-gray-300 capitalize">{pillar.replace('_', ' ')}</span>
                                                        <span className="text-white font-medium">{val} pts</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                        <div>
                                            <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Analyst Notes</h4>
                                            <textarea 
                                                className="w-full bg-[#1a1f2e] border border-gray-700 rounded-lg p-3 text-white text-sm focus:border-blue-500 focus:outline-none"
                                                rows="3"
                                                placeholder="Add context or reason for decision..."
                                                value={actionNotes}
                                                onChange={(e) => setActionNotes(e.target.value)}
                                            ></textarea>
                                        </div>
                                    </div>
                                    
                                    <div className="flex justify-end gap-3 pt-4 border-t border-gray-800">
                                        <button 
                                            onClick={() => handleAction(item.id, 'approve')}
                                            className="px-4 py-2 rounded-lg bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20 font-medium flex items-center gap-2"
                                        >
                                            <CheckCircle size={18} /> Confirm False Positive (Unblock)
                                        </button>
                                        <button 
                                            onClick={() => handleAction(item.id, 'reject')}
                                            className="px-4 py-2 rounded-lg bg-red-500/10 text-red-500 hover:bg-red-500/20 font-medium flex items-center gap-2"
                                        >
                                            <Shield size={18} /> Reject (Block Entity)
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
