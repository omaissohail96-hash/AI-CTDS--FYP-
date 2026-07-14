import React, { useMemo, useState } from 'react';
import axios from 'axios';
import { Search, SlidersHorizontal, GitBranch, Clock, Network, User, AlertTriangle, ShieldCheck, Crosshair, ChevronRight } from 'lucide-react';
import API_BASE from '../config/api';
import PageHeader from '../components/PageHeader';

const emptyFilters = {
    ip: '',
    domain: '',
    url: '',
    email: '',
    from: '',
    to: '',
    threat_type: '',
    severity: '',
    sort_by: 'created_at',
    sort_dir: 'desc'
};

const ThreatHuntingPage = () => {
    const [filters, setFilters] = useState(emptyFilters);
    const [results, setResults] = useState(null);
    const [selected, setSelected] = useState(null);
    const [loading, setLoading] = useState(false);

    const queryParams = useMemo(() => {
        const params = new URLSearchParams();
        Object.entries(filters).forEach(([key, value]) => {
            if (value) params.append(key, value);
        });
        params.append('limit', '100');
        return params;
    }, [filters]);

    const runSearch = async (event) => {
        event?.preventDefault();
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            const response = await axios.get(`${API_BASE}/hunting/search?${queryParams.toString()}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setResults(response.data);
            setSelected(response.data.incidents?.[0] || null);
        } catch (error) {
            console.error('Threat hunting search failed', error);
        } finally {
            setLoading(false);
        }
    };

    const severityColors = {
        SAFE: 'text-cyber-success',
        SUSPICIOUS: 'text-cyber-warning',
        HIGH: 'text-accent',
        CRITICAL: 'text-cyber-danger'
    };

    return (
        <div className="space-y-6">
            <PageHeader
                icon={Crosshair}
                iconColor="#FF3D57"
                title="Threat Hunting Engine"
                subtitle="Query scan history, investigate indicator correlations, and inspect entity relationships"
                badges={[
                    { label: 'Advanced Queries', variant: 'danger' },
                    { label: 'MITRE Mapped', variant: 'info' },
                ]}
            />

            {/* Filter Form */}
            <form className="glass-card p-6" onSubmit={runSearch}>
                <div className="flex items-center justify-between pb-4 border-b border-white/5 mb-6">
                    <div className="flex items-center gap-2 font-bold text-white text-sm uppercase tracking-wider">
                        <SlidersHorizontal size={16} className="text-accent" />
                        Search Criteria
                    </div>
                    <button className="btn btn-primary px-6" type="submit" disabled={loading}>
                        <Search size={15} /> {loading ? 'Running Query...' : 'Run Search'}
                    </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {['ip', 'domain', 'url', 'email', 'threat_type'].map((field) => (
                        <div className="input-group" key={field}>
                            <label className="input-label">{field.replace('_', ' ')}</label>
                            <input
                                className="input-field"
                                value={filters[field]}
                                onChange={(event) => setFilters({ ...filters, [field]: event.target.value })}
                                placeholder={`Filter by ${field}`}
                            />
                        </div>
                    ))}
                    <div className="input-group">
                        <label className="input-label">Severity Level</label>
                        <select className="input-field" value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}>
                            <option value="">Any Severity</option>
                            <option value="SAFE">Safe</option>
                            <option value="SUSPICIOUS">Suspicious</option>
                            <option value="HIGH">High</option>
                            <option value="CRITICAL">Critical</option>
                        </select>
                    </div>
                    <div className="input-group">
                        <label className="input-label">Sort Attribute</label>
                        <select className="input-field" value={filters.sort_by} onChange={(event) => setFilters({ ...filters, sort_by: event.target.value })}>
                            <option value="created_at">Timestamp</option>
                            <option value="risk_score">Risk Score</option>
                            <option value="severity">Severity Level</option>
                            <option value="attack_type">Attack Vector</option>
                        </select>
                    </div>
                </div>
            </form>

            {/* Hunting Content Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                
                {/* Left Panel: Results list */}
                <div className="glass-card lg:col-span-3 overflow-hidden">
                    <div className="card-header">
                        <h3 className="card-title uppercase tracking-wider text-xs">Matching Entities</h3>
                        <span className="badge badge-info">{results?.incidents?.length || 0} hits</span>
                    </div>
                    <div className="divide-y divide-white/5 max-h-[500px] overflow-y-auto">
                        {!results?.incidents?.length ? (
                            <div className="empty-state text-xs p-12 text-gray-500 text-center">Run search query.</div>
                        ) : results.incidents.map((incident) => (
                            <button
                                key={incident.id}
                                className={`w-full text-left p-4 hover:bg-white/5 transition-colors flex items-center justify-between group ${selected?.id === incident.id ? 'bg-accent/10 border-l-2 border-l-accent' : ''}`}
                                onClick={() => setSelected(incident)}
                                type="button"
                            >
                                <div className="min-w-0 pr-2">
                                    <div className="text-white font-bold text-xs truncate mb-1">{incident.attack_type || 'UNKNOWN'}</div>
                                    <div className="text-[10px] text-gray-500 font-mono truncate">{incident.entity || 'N/A'}</div>
                                </div>
                                <div className="flex items-center gap-2 flex-shrink-0">
                                    <span className={`text-xs font-bold font-mono ${incident.risk_score >= 75 ? 'text-cyber-danger' : incident.risk_score >= 50 ? 'text-accent' : 'text-cyber-success'}`}>
                                        {incident.risk_score}%
                                    </span>
                                    <ChevronRight size={14} className="text-gray-600 group-hover:text-gray-400 transition-colors" />
                                </div>
                            </button>
                        ))}
                    </div>
                </div>

                {/* Center Panel: Investigation detail */}
                <div className="glass-card lg:col-span-6">
                    <div className="card-header">
                        <h3 className="card-title uppercase tracking-wider text-xs"><Network size={15} className="text-accent" /> Analyzer Panel</h3>
                    </div>
                    {!selected ? (
                        <div className="empty-state py-24 text-center">
                            <Crosshair size={32} className="text-gray-600 mx-auto mb-3" />
                            <p className="text-xs text-gray-500">Select an indicator hit to initiate deep-dive telemetry analysis.</p>
                        </div>
                    ) : (
                        <div className="p-6 space-y-6">
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-black/15 border border-white/5 rounded-xl text-xs font-mono">
                                <div>
                                    <span className="text-gray-500 block mb-0.5">TARGET ENTITY</span>
                                    <span className="text-white font-semibold truncate block">{selected.entity || 'N/A'}</span>
                                </div>
                                <div>
                                    <span className="text-gray-500 block mb-0.5">INGEST VECTOR</span>
                                    <span className="text-cyber-info font-semibold">{selected.input_type?.toUpperCase()}</span>
                                </div>
                                <div>
                                    <span className="text-gray-500 block mb-0.5">RISK SCORE</span>
                                    <span className={`font-semibold ${selected.risk_score >= 75 ? 'text-cyber-danger' : 'text-cyber-success'}`}>{selected.risk_score}%</span>
                                </div>
                                <div>
                                    <span className="text-gray-500 block mb-0.5">VERDICT</span>
                                    <span className={`font-semibold ${severityColors[selected.verdict] || 'text-white'}`}>{selected.verdict}</span>
                                </div>
                            </div>

                            <div className="space-y-2">
                                <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">AI Security Insight</h4>
                                <p className="text-sm text-gray-300 leading-relaxed bg-white/5 p-4 rounded-xl border border-white/5">{selected.explanation?.explanation || 'No details available.'}</p>
                            </div>

                            {selected.explanation?.recommended_action && (
                                <div className="p-4 bg-cyber-info/5 border border-cyber-info/10 rounded-xl">
                                    <h4 className="text-xs font-bold text-cyber-info uppercase tracking-wider mb-1">Recommended Action</h4>
                                    <p className="text-xs text-gray-300 leading-relaxed">{selected.explanation.recommended_action}</p>
                                </div>
                            )}

                            <div>
                                <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">MITRE Technique Mapping</h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    {(selected.mitre_mappings || []).map((mapping) => (
                                        <div className="p-3 bg-black/20 border border-white/5 rounded-xl font-mono text-xs" key={mapping.technique_id}>
                                            <span className="text-cyber-danger font-semibold bg-cyber-danger/10 px-2 py-0.5 rounded">{mapping.technique_id}</span>
                                            <div className="text-white font-bold mt-2">{mapping.technique}</div>
                                            <div className="text-gray-500 mt-1 uppercase text-[10px]">{mapping.tactic}</div>
                                        </div>
                                    ))}
                                    {(selected.mitre_mappings || []).length === 0 && (
                                        <div className="text-xs text-gray-500 italic p-2">No active mapping matches ATT&amp;CK matrices.</div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Right Panel: Log Timeline / Correlations */}
                <div className="lg:col-span-3 space-y-6">
                    
                    {/* TimeLogs */}
                    <div className="glass-card">
                        <div className="card-header">
                            <h3 className="card-title uppercase tracking-wider text-xs"><Clock size={15} className="text-accent" /> Timeline</h3>
                        </div>
                        <div className="p-5 max-h-[300px] overflow-y-auto relative pl-6 ml-2 border-l border-white/5 space-y-4">
                            {(results?.timeline || []).map((item, index) => (
                                <div className="relative text-xs" key={`${item.timestamp}-${index}`}>
                                    <span className="absolute -left-[27px] top-1.5 h-2.5 w-2.5 rounded-full bg-accent" />
                                    <div className="font-mono text-[10px] text-gray-500 mb-0.5">
                                        {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Unknown'}
                                    </div>
                                    <div className="text-white font-bold">{item.attack_type || 'UNKNOWN'}</div>
                                    <div className="text-[10px] text-gray-400 font-mono mt-0.5">{item.entity || 'N/A'} · {item.verdict}</div>
                                </div>
                            ))}
                            {(results?.timeline || []).length === 0 && (
                                <div className="text-xs text-gray-500 p-2 italic text-center">Timeline logs are empty.</div>
                            )}
                        </div>
                    </div>

                    {/* Correlation Findings */}
                    <div className="glass-card">
                        <div className="card-header">
                            <h3 className="card-title uppercase tracking-wider text-xs"><GitBranch size={15} className="text-accent" /> Findings</h3>
                        </div>
                        <div className="divide-y divide-white/5">
                            {(results?.correlation_findings || []).map((finding) => (
                                <div className="p-4 space-y-2" key={finding.scan_id}>
                                    <div className="flex justify-between items-start">
                                        <div className="font-bold text-xs text-white">{finding.correlation.pattern}</div>
                                        <span className="badge badge-critical">{finding.correlation.rules_triggered?.length || 0}</span>
                                    </div>
                                    <div className="text-[10px] font-mono text-gray-500">
                                        {finding.correlation.evidence_count} evidence entries correlated
                                    </div>
                                </div>
                            ))}
                            {(results?.correlation_findings || []).length === 0 && (
                                <div className="text-xs text-gray-500 p-6 italic text-center">No indicators correlated.</div>
                            )}
                        </div>
                    </div>

                </div>

            </div>
        </div>
    );
};

export default ThreatHuntingPage;
