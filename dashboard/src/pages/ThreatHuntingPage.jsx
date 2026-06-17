import React, { useMemo, useState } from 'react';
import axios from 'axios';
import { Search, SlidersHorizontal, GitBranch, Clock, Network } from 'lucide-react';

import API_BASE from '../config/api';

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

    return (
        <div className="fadeIn">
            <div className="page-header">
                <h1 className="page-title">Threat Hunting</h1>
                <p className="page-subtitle">Search scan history, pivot on related entities, and review correlated incidents.</p>
            </div>

            <form className="card hunting-filter-panel" onSubmit={runSearch}>
                <div className="card-header">
                    <div className="card-title"><SlidersHorizontal size={20} /> Advanced Filters</div>
                    <button className="btn btn-primary" type="submit" disabled={loading}>
                        <Search size={18} /> {loading ? 'Searching...' : 'Search'}
                    </button>
                </div>
                <div className="hunting-filter-grid">
                    {['ip', 'domain', 'url', 'email', 'threat_type'].map((field) => (
                        <div className="input-group" key={field}>
                            <label className="input-label">{field.replace('_', ' ').toUpperCase()}</label>
                            <input
                                className="input-field"
                                value={filters[field]}
                                onChange={(event) => setFilters({ ...filters, [field]: event.target.value })}
                                placeholder={`Filter by ${field.replace('_', ' ')}`}
                            />
                        </div>
                    ))}
                    <div className="input-group">
                        <label className="input-label">SEVERITY</label>
                        <select className="input-field" value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}>
                            <option value="">Any</option>
                            <option value="SAFE">Safe</option>
                            <option value="SUSPICIOUS">Suspicious</option>
                            <option value="HIGH">High</option>
                            <option value="CRITICAL">Critical</option>
                        </select>
                    </div>
                    <div className="input-group">
                        <label className="input-label">FROM</label>
                        <input className="input-field" type="datetime-local" value={filters.from} onChange={(event) => setFilters({ ...filters, from: event.target.value })} />
                    </div>
                    <div className="input-group">
                        <label className="input-label">TO</label>
                        <input className="input-field" type="datetime-local" value={filters.to} onChange={(event) => setFilters({ ...filters, to: event.target.value })} />
                    </div>
                    <div className="input-group">
                        <label className="input-label">SORT</label>
                        <select className="input-field" value={filters.sort_by} onChange={(event) => setFilters({ ...filters, sort_by: event.target.value })}>
                            <option value="created_at">Time</option>
                            <option value="risk_score">Risk score</option>
                            <option value="severity">Severity</option>
                            <option value="attack_type">Attack type</option>
                        </select>
                    </div>
                </div>
            </form>

            <div className="hunting-layout">
                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title">Matching Incidents</div>
                        <span className="badge">{results?.total || 0}</span>
                    </div>
                    <div className="hunting-results">
                        {!results?.incidents?.length ? (
                            <div className="empty-state">Run a search to view incidents.</div>
                        ) : results.incidents.map((incident) => (
                            <button
                                key={incident.id}
                                className={`incident-list-item ${selected?.id === incident.id ? 'active' : ''}`}
                                onClick={() => setSelected(incident)}
                                type="button"
                            >
                                <span>{incident.attack_type || 'UNKNOWN'}</span>
                                <small>{incident.entity || 'N/A'} | risk {incident.risk_score}</small>
                            </button>
                        ))}
                    </div>
                </div>

                <div className="card analytics-panel investigation-panel">
                    <div className="card-header">
                        <div className="card-title"><Network size={20} /> Investigation View</div>
                    </div>
                    {!selected ? (
                        <div className="empty-state">Select an incident to inspect evidence, MITRE mappings, and correlations.</div>
                    ) : (
                        <>
                            <div className="investigation-summary">
                                <div><span>Entity</span><strong>{selected.entity || 'N/A'}</strong></div>
                                <div><span>Vector</span><strong>{selected.input_type?.toUpperCase()}</strong></div>
                                <div><span>Risk</span><strong>{selected.risk_score}</strong></div>
                                <div><span>Verdict</span><strong>{selected.verdict}</strong></div>
                            </div>
                            <section className="detail-section">
                                <h3>Threat Explanation</h3>
                                <p>{selected.explanation?.explanation || 'No explanation stored for this incident.'}</p>
                                <strong>Recommended action</strong>
                                <p>{selected.explanation?.recommended_action || 'Review the incident manually.'}</p>
                            </section>
                            <section className="detail-section">
                                <h3>MITRE ATT&CK</h3>
                                <div className="mitre-grid">
                                    {(selected.mitre_mappings || []).map((mapping) => (
                                        <div className="mitre-card" key={mapping.technique_id}>
                                            <strong>{mapping.technique_id}</strong>
                                            <span>{mapping.technique}</span>
                                            <small>{mapping.tactic}</small>
                                        </div>
                                    ))}
                                </div>
                            </section>
                            <section className="detail-section">
                                <h3>Related Entities</h3>
                                <div className="entity-chip-row">
                                    {(selected.entities || []).map((entity) => <span className="signal-flag" key={entity}>{entity}</span>)}
                                </div>
                            </section>
                        </>
                    )}
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title"><Clock size={20} /> Timeline</div>
                    </div>
                    <div className="timeline-list">
                        {(results?.timeline || []).map((item, index) => (
                            <div className="timeline-item" key={`${item.timestamp}-${index}`}>
                                <span>{item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Unknown'}</span>
                                <strong>{item.attack_type || 'UNKNOWN'}</strong>
                                <small>{item.entity || 'N/A'} | {item.verdict}</small>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="card analytics-panel">
                    <div className="card-header">
                        <div className="card-title"><GitBranch size={20} /> Correlation Findings</div>
                    </div>
                    {(results?.correlation_findings || []).length === 0 ? (
                        <div className="empty-state">No correlation findings in the current result set.</div>
                    ) : results.correlation_findings.map((finding) => (
                        <div className="threat-row" key={finding.scan_id}>
                            <div>
                                <div className="threat-name">{finding.correlation.pattern}</div>
                                <div className="threat-meta">{finding.correlation.evidence_count} related events</div>
                            </div>
                            <span className="badge danger">{finding.correlation.rules_triggered?.length || 0}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default ThreatHuntingPage;
