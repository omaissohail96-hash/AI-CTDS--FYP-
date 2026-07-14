import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Shield, Lock, Unlock, Search, Filter, Clock,
  AlertCircle, CheckCircle, Eye, Zap, BarChart3, TrendingUp
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import { useAuth } from '../context/AuthContext';

const PreventionCenter = () => {
  const { hasRole } = useAuth();
  const canAct = hasRole(['super_admin', 'workspace_admin', 'security_analyst']);
  const [blockedEntities, setBlockedEntities] = useState([]);
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [loading, setLoading] = useState(true);
  const [selectedEntity, setSelectedEntity] = useState(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [showReasoningModal, setShowReasoningModal] = useState(false);
  const [reasoning, setReasoning] = useState('');
  const [pagination, setPagination] = useState({ skip: 0, limit: 50, total: 0 });

  const API_BASE = 'http://localhost:8000/api/v1/prevention';

  const fetchBlockedEntities = async (skip = 0) => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        skip,
        limit: 50,
        active_only: true
      });
      if (filterType) params.append('entity_type', filterType);
      if (filterSeverity) params.append('severity', filterSeverity);

      const response = await axios.get(`${API_BASE}/blocked?${params}`, {
        headers: { 'X-API-KEY': localStorage.getItem('api_key') }
      });

      setBlockedEntities(response.data.items);
      setPagination({
        skip: response.data.skip,
        limit: response.data.limit,
        total: response.data.total
      });
    } catch (error) {
      console.error('Error fetching blocked entities:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API_BASE}/stats`, {
        headers: { 'X-API-KEY': localStorage.getItem('api_key') }
      });
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const fetchHistory = async () => {
    try {
      const response = await axios.get(`${API_BASE}/history?hours=24&limit=10`, {
        headers: { 'X-API-KEY': localStorage.getItem('api_key') }
      });
      setHistory(response.data.items);
    } catch (error) {
      console.error('Error fetching history:', error);
    }
  };

  const fetchReasoning = async (entityId) => {
    try {
      const response = await axios.get(`${API_BASE}/reasoning/${entityId}`, {
        headers: { 'X-API-KEY': localStorage.getItem('api_key') }
      });
      setReasoning(response.data.reasoning);
      setShowReasoningModal(true);
    } catch (error) {
      console.error('Error fetching reasoning:', error);
    }
  };

  const handleUnblock = async (entityId) => {
    if (!window.confirm('Are you sure you want to unblock this entity?')) return;

    try {
      await axios.post(
        `${API_BASE}/unblock/${entityId}`,
        { reason: 'Manual unblock by user' },
        { headers: { 'X-API-KEY': localStorage.getItem('api_key') } }
      );
      fetchBlockedEntities(pagination.skip);
      fetchStats();
      alert('Entity unblocked successfully');
    } catch (error) {
      console.error('Error unblocking entity:', error);
      alert('Failed to unblock entity');
    }
  };

  useEffect(() => {
    fetchBlockedEntities();
    fetchStats();
    fetchHistory();

    const interval = setInterval(() => {
      fetchStats();
      fetchHistory();
    }, 15000);

    return () => clearInterval(interval);
  }, [filterType, filterSeverity]);

  const getSeverityBadgeClass = (severity) => {
    const classes = {
      LOW: 'badge-safe',
      MEDIUM: 'badge-suspicious',
      HIGH: 'badge-high',
      CRITICAL: 'badge-critical'
    };
    return classes[severity] || 'badge-muted';
  };

  const getEntityTypeIcon = (type) => {
    switch (type) {
      case 'IP': return '📡';
      case 'URL': return '🔗';
      case 'DOMAIN': return '🌐';
      default: return '❓';
    }
  };

  const filteredEntities = blockedEntities.filter(entity =>
    entity.entity.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Shield}
        iconColor="#36D399"
        title="Intrusion Prevention Center"
        subtitle="Configure firewall rules, active blocker parameters, and inspect blacklisted connections."
        badges={[
            { label: 'Active Blocking', variant: 'danger' },
            { label: 'Firewall Sync', variant: 'success' },
        ]}
      />

      {/* Statistics Cards */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="glass-card p-5 border-l-4 border-l-cyber-danger">
            <span className="text-xs font-bold text-gray-500 tracking-wider block mb-1">ACTIVE BLOCKS</span>
            <div className="text-3xl font-extrabold text-white">{stats.active_blocks_count}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-l-accent">
            <span className="text-xs font-bold text-gray-500 tracking-wider block mb-1">BLOCKED REQS (24H)</span>
            <div className="text-3xl font-extrabold text-white">{stats.total_blocked_requests_24h}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-l-cyber-warning">
            <span className="text-xs font-bold text-gray-500 tracking-wider block mb-1">AUTO GENERATED</span>
            <div className="text-3xl font-extrabold text-white">{stats.auto_generated_blocks}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-l-cyber-success">
            <span className="text-xs font-bold text-gray-500 tracking-wider block mb-1">MANUAL RULE BLOCKS</span>
            <div className="text-3xl font-extrabold text-white">{stats.manual_blocks}</div>
          </div>
        </div>
      )}

      {/* Filters and Controls */}
      <div className="glass-card p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3 bg-black/25 border border-white/5 rounded-xl px-4 py-2 flex-1 max-w-md text-gray-500">
          <Search size={16} />
          <input
            type="text"
            placeholder="Filter entities (IP, domain, URL)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent border-none outline-none text-xs text-white placeholder-gray-600 w-full"
          />
        </div>

        <div className="flex gap-3">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="select-control py-1 px-3 text-xs h-9"
          >
            <option value="">All Types</option>
            <option value="IP">IP Address</option>
            <option value="URL">URL</option>
            <option value="DOMAIN">Domain</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="select-control py-1 px-3 text-xs h-9"
          >
            <option value="">All Severities</option>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>
        </div>
      </div>

      {/* Blocked Entities Table */}
      <div className="glass-card overflow-hidden">
        <div className="card-header">
          <h2 className="card-title text-xs uppercase tracking-wider">Active Blacklist telemetry</h2>
        </div>
        {loading ? (
          <div className="p-8 text-center text-gray-500 font-mono text-xs">Accessing block database...</div>
        ) : filteredEntities.length === 0 ? (
          <div className="empty-state py-16 text-center text-gray-500">
            <CheckCircle size={40} className="text-cyber-success mx-auto mb-3" />
            <h3 className="text-sm font-bold text-white mb-1">System Uncompromised</h3>
            <p className="text-xs">No active block restrictions. All routing lanes cleared.</p>
          </div>
        ) : (
          <div className="table-shell">
            <table className="glass-table">
              <thead>
                <tr>
                  <th>Entity</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Reason</th>
                  <th>Hits</th>
                  <th>Expires</th>
                  <th>Auto</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredEntities.map((entity) => (
                  <tr key={entity.id}>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="text-xs">{getEntityTypeIcon(entity.entity_type)}</span>
                        <code className="text-cyber-info font-bold text-xs">{entity.entity}</code>
                      </div>
                    </td>
                    <td className="font-mono text-xs">{entity.entity_type}</td>
                    <td>
                      <span className={`badge ${getSeverityBadgeClass(entity.severity)}`}>
                        {entity.severity}
                      </span>
                    </td>
                    <td className="text-xs text-gray-400 max-w-[200px] truncate">{entity.reason}</td>
                    <td className="font-mono text-xs font-bold text-white">{entity.blocked_request_count}</td>
                    <td className="font-mono text-xs text-gray-500">
                      {new Date(entity.blocked_until).toLocaleTimeString()}
                    </td>
                    <td className="text-center font-bold">{entity.auto_generated ? '✓' : '✗'}</td>
                    <td className="text-right whitespace-nowrap">
                      <button
                        className="btn-action info"
                        onClick={() => {
                          setSelectedEntity(entity);
                          setShowDetailModal(true);
                        }}
                        title="Details"
                      >
                        <Eye size={13} />
                      </button>
                      <button
                        className="btn-action warning"
                        onClick={() => fetchReasoning(entity.id)}
                        title="Decision Engine reasoning"
                      >
                        <AlertCircle size={13} />
                      </button>
                      {canAct && (
                        <button
                          className="btn-action danger"
                          onClick={() => handleUnblock(entity.id)}
                          title="Revoke Block Rule"
                        >
                          <Unlock size={13} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {showDetailModal && selectedEntity && (
        <div className="modal-overlay" onClick={() => setShowDetailModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between pb-4 border-b border-white/5 mb-6">
              <h2 className="text-base font-bold text-white tracking-tight">Security Block Telemetry</h2>
              <button className="text-gray-400 hover:text-white transition-colors text-2xl leading-none" onClick={() => setShowDetailModal(false)}>×</button>
            </div>
            
            <div className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-4 p-4 bg-black/20 border border-white/5 rounded-xl">
                <div>
                  <label className="text-gray-500 block mb-0.5">ENTITY</label>
                  <code className="text-cyber-info font-bold text-xs">{selectedEntity.entity}</code>
                </div>
                <div>
                  <label className="text-gray-500 block mb-0.5">TYPE</label>
                  <span className="text-white font-semibold">{selectedEntity.entity_type}</span>
                </div>
                <div>
                  <label className="text-gray-500 block mb-0.5">SEVERITY</label>
                  <span className={`badge ${getSeverityBadgeClass(selectedEntity.severity)}`}>{selectedEntity.severity}</span>
                </div>
                <div>
                  <label className="text-gray-500 block mb-0.5">BLOCKED REQS</label>
                  <span className="text-white font-bold">{selectedEntity.blocked_request_count}</span>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-gray-500 block">TRIGGER MOTIVE</label>
                <p className="text-gray-300 font-sans leading-relaxed">{selectedEntity.reason}</p>
              </div>

              {selectedEntity.prevention_reason && (
                <div className="space-y-1">
                  <label className="text-gray-500 block">ENGINE INSIGHT</label>
                  <p className="text-gray-300 font-sans leading-relaxed">{selectedEntity.prevention_reason}</p>
                </div>
              )}
            </div>
            
            <div className="flex items-center justify-end gap-3 pt-6 border-t border-white/5 mt-8">
              <button className="btn btn-secondary" onClick={() => setShowDetailModal(false)}>
                Close
              </button>
              {canAct && (
                <button
                  className="btn btn-danger"
                  onClick={() => {
                    handleUnblock(selectedEntity.id);
                    setShowDetailModal(false);
                  }}
                >
                  <Unlock size={14} /> Unblock Entity
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Reasoning Modal */}
      {showReasoningModal && (
        <div className="modal-overlay" onClick={() => setShowReasoningModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between pb-4 border-b border-white/5 mb-6">
              <h2 className="text-base font-bold text-white tracking-tight">Detection Engine Reasoning</h2>
              <button className="text-gray-400 hover:text-white transition-colors text-2xl leading-none" onClick={() => setShowReasoningModal(false)}>×</button>
            </div>
            <div className="max-h-[300px] overflow-y-auto space-y-3 pr-1 text-xs text-gray-300 leading-relaxed font-sans">
              {reasoning.split('\n').map((line, idx) => (
                <p key={idx}>{line}</p>
              ))}
            </div>
            <div className="flex items-center justify-end pt-6 border-t border-white/5 mt-8">
              <button className="btn btn-secondary" onClick={() => setShowReasoningModal(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PreventionCenter;
