import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Shield, Lock, Unlock, Trash2, Search, Filter, Clock,
  AlertCircle, CheckCircle, Eye, Zap, BarChart3, TrendingUp
} from 'lucide-react';
import './PreventionCenter.css';

const PreventionCenter = () => {
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

  // Fetch blocked entities
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

  // Fetch statistics
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

  // Fetch history
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

  // Get detailed reasoning
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

  // Unblock entity
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

  // Initial load and setup auto-refresh
  useEffect(() => {
    fetchBlockedEntities();
    fetchStats();
    fetchHistory();

    const interval = setInterval(() => {
      fetchStats();
      fetchHistory();
    }, 15000); // Refresh every 15 seconds

    return () => clearInterval(interval);
  }, [filterType, filterSeverity]);

  const getSeverityColor = (severity) => {
    const colors = {
      LOW: '#10b981',
      MEDIUM: '#f59e0b',
      HIGH: '#f97316',
      CRITICAL: '#ef4444'
    };
    return colors[severity] || '#6b7280';
  };

  const getEntityTypeIcon = (type) => {
    switch (type) {
      case 'IP':
        return '🔴';
      case 'URL':
        return '🔗';
      case 'DOMAIN':
        return '🌐';
      default:
        return '❓';
    }
  };

  const filteredEntities = blockedEntities.filter(entity =>
    entity.entity.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="prevention-center">
      <div className="prevention-header">
        <div className="header-content">
          <Shield className="header-icon" size={40} style={{ color: '#ef4444' }} />
          <div>
            <h1>Threat Prevention Center</h1>
            <p>Active Intrusion Prevention System (IPS) - Real-time entity blocking and response</p>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      {stats && (
        <div className="stats-grid">
          <div className="stat-card critical">
            <div className="stat-icon">
              <AlertCircle size={24} />
            </div>
            <div className="stat-content">
              <div className="stat-value">{stats.active_blocks_count}</div>
              <div className="stat-label">Active Blocks</div>
            </div>
          </div>

          <div className="stat-card warning">
            <div className="stat-icon">
              <Zap size={24} />
            </div>
            <div className="stat-content">
              <div className="stat-value">{stats.total_blocked_requests_24h}</div>
              <div className="stat-label">Blocked (24h)</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">
              <TrendingUp size={24} />
            </div>
            <div className="stat-content">
              <div className="stat-value">{stats.auto_generated_blocks}</div>
              <div className="stat-label">Auto-Blocked</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">
              <BarChart3 size={24} />
            </div>
            <div className="stat-content">
              <div className="stat-value">{stats.manual_blocks}</div>
              <div className="stat-label">Manual Blocks</div>
            </div>
          </div>
        </div>
      )}

      {/* Filters and Controls */}
      <div className="controls-section">
        <div className="search-bar">
          <Search size={20} />
          <input
            type="text"
            placeholder="Search by entity (IP, domain, URL)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>

        <div className="filters">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="filter-select"
          >
            <option value="">All Types</option>
            <option value="IP">IP Address</option>
            <option value="URL">URL</option>
            <option value="DOMAIN">Domain</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="filter-select"
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
      <div className="blocked-entities-section">
        <h2>Active Blocked Entities</h2>
        {loading ? (
          <div className="loading">Loading blocked entities...</div>
        ) : filteredEntities.length === 0 ? (
          <div className="empty-state">
            <CheckCircle size={48} />
            <h3>No Active Blocks</h3>
            <p>All entities are currently allowed. Your network is secure!</p>
          </div>
        ) : (
          <div className="entities-table">
            <table>
              <thead>
                <tr>
                  <th>Entity</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Reason</th>
                  <th>Blocked Requests</th>
                  <th>Expires</th>
                  <th>Auto-Generated</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredEntities.map((entity) => (
                  <tr key={entity.id}>
                    <td className="entity-cell">
                      <span className="entity-icon">{getEntityTypeIcon(entity.entity_type)}</span>
                      <code>{entity.entity}</code>
                    </td>
                    <td>{entity.entity_type}</td>
                    <td>
                      <span
                        className="severity-badge"
                        style={{ backgroundColor: getSeverityColor(entity.severity) }}
                      >
                        {entity.severity}
                      </span>
                    </td>
                    <td className="reason-cell">{entity.reason}</td>
                    <td className="count-cell">{entity.blocked_request_count}</td>
                    <td className="expires-cell">
                      <Clock size={14} />
                      {new Date(entity.blocked_until).toLocaleString()}
                    </td>
                    <td>{entity.auto_generated ? '✓' : '✗'}</td>
                    <td className="actions-cell">
                      <button
                        className="btn-action info"
                        onClick={() => {
                          setSelectedEntity(entity);
                          setShowDetailModal(true);
                        }}
                        title="View details"
                      >
                        <Eye size={16} />
                      </button>
                      <button
                        className="btn-action warning"
                        onClick={() => fetchReasoning(entity.id)}
                        title="Show reasoning"
                      >
                        <AlertCircle size={16} />
                      </button>
                      <button
                        className="btn-action danger"
                        onClick={() => handleUnblock(entity.id)}
                        title="Unblock entity"
                      >
                        <Unlock size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Prevention Timeline */}
      {history.length > 0 && (
        <div className="timeline-section">
          <h2>Recent Prevention Actions</h2>
          <div className="timeline">
            {history.map((item, index) => (
              <div key={item.id} className="timeline-item">
                <div className="timeline-marker">
                  <Lock size={16} />
                </div>
                <div className="timeline-content">
                  <div className="timeline-entity">
                    {getEntityTypeIcon(item.entity_type)} {item.entity}
                  </div>
                  <div className="timeline-reason">{item.reason}</div>
                  <div className="timeline-time">
                    {new Date(item.created_at).toLocaleString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detail Modal */}
      {showDetailModal && selectedEntity && (
        <div className="modal-overlay" onClick={() => setShowDetailModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Entity Details</h2>
            <div className="detail-info">
              <div className="detail-row">
                <label>Entity:</label>
                <code>{selectedEntity.entity}</code>
              </div>
              <div className="detail-row">
                <label>Type:</label>
                <span>{selectedEntity.entity_type}</span>
              </div>
              <div className="detail-row">
                <label>Severity:</label>
                <span
                  className="severity-badge"
                  style={{ backgroundColor: getSeverityColor(selectedEntity.severity) }}
                >
                  {selectedEntity.severity}
                </span>
              </div>
              <div className="detail-row">
                <label>Reason:</label>
                <span>{selectedEntity.reason}</span>
              </div>
              <div className="detail-row">
                <label>Prevention Reasoning:</label>
                <span>{selectedEntity.prevention_reason}</span>
              </div>
              <div className="detail-row">
                <label>Blocked Requests:</label>
                <span>{selectedEntity.blocked_request_count}</span>
              </div>
              <div className="detail-row">
                <label>Blocked Until:</label>
                <span>{new Date(selectedEntity.blocked_until).toLocaleString()}</span>
              </div>
              <div className="detail-row">
                <label>Auto-Generated:</label>
                <span>{selectedEntity.auto_generated ? 'Yes' : 'No'}</span>
              </div>
            </div>
            <div className="modal-actions">
              <button className="btn-primary" onClick={() => setShowDetailModal(false)}>
                Close
              </button>
              <button
                className="btn-danger"
                onClick={() => {
                  handleUnblock(selectedEntity.id);
                  setShowDetailModal(false);
                }}
              >
                <Unlock size={16} /> Unblock Entity
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reasoning Modal */}
      {showReasoningModal && (
        <div className="modal-overlay" onClick={() => setShowReasoningModal(false)}>
          <div className="modal-content reasoning-modal" onClick={(e) => e.stopPropagation()}>
            <h2>Prevention Reasoning</h2>
            <div className="reasoning-text">
              {reasoning.split('\n').map((line, idx) => (
                <p key={idx}>{line}</p>
              ))}
            </div>
            <div className="modal-actions">
              <button className="btn-primary" onClick={() => setShowReasoningModal(false)}>
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
