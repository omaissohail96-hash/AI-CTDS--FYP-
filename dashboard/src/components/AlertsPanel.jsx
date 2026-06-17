import React, { useEffect, useState, useCallback } from 'react';
import { AlertCircle, RefreshCw, Filter } from 'lucide-react';
import axios from 'axios';
import API_BASE from '../config/api';
import { AlertCard, AlertDetailModal, AlertToast, SeverityBadge } from './AlertComponents';
import './AlertsPanel.css';

/**
 * Alerts Panel Component
 * Displays real-time alert management interface with filtering and statistics
 */
export const AlertsPanel = () => {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState(null);
  const [filterResolved, setFilterResolved] = useState(false);
  const [showRecentOnly, setShowRecentOnly] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toastAlert, setToastAlert] = useState(null);
  const [page, setPage] = useState(0);

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      const headers = { Authorization: `Bearer ${token}` };

      let url = `${API_BASE}/alerts`;
      if (showRecentOnly) {
        url = `${API_BASE}/alerts/recent?limit=30`;
      } else {
        const params = new URLSearchParams({
          limit: 50,
          offset: page * 50,
        });
        if (filterSeverity) params.append('severity', filterSeverity);
        if (filterResolved !== null) params.append('resolved', filterResolved);
        url = `${API_BASE}/alerts?${params.toString()}`;
      }

      const [alertsRes, statsRes] = await Promise.all([
        axios.get(url, { headers }),
        axios.get(`${API_BASE}/alerts/stats`, { headers }),
      ]);

      setAlerts(alertsRes.data.alerts || alertsRes.data);
      setStats(statsRes.data);
      setError(null);

      // Show toast for critical alerts
      const criticalAlerts = (alertsRes.data.alerts || alertsRes.data).filter(
        (a) => a.severity === 'CRITICAL' && !a.resolved_status
      );
      if (criticalAlerts.length > 0 && !selectedAlert) {
        setToastAlert(criticalAlerts[0]);
      }
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
      setError('Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, [showRecentOnly, filterSeverity, filterResolved, page]);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  const handleResolve = async (alertId) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `${API_BASE}/alerts/${alertId}/resolve`,
        { resolution_notes: 'Resolved from dashboard' },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setSelectedAlert(null);
      await fetchAlerts();
    } catch (error) {
      console.error('Failed to resolve alert:', error);
    }
  };

  const handleEscalate = async (alertId) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `${API_BASE}/alerts/${alertId}/escalate`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      await fetchAlerts();
    } catch (error) {
      console.error('Failed to escalate alert:', error);
    }
  };

  return (
    <div className="alerts-panel">
      <div className="panel-header">
        <div className="header-title">
          <AlertCircle size={24} />
          <h2>Security Alerts</h2>
        </div>
        <button
          className="btn-refresh"
          onClick={fetchAlerts}
          disabled={loading}
        >
          <RefreshCw size={18} className={loading ? 'spinning' : ''} />
        </button>
      </div>

      {/* Alert Statistics */}
      {stats && (
        <div className="alerts-stats">
          <div className="stat-card critical">
            <div className="stat-label">Critical</div>
            <div className="stat-value">{stats.unresolved_by_severity.CRITICAL}</div>
          </div>
          <div className="stat-card high">
            <div className="stat-label">High</div>
            <div className="stat-value">{stats.unresolved_by_severity.HIGH}</div>
          </div>
          <div className="stat-card medium">
            <div className="stat-label">Medium</div>
            <div className="stat-value">{stats.unresolved_by_severity.MEDIUM}</div>
          </div>
          <div className="stat-card total">
            <div className="stat-label">Total</div>
            <div className="stat-value">{stats.total_alerts}</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="alerts-filters">
        <div className="filter-group">
          <label className="filter-label">
            <input
              type="checkbox"
              checked={showRecentOnly}
              onChange={(e) => {
                setShowRecentOnly(e.target.checked);
                setPage(0);
              }}
            />
            Show Recent Only
          </label>
        </div>

        {!showRecentOnly && (
          <>
            <div className="filter-group">
              <label className="filter-label">Severity:</label>
              <select
                value={filterSeverity || ''}
                onChange={(e) => {
                  setFilterSeverity(e.target.value || null);
                  setPage(0);
                }}
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Status:</label>
              <select
                value={filterResolved}
                onChange={(e) => {
                  setFilterResolved(e.target.value === 'true' ? true : e.target.value === 'false' ? false : null);
                  setPage(0);
                }}
              >
                <option value="">All Statuses</option>
                <option value="false">Unresolved</option>
                <option value="true">Resolved</option>
              </select>
            </div>
          </>
        )}
      </div>

      {/* Alerts List */}
      <div className="alerts-list">
        {error && <div className="error-message">{error}</div>}

        {loading && alerts.length === 0 ? (
          <div className="loading-state">
            <div className="spinner"></div>
            <p>Loading alerts...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <AlertCircle size={40} />
            <p>No alerts found</p>
          </div>
        ) : (
          alerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onResolve={handleResolve}
              onSelect={setSelectedAlert}
              onEscalate={handleEscalate}
            />
          ))
        )}
      </div>

      {/* Pagination */}
      {!showRecentOnly && alerts.length > 0 && (
        <div className="pagination">
          <button
            className="btn btn-secondary"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
          >
            Previous
          </button>
          <span className="page-info">Page {page + 1}</span>
          <button
            className="btn btn-secondary"
            onClick={() => setPage(page + 1)}
            disabled={alerts.length < 50}
          >
            Next
          </button>
        </div>
      )}

      {/* Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onResolve={handleResolve}
        />
      )}

      {/* Toast Notification */}
      {toastAlert && (
        <AlertToast
          alert={toastAlert}
          onClose={() => setToastAlert(null)}
        />
      )}
    </div>
  );
};

/**
 * Critical Alerts Widget
 * Compact view for critical alerts in main dashboard
 */
export const CriticalAlertsWidget = () => {
  const [criticalAlerts, setCriticalAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCritical = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await axios.get(`${API_BASE}/alerts/critical?limit=5`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setCriticalAlerts(res.data.critical_alerts);
      } catch (error) {
        console.error('Failed to fetch critical alerts:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchCritical();
    const interval = setInterval(fetchCritical, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="widget-skeleton">Loading...</div>;
  }

  if (criticalAlerts.length === 0) {
    return (
      <div className="critical-alerts-widget">
        <h3>🛡️ No Critical Alerts</h3>
        <p>All systems operating normally</p>
      </div>
    );
  }

  return (
    <div className="critical-alerts-widget critical-active">
      <h3>🚨 {criticalAlerts.length} Critical Alert{criticalAlerts.length !== 1 ? 's' : ''}</h3>
      <div className="critical-list">
        {criticalAlerts.map((alert) => (
          <div key={alert.id} className="critical-item">
            <div className="critical-entity">{alert.entity}</div>
            <div className="critical-type">{alert.alert_type}</div>
            <div className="critical-score">Risk: {alert.risk_score}%</div>
          </div>
        ))}
      </div>
    </div>
  );
};

/**
 * Alert Timeline Component
 * Shows recent alert events in chronological order
 */
export const AlertTimeline = ({ limit = 10 }) => {
  const [alertHistory, setAlertHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await axios.get(`${API_BASE}/alerts/recent?hours=24&limit=${limit}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setAlertHistory(res.data.alerts);
      } catch (error) {
        console.error('Failed to fetch alert timeline:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchTimeline();
    const interval = setInterval(fetchTimeline, 30000);
    return () => clearInterval(interval);
  }, [limit]);

  return (
    <div className="alert-timeline">
      <h3>Recent Alert Timeline</h3>
      {loading ? (
        <p>Loading...</p>
      ) : alertHistory.length === 0 ? (
        <p>No alerts in the last 24 hours</p>
      ) : (
        <div className="timeline">
          {alertHistory.map((alert, idx) => (
            <div key={alert.id} className="timeline-item">
              <div className={`timeline-dot severity-${alert.severity.toLowerCase()}`}></div>
              <div className="timeline-content">
                <div className="timeline-time">
                  {new Date(alert.created_at).toLocaleTimeString()}
                </div>
                <div className="timeline-title">{alert.title}</div>
                <div className="timeline-entity">{alert.entity}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AlertsPanel;
