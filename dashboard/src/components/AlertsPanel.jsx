import React, { useEffect, useState, useCallback } from 'react';
import { AlertCircle, RefreshCw, Filter, SlidersHorizontal, ChevronLeft, ChevronRight } from 'lucide-react';
import axios from 'axios';
import API_BASE from '../config/api';
import { AlertCard, AlertDetailModal, AlertToast } from './AlertComponents';

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

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="alerts-panel space-y-6">
      {/* Alert Statistics */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="glass-card p-5 border-l-4 border-l-cyber-danger">
            <span className="text-xs font-bold text-gray-500 tracking-wider block mb-1">UNRESOLVED CRITICAL</span>
            <div className="text-3xl font-extrabold text-white">{stats.unresolved_by_severity.CRITICAL}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-l-accent">
            <span className="text-xs font-bold text-gray-500 tracking-wider block mb-1">UNRESOLVED HIGH</span>
            <div className="text-3xl font-extrabold text-white">{stats.unresolved_by_severity.HIGH}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-l-cyber-warning">
            <span className="text-xs font-bold text-gray-500 tracking-wider block mb-1">UNRESOLVED MEDIUM</span>
            <div className="text-3xl font-extrabold text-white">{stats.unresolved_by_severity.MEDIUM}</div>
          </div>
          <div className="glass-card p-5 border-l-4 border-l-cyber-info">
            <span className="text-xs font-bold text-gray-500 tracking-wider block mb-1">TOTAL SYSTEM ALERTS</span>
            <div className="text-3xl font-extrabold text-white">{stats.total_alerts}</div>
          </div>
        </div>
      )}

      {/* Control / Filter Bar */}
      <div className="glass-card p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-2 text-sm font-semibold text-gray-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showRecentOnly}
              onChange={(e) => {
                setShowRecentOnly(e.target.checked);
                setPage(0);
              }}
              className="rounded border-white/10 bg-black/40 text-accent focus:ring-accent"
            />
            Recent Alerts Only
          </label>

          {!showRecentOnly && (
            <div className="flex flex-wrap items-center gap-3">
              <div className="h-4 w-[1px] bg-white/10 hidden md:block" />
              
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-gray-500 font-bold uppercase tracking-wider">SEVERITY:</span>
                <div className="flex gap-1">
                  <button 
                    onClick={() => { setFilterSeverity(null); setPage(0); }} 
                    className={`btn btn-sm ${!filterSeverity ? 'btn-primary' : 'btn-secondary'}`}
                  >
                    All
                  </button>
                  {severities.map(sev => (
                    <button
                      key={sev}
                      onClick={() => { setFilterSeverity(sev); setPage(0); }}
                      className={`btn btn-sm ${filterSeverity === sev ? 'btn-primary' : 'btn-secondary'}`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              <div className="h-4 w-[1px] bg-white/10 hidden md:block" />

              <div className="flex items-center gap-1.5">
                <span className="text-xs text-gray-500 font-bold uppercase tracking-wider">STATUS:</span>
                <select
                  value={filterResolved}
                  onChange={(e) => {
                    setFilterResolved(e.target.value === 'true' ? true : e.target.value === 'false' ? false : null);
                    setPage(0);
                  }}
                  className="select-control py-1 px-3 text-xs"
                >
                  <option value="">All Statuses</option>
                  <option value="false">Unresolved</option>
                  <option value="true">Resolved</option>
                </select>
              </div>
            </div>
          )}
        </div>

        <button
          className="btn btn-secondary btn-sm h-9"
          onClick={fetchAlerts}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? 'animate-spin text-accent' : ''} />
          Refresh
        </button>
      </div>

      {/* Alerts List */}
      <div className="space-y-4">
        {error && <div className="p-4 bg-cyber-danger/10 border border-cyber-danger/25 rounded-xl text-[#FF3D57] text-sm text-center">{error}</div>}

        {loading && alerts.length === 0 ? (
          <div className="glass-card p-12 text-center text-gray-400">
            <RefreshCw size={36} className="animate-spin text-accent mx-auto mb-4" />
            <p className="text-sm">Retrieving real-time security alerts...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="glass-card p-12 text-center text-gray-400">
            <AlertCircle size={40} className="text-gray-600 mx-auto mb-4" />
            <p className="text-sm font-semibold">No alerts found matching current criteria</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {alerts.map((alert) => (
              <AlertCard
                key={alert.id}
                alert={alert}
                onResolve={handleResolve}
                onSelect={setSelectedAlert}
                onEscalate={handleEscalate}
              />
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {!showRecentOnly && alerts.length > 0 && (
        <div className="flex items-center justify-between glass-card p-4">
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
          >
            <ChevronLeft size={16} /> Previous Page
          </button>
          <span className="text-xs text-gray-400 font-mono">PAGE {page + 1}</span>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setPage(page + 1)}
            disabled={alerts.length < 50}
          >
            Next Page <ChevronRight size={16} />
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
    return <div className="glass-card p-6 text-gray-400 text-xs animate-pulse">Loading Critical Alerts...</div>;
  }

  if (criticalAlerts.length === 0) {
    return (
      <div className="glass-card p-6 border-l-4 border-l-cyber-success flex items-center justify-between">
        <div>
          <h3 className="font-bold text-white mb-1">🛡️ No Critical Alerts</h3>
          <p className="text-xs text-gray-400">All systems operating within normal parameters.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="glass-card p-6 border-l-4 border-l-cyber-danger">
      <h3 className="font-extrabold text-white text-sm mb-4 tracking-wider flex items-center gap-2">
        <span className="flex h-2.5 w-2.5 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-danger opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyber-danger"></span>
        </span>
        CRITICAL EVENTS ({criticalAlerts.length})
      </h3>
      <div className="space-y-3">
        {criticalAlerts.map((alert) => (
          <div key={alert.id} className="p-3 bg-cyber-danger/5 border border-cyber-danger/10 rounded-xl flex items-center justify-between gap-4 font-mono text-xs">
            <div className="min-w-0">
              <div className="text-white font-semibold truncate">{alert.entity}</div>
              <div className="text-gray-500 truncate text-[10px]">{alert.alert_type}</div>
            </div>
            <div className="text-cyber-danger font-bold flex-shrink-0">RISK: {alert.risk_score}%</div>
          </div>
        ))}
      </div>
    </div>
  );
};

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
    <div className="glass-card p-6">
      <h3 className="font-bold text-white text-sm mb-4 tracking-wider uppercase">Recent Security Timeline</h3>
      {loading ? (
        <p className="text-xs text-gray-500 font-mono animate-pulse">Synchronizing timeline logs...</p>
      ) : alertHistory.length === 0 ? (
        <p className="text-xs text-gray-500 font-mono">No actions logged in the past 24 hours.</p>
      ) : (
        <div className="relative border-l border-white/5 pl-4 ml-2 space-y-4 max-h-[300px] overflow-y-auto">
          {alertHistory.map((alert) => (
            <div key={alert.id} className="relative">
              <span className={`absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border border-[#0B0D11] ${
                alert.severity === 'CRITICAL' ? 'bg-cyber-danger' : 
                alert.severity === 'HIGH' ? 'bg-accent' : 
                alert.severity === 'MEDIUM' ? 'bg-cyber-warning' : 
                'bg-cyber-success'
              }`} />
              <div className="font-mono text-[10px] text-gray-500 mb-0.5">
                {new Date(alert.created_at).toLocaleTimeString()}
              </div>
              <div className="text-xs font-bold text-white leading-tight mb-0.5">{alert.title}</div>
              <div className="text-[10px] text-gray-400 font-mono">{alert.entity}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AlertsPanel;
