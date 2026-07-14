import React, { useEffect, useState } from 'react';
import { Bell, AlertTriangle, CheckCircle, Clock, Zap, Shield, ShieldAlert, ArrowUpRight } from 'lucide-react';
import axios from 'axios';
import API_BASE from '../config/api';
import { useAuth } from '../context/AuthContext';

/**
 * Alert Notification Toast Component
 * Displays temporary notifications for critical alerts
 */
export const AlertToast = ({ alert, onClose }) => {
  useEffect(() => {
    const timer = setTimeout(onClose, 6000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const severityColors = {
    CRITICAL: 'border-l-4 border-l-cyber-danger bg-cyber-danger/10 text-[#FF3D57]',
    HIGH: 'border-l-4 border-l-accent bg-accent/10 text-[#FF5A36]',
    MEDIUM: 'border-l-4 border-l-cyber-warning bg-cyber-warning/10 text-[#FFC857]',
    LOW: 'border-l-4 border-l-cyber-success bg-cyber-success/10 text-[#36D399]',
  };

  return (
    <div className={`fixed bottom-6 right-6 z-50 flex items-start gap-4 p-4 rounded-xl shadow-2xl glass-card backdrop-blur-xl border border-white/10 ${severityColors[alert.severity] || 'border-l-4 border-l-accent'} min-w-[320px] max-w-[400px] animate-slide-in`}>
      <div className="p-2 rounded-lg bg-black/20 flex-shrink-0">
        <Bell size={20} className="animate-bounce" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-bold text-sm text-white mb-0.5">{alert.title}</div>
        <div className="text-xs text-gray-400 truncate mb-1">{alert.description}</div>
        <div className="text-[10px] text-gray-500 font-mono">Entity: {alert.entity}</div>
      </div>
      <button 
        className="text-gray-400 hover:text-white transition-colors text-lg leading-none" 
        onClick={onClose}
      >
        &times;
      </button>
    </div>
  );
};

/**
 * Alert Bell Icon with Counter Badge
 * Shows number of unresolved critical alerts
 */
export const AlertBellIcon = ({ unresolved }) => {
  const total = unresolved?.total || 0;
  const critical = unresolved?.by_severity?.CRITICAL || 0;

  return (
    <div className="relative p-2 rounded-lg hover:bg-white/5 transition-colors cursor-pointer text-gray-400 hover:text-white">
      <Bell size={22} className={critical > 0 ? "animate-pulse text-cyber-danger" : ""} />
      {total > 0 && (
        <span className={`absolute -top-1 -right-1 flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold text-white shadow-lg ${critical > 0 ? 'bg-cyber-danger animate-pulse shadow-cyber-danger/30' : 'bg-accent'}`}>
          {total > 99 ? '99+' : total}
        </span>
      )}
    </div>
  );
};

/**
 * Alert Severity Badge Component
 * Color-coded severity indicator
 */
export const SeverityBadge = ({ severity }) => {
  const badgeColors = {
    CRITICAL: 'badge-critical',
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-safe',
  };

  const icons = {
    CRITICAL: <AlertTriangle size={12} />,
    HIGH: <Zap size={12} />,
    MEDIUM: <Clock size={12} />,
    LOW: <CheckCircle size={12} />,
  };

  return (
    <span className={`badge ${badgeColors[severity] || 'badge-muted'}`}>
      {icons[severity]}
      {severity}
    </span>
  );
};

/**
 * Alert Card Component
 * Displays individual alert information
 */
export const AlertCard = ({ alert, onResolve, onSelect, onEscalate }) => {
  const { hasRole } = useAuth();
  const canAct = hasRole(['super_admin', 'workspace_admin', 'security_analyst']);
  const isResolved = alert.resolved_status;

  return (
    <div className={`glass-card relative overflow-hidden p-5 transition-all duration-200 border-l-2 ${
      alert.severity === 'CRITICAL' ? 'border-l-cyber-danger hover:border-l-cyber-danger/80' : 
      alert.severity === 'HIGH' ? 'border-l-accent hover:border-l-accent/80' : 
      alert.severity === 'MEDIUM' ? 'border-l-cyber-warning hover:border-l-cyber-warning/80' : 
      'border-l-cyber-success hover:border-l-cyber-success/80'
    }`}>
      {isResolved && (
        <div className="absolute top-2 right-2 flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-cyber-success/10 text-cyber-success border border-cyber-success/20">
          <CheckCircle size={10} /> RESOLVED
        </div>
      )}
      
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-3">
          <SeverityBadge severity={alert.severity} />
          <h3 className="font-bold text-white text-base tracking-tight">{alert.title}</h3>
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-500 font-mono">
          <Clock size={13} />
          {new Date(alert.created_at).toLocaleString()}
        </div>
      </div>

      <div className="mb-4">
        <p className="text-sm text-gray-300 leading-relaxed mb-4">{alert.description}</p>
        
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 p-3 bg-black/15 border border-white/5 rounded-xl text-xs font-mono">
          <div>
            <span className="text-gray-500 block mb-0.5">ENTITY</span>
            <span className="text-white font-semibold truncate block">{alert.entity}</span>
          </div>
          <div>
            <span className="text-gray-500 block mb-0.5">TYPE</span>
            <span className="text-cyber-info font-semibold">{alert.alert_type}</span>
          </div>
          <div>
            <span className="text-gray-500 block mb-0.5">RISK SCORE</span>
            <span className={`font-semibold ${alert.risk_score >= 75 ? 'text-cyber-danger' : alert.risk_score >= 50 ? 'text-accent' : 'text-cyber-success'}`}>
              {alert.risk_score}/100
            </span>
          </div>
        </div>

        {alert.recommended_action && (
          <div className="mt-4 p-3 bg-cyber-info/5 border border-cyber-info/10 rounded-xl">
            <span className="text-[10px] font-bold text-cyber-info tracking-wider block mb-1">RECOMMENDED ACTION</span>
            <p className="text-xs text-gray-300">{alert.recommended_action}</p>
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-end gap-2 pt-4 border-t border-white/5">
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => onSelect(alert)}
        >
          View Details
        </button>
        {canAct && alert.severity === 'HIGH' && !isResolved && (
          <button
            className="btn btn-danger btn-sm"
            onClick={() => onEscalate(alert.id)}
          >
            Escalate
          </button>
        )}
        {canAct && (!isResolved ? (
          <button
            className="btn btn-primary btn-sm"
            onClick={() => onResolve(alert.id)}
          >
            Resolve
          </button>
        ) : (
          <span className="px-3 py-1.5 text-xs font-semibold text-gray-500 bg-white/5 border border-white/5 rounded-lg select-none">
            Resolved
          </span>
        ))}
      </div>
    </div>
  );
};

/**
 * Alert Detail Modal Component
 * Shows comprehensive alert information
 */
export const AlertDetailModal = ({ alert, onClose, onResolve }) => {
  const { hasRole } = useAuth();
  const canAct = hasRole(['super_admin', 'workspace_admin', 'security_analyst']);
  const [notes, setNotes] = useState('');
  const [resolving, setResolving] = useState(false);

  const handleResolve = async () => {
    setResolving(true);
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `${API_BASE}/alerts/${alert.id}/resolve`,
        { resolution_notes: notes },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      onResolve(alert.id);
      onClose();
    } catch (error) {
      console.error('Failed to resolve alert:', error);
    } finally {
      setResolving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between pb-4 border-b border-white/5 mb-6">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={alert.severity} />
            <h2 className="text-lg font-bold text-white tracking-tight">{alert.title}</h2>
          </div>
          <button className="text-gray-400 hover:text-white transition-colors text-2xl leading-none" onClick={onClose}>×</button>
        </div>

        <div className="space-y-6">
          <div>
            <h3 className="text-xs font-bold text-gray-400 tracking-wider mb-3">ALERT DATA</h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 p-4 bg-black/20 border border-white/5 rounded-xl font-mono text-xs">
              <div>
                <label className="text-gray-500 block mb-0.5">SEVERITY</label>
                <span className="text-white font-semibold">{alert.severity}</span>
              </div>
              <div>
                <label className="text-gray-500 block mb-0.5">RISK SCORE</label>
                <span className={`font-semibold ${alert.risk_score >= 75 ? 'text-cyber-danger' : alert.risk_score >= 50 ? 'text-accent' : 'text-cyber-success'}`}>
                  {alert.risk_score}%
                </span>
              </div>
              <div>
                <label className="text-gray-500 block mb-0.5">ALERT TYPE</label>
                <span className="text-cyber-info font-semibold">{alert.alert_type}</span>
              </div>
              <div>
                <label className="text-gray-500 block mb-0.5">ENTITY</label>
                <span className="text-white truncate block">{alert.entity}</span>
              </div>
              <div>
                <label className="text-gray-500 block mb-0.5">SOURCE VECTOR</label>
                <span className="text-white">{alert.source_vector}</span>
              </div>
              <div>
                <label className="text-gray-500 block mb-0.5">ML CONFIDENCE</label>
                <span className="text-white">{alert.ml_confidence}%</span>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-xs font-bold text-gray-400 tracking-wider mb-2">DESCRIPTION</h3>
            <p className="text-sm text-gray-300 leading-relaxed">{alert.description}</p>
          </div>

          {alert.recommended_action && (
            <div className="p-4 bg-cyber-info/5 border border-cyber-info/10 rounded-xl">
              <h3 className="text-xs font-bold text-cyber-info tracking-wider mb-2">RECOMMENDED ACTION</h3>
              <p className="text-sm text-gray-300 leading-relaxed">{alert.recommended_action}</p>
            </div>
          )}

          {alert.indicators && alert.indicators.length > 0 && (
            <div>
              <h3 className="text-xs font-bold text-gray-400 tracking-wider mb-3">IOC INDICATORS</h3>
              <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
                {alert.indicators.map((indicator, idx) => (
                  <div key={idx} className="flex justify-between items-center p-3 bg-black/15 border border-white/5 rounded-lg text-xs font-mono">
                    <span className="text-cyber-danger font-semibold bg-cyber-danger/10 px-2 py-0.5 rounded">{indicator.type}</span>
                    <span className="text-white font-medium truncate max-w-[200px]">{indicator.value}</span>
                    <span className="text-gray-500">{indicator.source}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {canAct && !alert.resolved_status && (
            <div>
              <h3 className="text-xs font-bold text-gray-400 tracking-wider mb-2">RESOLUTION NOTES</h3>
              <textarea
                className="input-field"
                placeholder="Describe remediation steps, actions taken, or analysis details..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
              />
            </div>
          )}

          {alert.resolved_status && (
            <div className="p-4 bg-cyber-success/5 border border-cyber-success/10 rounded-xl font-mono text-xs">
              <h3 className="font-bold text-cyber-success tracking-wider mb-2">RESOLVED</h3>
              <p className="text-gray-300 mb-1">
                Resolved by <span className="text-white font-semibold">{alert.resolved_by}</span> on {new Date(alert.resolved_at).toLocaleString()}
              </p>
              {alert.resolution_notes && (
                <p className="text-gray-400 mt-2"><strong>Notes:</strong> {alert.resolution_notes}</p>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-3 pt-6 border-t border-white/5 mt-8">
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
          {canAct && !alert.resolved_status && (
            <button
              className="btn btn-primary"
              onClick={handleResolve}
              disabled={resolving}
            >
              {resolving ? 'Resolving...' : 'Resolve Alert'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertCard;
