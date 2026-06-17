import React, { useEffect, useState } from 'react';
import { Bell, AlertTriangle, CheckCircle, Clock, Zap } from 'lucide-react';
import axios from 'axios';
import API_BASE from '../config/api';
import './AlertComponents.css';

/**
 * Alert Notification Toast Component
 * Displays temporary notifications for critical alerts
 */
export const AlertToast = ({ alert, onClose }) => {
  useEffect(() => {
    const timer = setTimeout(onClose, 6000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const severityStyles = {
    CRITICAL: 'toast-critical',
    HIGH: 'toast-high',
    MEDIUM: 'toast-medium',
    LOW: 'toast-low',
  };

  return (
    <div className={`alert-toast ${severityStyles[alert.severity]}`}>
      <div className="toast-icon">
        <Bell size={20} />
      </div>
      <div className="toast-content">
        <div className="toast-title">{alert.title}</div>
        <div className="toast-description">{alert.description}</div>
        <div className="toast-entity">Entity: {alert.entity}</div>
      </div>
      <button className="toast-close" onClick={onClose}>×</button>
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
    <div className="alert-bell">
      <Bell size={24} />
      {total > 0 && (
        <span className={`alert-badge ${critical > 0 ? 'critical' : ''}`}>
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
  const badgeClasses = {
    CRITICAL: 'severity-badge severity-critical',
    HIGH: 'severity-badge severity-high',
    MEDIUM: 'severity-badge severity-medium',
    LOW: 'severity-badge severity-low',
  };

  const icons = {
    CRITICAL: <AlertTriangle size={14} />,
    HIGH: <Zap size={14} />,
    MEDIUM: <Clock size={14} />,
    LOW: <CheckCircle size={14} />,
  };

  return (
    <span className={badgeClasses[severity]}>
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
  return (
    <div className={`alert-card alert-${alert.severity.toLowerCase()}`}>
      <div className="alert-card-header">
        <div className="alert-header-left">
          <SeverityBadge severity={alert.severity} />
          <h3 className="alert-title">{alert.title}</h3>
        </div>
        <div className="alert-header-right">
          <span className="alert-timestamp">
            {new Date(alert.created_at).toLocaleTimeString()}
          </span>
        </div>
      </div>

      <div className="alert-card-body">
        <p className="alert-description">{alert.description}</p>
        
        <div className="alert-details">
          <div className="detail-item">
            <span className="detail-label">Entity:</span>
            <span className="detail-value">{alert.entity}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Type:</span>
            <span className="detail-value">{alert.alert_type}</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Risk Score:</span>
            <span className="detail-value">{alert.risk_score}/100</span>
          </div>
        </div>

        {alert.recommended_action && (
          <div className="alert-recommendation">
            <strong>Recommended Action:</strong>
            <p>{alert.recommended_action}</p>
          </div>
        )}
      </div>

      <div className="alert-card-footer">
        <button
          className="btn btn-secondary"
          onClick={() => onSelect(alert)}
        >
          View Details
        </button>
        {alert.severity === 'HIGH' && !alert.resolved_status && (
          <button
            className="btn btn-warning"
            onClick={() => onEscalate(alert.id)}
          >
            Escalate
          </button>
        )}
        {!alert.resolved_status && (
          <button
            className="btn btn-primary"
            onClick={() => onResolve(alert.id)}
          >
            Resolve
          </button>
        )}
        {alert.resolved_status && (
          <span className="btn btn-disabled">Resolved</span>
        )}
      </div>
    </div>
  );
};

/**
 * Alert Detail Modal Component
 * Shows comprehensive alert information
 */
export const AlertDetailModal = ({ alert, onClose, onResolve }) => {
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
        <div className="modal-header">
          <h2>{alert.title}</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>

        <div className="modal-body">
          <div className="detail-section">
            <h3>Alert Information</h3>
            <div className="info-grid">
              <div className="info-item">
                <label>Severity</label>
                <SeverityBadge severity={alert.severity} />
              </div>
              <div className="info-item">
                <label>Risk Score</label>
                <div className="risk-score">{alert.risk_score}%</div>
              </div>
              <div className="info-item">
                <label>Alert Type</label>
                <div>{alert.alert_type}</div>
              </div>
              <div className="info-item">
                <label>Entity</label>
                <div className="entity-value">{alert.entity}</div>
              </div>
              <div className="info-item">
                <label>Source Vector</label>
                <div>{alert.source_vector}</div>
              </div>
              <div className="info-item">
                <label>ML Confidence</label>
                <div>{alert.ml_confidence}%</div>
              </div>
            </div>
          </div>

          <div className="detail-section">
            <h3>Description</h3>
            <p>{alert.description}</p>
          </div>

          {alert.recommended_action && (
            <div className="detail-section action-section">
              <h3>Recommended Action</h3>
              <p className="action-text">{alert.recommended_action}</p>
            </div>
          )}

          {alert.indicators && alert.indicators.length > 0 && (
            <div className="detail-section">
              <h3>Attack Indicators</h3>
              <div className="indicators-list">
                {alert.indicators.map((indicator, idx) => (
                  <div key={idx} className="indicator-item">
                    <span className="indicator-type">{indicator.type}</span>
                    <span className="indicator-value">{indicator.value}</span>
                    <span className="indicator-source">{indicator.source}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!alert.resolved_status && (
            <div className="detail-section">
              <h3>Resolution</h3>
              <textarea
                className="resolution-notes"
                placeholder="Add notes about your resolution (optional)..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
              />
            </div>
          )}

          {alert.resolved_status && (
            <div className="detail-section resolved-section">
              <h3>Resolution Status</h3>
              <p>
                Resolved by {alert.resolved_by} on {new Date(alert.resolved_at).toLocaleString()}
              </p>
              {alert.resolution_notes && (
                <p><strong>Notes:</strong> {alert.resolution_notes}</p>
              )}
            </div>
          )}
        </div>

        <div className="modal-footer">
          {!alert.resolved_status && (
            <button
              className="btn btn-primary"
              onClick={handleResolve}
              disabled={resolving}
            >
              {resolving ? 'Resolving...' : 'Resolve Alert'}
            </button>
          )}
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default AlertCard;
