import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Globe, Monitor, Shield, Activity, Clock, RefreshCw,
  Wifi, User, Key, AlertCircle, CheckCircle, XCircle, Eye
} from 'lucide-react';
import API_BASE from '../config/api';
import PageHeader from '../components/PageHeader';

/* ── helpers ────────────────────────────────────────────────────── */
const authHeaders = () => ({
  Authorization: `Bearer ${localStorage.getItem('token')}`
});

const requestConfig = () => ({
  headers: authHeaders(),
  timeout: 10000,
});

const fmt = (iso) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString();
};

const EventBadge = ({ type }) => {
  if (type === 'login_success') return (
    <span className="ip-badge ip-badge--success"><CheckCircle size={11} /> Success</span>
  );
  return (
    <span className="ip-badge ip-badge--danger"><XCircle size={11} /> Failed</span>
  );
};

const RiskBadge = ({ level }) => {
  const map = { NORMAL: 'success', LOW: 'info', MEDIUM: 'warning', HIGH: 'danger', CRITICAL: 'danger' };
  const cls = map[level] || 'info';
  return <span className={`ip-badge ip-badge--${cls}`}>{level}</span>;
};

/* ── main page ───────────────────────────────────────────────────── */
const IPTrackingPage = () => {
  const [profile, setProfile] = useState(null);
  const [sessions, setSessions] = useState(null);
  const [loginHistory, setLoginHistory] = useState(null);
  const [apiActivity, setApiActivity] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const historyRequest = axios.get(`${API_BASE}/me/login-history?limit=50`, requestConfig());
      const activityRequest = axios.get(`${API_BASE}/me/api-activity?limit=100`, requestConfig());
      const [profileResult, sessionsResult] = await Promise.allSettled([
        axios.get(`${API_BASE}/me`, requestConfig()),
        axios.get(`${API_BASE}/me/sessions`, requestConfig()),
      ]);

      if (profileResult.status !== 'fulfilled') {
        throw profileResult.reason;
      }

      setProfile(profileResult.value.data);
      setSessions(sessionsResult.status === 'fulfilled'
        ? sessionsResult.value.data
        : { total_active_sessions: 0, sessions: [] });

      // These detailed tables should never delay opening the page.
      setLoading(false);
      const [historyResult, activityResult] = await Promise.allSettled([
        historyRequest,
        activityRequest,
      ]);
      setLoginHistory(historyResult.status === 'fulfilled'
        ? historyResult.value.data
        : { history: [] });
      setApiActivity(activityResult.status === 'fulfilled'
        ? activityResult.value.data
        : { recent_activity: [], unique_ips_per_key: {} });
    } catch (err) {
      setError('Failed to load IP tracking data. Make sure you are logged in.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAll(); }, []);

  if (loading) return (
    <div className="ip-loading">
      <div className="ip-spinner" />
      <p>Loading IP tracking data…</p>
    </div>
  );

  if (error) return (
    <div className="ip-error">
      <AlertCircle size={32} />
      <p>{error}</p>
      <button className="ip-tab ip-tab--refresh" onClick={loadAll} title="Try again">
        <RefreshCw size={14} />
      </button>
    </div>
  );

  return (
    <div className="ip-page">
      <PageHeader
        title="IP & Session Tracking"
        subtitle="Monitor all login IPs, active sessions, and API consumer activity"
        icon={Globe}
      />

      {/* ── Summary cards ── */}
      <div className="ip-stat-grid">
        <StatCard
          icon={<Monitor size={22} />}
          label="Current Request IP"
          value={profile?.current_request_ip || '—'}
          accent="cyan"
        />
        <StatCard
          icon={<Shield size={22} />}
          label="Last Login IP"
          value={profile?.last_login_ip || 'No logins yet'}
          accent="purple"
          sub={fmt(profile?.last_login_at)}
        />
        <StatCard
          icon={<Activity size={22} />}
          label="Active Sessions"
          value={sessions?.total_active_sessions ?? '—'}
          accent="green"
        />
        <StatCard
          icon={<Key size={22} />}
          label="Total Logins"
          value={profile?.login_count ?? '—'}
          accent="orange"
        />
      </div>

      {/* ── Tabs ── */}
      <div className="ip-tabs">
        {['overview', 'sessions', 'login-history', 'api-activity'].map(tab => (
          <button
            key={tab}
            className={`ip-tab${activeTab === tab ? ' ip-tab--active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab.replace('-', ' ').replace(/\b\w/g, c => c.toUpperCase())}
          </button>
        ))}
        <button className="ip-tab ip-tab--refresh" onClick={loadAll} title="Refresh">
          <RefreshCw size={14} />
        </button>
      </div>

      {/* ── Tab content ── */}
      <div className="ip-content">
        {activeTab === 'overview' && <OverviewTab profile={profile} />}
        {activeTab === 'sessions' && <SessionsTab sessions={sessions} />}
        {activeTab === 'login-history' && <LoginHistoryTab data={loginHistory} />}
        {activeTab === 'api-activity' && <ApiActivityTab data={apiActivity} />}
      </div>
    </div>
  );
};

/* ── sub-components ─────────────────────────────────────────────── */

const StatCard = ({ icon, label, value, accent, sub }) => (
  <div className={`ip-stat-card ip-stat-card--${accent}`}>
    <div className="ip-stat-icon">{icon}</div>
    <div>
      <p className="ip-stat-label">{label}</p>
      <p className="ip-stat-value">{value}</p>
      {sub && <p className="ip-stat-sub">{sub}</p>}
    </div>
  </div>
);

const OverviewTab = ({ profile }) => (
  <div className="ip-overview">
    <h3 className="ip-section-title"><User size={16} /> Your Account</h3>
    <div className="ip-info-grid">
      <InfoRow label="Email" value={profile?.email} />
      <InfoRow label="Full Name" value={profile?.full_name || '—'} />
      <InfoRow label="Role" value={profile?.role} />
      <InfoRow label="Account Created" value={fmt(profile?.created_at)} />
      <InfoRow label="Current Request IP" value={<IpChip ip={profile?.current_request_ip} />} />
      <InfoRow label="Last Login IP" value={<IpChip ip={profile?.last_login_ip} />} />
      <InfoRow label="Last Login" value={fmt(profile?.last_login_at)} />
      <InfoRow label="Total Logins" value={profile?.login_count ?? 0} />
    </div>
  </div>
);

const SessionsTab = ({ sessions }) => (
  <div>
    <h3 className="ip-section-title"><Monitor size={16} /> Active Sessions ({sessions?.total_active_sessions})</h3>
    {(!sessions?.sessions?.length) ? (
      <EmptyState icon={<Monitor size={32}/>} text="No active sessions found." />
    ) : (
      <div className="ip-table-wrap">
        <table className="ip-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Device / User Agent</th>
              <th>Started</th>
              <th>Expires</th>
            </tr>
          </thead>
          <tbody>
            {sessions.sessions.map(s => (
              <tr key={s.session_id}>
                <td><IpChip ip={s.ip_address} /></td>
                <td className="ip-ua">{s.user_agent || '—'}</td>
                <td>{fmt(s.created_at)}</td>
                <td>{fmt(s.expires_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

const LoginHistoryTab = ({ data }) => (
  <div>
    <h3 className="ip-section-title"><Clock size={16} /> Login History (last {data?.history?.length ?? 0} events)</h3>
    {(!data?.history?.length) ? (
      <EmptyState icon={<Clock size={32}/>} text="No login history found yet." />
    ) : (
      <div className="ip-table-wrap">
        <table className="ip-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>IP Address</th>
              <th>Risk Level</th>
              <th>Anomaly Score</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {data.history.map((e, i) => (
              <tr key={i}>
                <td><EventBadge type={e.event_type} /></td>
                <td><IpChip ip={e.ip_address} /></td>
                <td><RiskBadge level={e.risk_level} /></td>
                <td>{e.anomaly_score ?? 0}</td>
                <td>{fmt(e.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

const ApiActivityTab = ({ data }) => (
  <div>
    <h3 className="ip-section-title"><Key size={16} /> API Consumer Activity</h3>

    {/* Unique IPs per key summary */}
    {data?.unique_ips_per_key && Object.keys(data.unique_ips_per_key).length > 0 && (
      <div className="ip-key-summary">
        <h4 className="ip-subsection">Unique IPs Per API Key</h4>
        <div className="ip-key-cards">
          {Object.entries(data.unique_ips_per_key).map(([label, info]) => (
            <div key={label} className="ip-key-card">
              <div className="ip-key-label"><Key size={13} /> {label}</div>
              <div className="ip-key-stats">
                <span><Wifi size={12} /> {info.unique_ips.length} unique IPs</span>
                <span><Activity size={12} /> {info.total_requests} requests</span>
              </div>
              <div className="ip-key-ips">
                {info.unique_ips.map(ip => <IpChip key={ip} ip={ip} />)}
              </div>
            </div>
          ))}
        </div>
      </div>
    )}

    {/* Raw activity log */}
    <h4 className="ip-subsection">Recent API Calls</h4>
    {(!data?.recent_activity?.length) ? (
      <EmptyState icon={<Activity size={32}/>} text="No API activity recorded yet." />
    ) : (
      <div className="ip-table-wrap">
        <table className="ip-table">
          <thead>
            <tr>
              <th>API Key</th>
              <th>Client IP</th>
              <th>Endpoint</th>
              <th>Status</th>
              <th>Event</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {data.recent_activity.map((log, i) => (
              <tr key={i}>
                <td className="ip-key-name">{log.api_key_label}</td>
                <td><IpChip ip={log.client_ip} /></td>
                <td className="ip-endpoint">{log.endpoint}</td>
                <td>
                  <span className={`ip-status ip-status--${log.status_code < 400 ? 'ok' : 'err'}`}>
                    {log.status_code}
                  </span>
                </td>
                <td>{log.event}</td>
                <td>{fmt(log.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

const IpChip = ({ ip }) => {
  if (!ip) return <span className="ip-chip ip-chip--empty">unknown</span>;
  return <span className="ip-chip"><Globe size={10} /> {ip}</span>;
};

const InfoRow = ({ label, value }) => (
  <div className="ip-info-row">
    <span className="ip-info-label">{label}</span>
    <span className="ip-info-value">{value}</span>
  </div>
);

const EmptyState = ({ icon, text }) => (
  <div className="ip-empty">
    {icon}
    <p>{text}</p>
  </div>
);

export default IPTrackingPage;
