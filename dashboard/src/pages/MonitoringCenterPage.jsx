import React, { useEffect, useState } from 'react';
import axios from 'axios';

const MonitoringCenterPage = () => {
  const [snapshot, setSnapshot] = useState(null);

  useEffect(() => {
    axios.get('http://localhost:8000/api/v1/monitoring').then((res) => setSnapshot(res.data)).catch(() => setSnapshot({ counts: { alerts: 0, scans: 0, users: 0 }, metrics: { counters: {} } }));
  }, []);

  return (
    <div style={{ color: '#f8fafc', padding: 24 }}>
      <h2>Monitoring Center</h2>
      <p style={{ color: '#94a3b8' }}>Operational telemetry for the production security platform.</p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginTop: 16 }}>
        <div className="glass-card" style={{ padding: 20 }}><strong>Alerts</strong><div style={{ fontSize: 28 }}>{snapshot?.counts?.alerts ?? 0}</div></div>
        <div className="glass-card" style={{ padding: 20 }}><strong>Scans</strong><div style={{ fontSize: 28 }}>{snapshot?.counts?.scans ?? 0}</div></div>
        <div className="glass-card" style={{ padding: 20 }}><strong>Users</strong><div style={{ fontSize: 28 }}>{snapshot?.counts?.users ?? 0}</div></div>
      </div>
      <div className="glass-card" style={{ padding: 20, marginTop: 16 }}>
        <h3>Live Metrics</h3>
        <pre style={{ whiteSpace: 'pre-wrap', color: '#cbd5e1' }}>{JSON.stringify(snapshot?.metrics ?? {}, null, 2)}</pre>
      </div>
    </div>
  );
};

export default MonitoringCenterPage;
