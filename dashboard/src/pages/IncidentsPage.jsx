import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import {
  Network, Clock, Shield, AlertTriangle, ChevronRight, RefreshCw,
  FileText, Map, Activity, Target, Cpu, Globe, User, Mail,
  Link2, Layers, GitBranch, CheckCircle, Eye, Search, Filter,
  AlertCircle, Zap, Database, ExternalLink, X, ChevronDown
} from 'lucide-react';
import API_BASE from '../config/api';
import PageHeader from '../components/PageHeader';

// ── Constants ─────────────────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)', border: '#ef4444', text: '#f87171', dot: '#ef4444' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)', border: '#f97316', text: '#fb923c', dot: '#f97316' },
  MEDIUM:   { bg: 'rgba(234,179,8,0.15)',  border: '#eab308', text: '#facc15', dot: '#eab308' },
  LOW:      { bg: 'rgba(34,197,94,0.12)',  border: '#22c55e', text: '#4ade80', dot: '#22c55e' },
};

const STATUS_STYLES = {
  OPEN:          { bg: 'rgba(239,68,68,0.12)',  text: '#f87171',  label: 'Open' },
  INVESTIGATING: { bg: 'rgba(249,115,22,0.12)', text: '#fb923c',  label: 'Investigating' },
  RESOLVED:      { bg: 'rgba(34,197,94,0.12)',  text: '#4ade80',  label: 'Resolved' },
};

const NODE_COLORS = {
  INCIDENT:        { bg: '#7c3aed', border: '#a78bfa' },
  ALERT:           { bg: '#dc2626', border: '#f87171' },
  IP:              { bg: '#0369a1', border: '#38bdf8' },
  URL:             { bg: '#065f46', border: '#34d399' },
  DOMAIN:          { bg: '#0c4a6e', border: '#7dd3fc' },
  EMAIL:           { bg: '#86198f', border: '#e879f9' },
  USER:            { bg: '#92400e', border: '#fbbf24' },
  MITRE_TECHNIQUE: { bg: '#1e1b4b', border: '#818cf8' },
  NETWORK_EVENT:   { bg: '#134e4a', border: '#2dd4bf' },
  default:         { bg: '#1e293b', border: '#475569' },
};

const NODE_ICONS = {
  INCIDENT: '⚡', ALERT: '🚨', IP: '🖥', URL: '🔗', DOMAIN: '🌐',
  EMAIL: '✉', USER: '👤', MITRE_TECHNIQUE: '🎯', NETWORK_EVENT: '📡', default: '●'
};

// ── Helper utilities ──────────────────────────────────────────────────────────

const api = (token) => ({
  get: (url) => axios.get(`${API_BASE}${url}`, { headers: { Authorization: `Bearer ${token}` } })
});

const getSeverityStyle = (s) => SEVERITY_COLORS[s?.toUpperCase()] || SEVERITY_COLORS.LOW;
const getStatusStyle = (s) => STATUS_STYLES[s?.toUpperCase()] || STATUS_STYLES.OPEN;

const formatDate = (iso) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
};

const truncate = (str, n = 28) => str && str.length > n ? str.slice(0, n) + '…' : str;

// ── Sub-components ────────────────────────────────────────────────────────────

const SeverityBadge = ({ severity }) => {
  const s = getSeverityStyle(severity);
  return (
    <span style={{
      background: s.bg, border: `1px solid ${s.border}`, color: s.text,
      borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 700, letterSpacing: '0.05em'
    }}>
      {(severity || 'LOW').toUpperCase()}
    </span>
  );
};

const StatusBadge = ({ status, onClick }) => {
  const s = getStatusStyle(status);
  return (
    <span
      onClick={onClick}
      style={{
        background: s.bg, color: s.text, borderRadius: 6,
        padding: '3px 10px', fontSize: 11, fontWeight: 700,
        cursor: onClick ? 'pointer' : 'default', userSelect: 'none',
        transition: 'opacity 0.15s'
      }}
      title={onClick ? 'Click to change status' : undefined}
    >
      {s.label}
    </span>
  );
};

const RiskBar = ({ score }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
    <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 4, overflow: 'hidden' }}>
      <div style={{
        height: '100%', width: `${score}%`,
        background: score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e',
        borderRadius: 4, transition: 'width 0.4s ease'
      }} />
    </div>
    <span style={{ fontSize: 11, color: '#94a3b8', minWidth: 28 }}>{score}</span>
  </div>
);

const Spinner = () => (
  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', padding: '40px 0' }}>
    <div style={{
      width: 28, height: 28, border: '3px solid rgba(255,255,255,0.1)',
      borderTopColor: '#FF6A3D', borderRadius: '50%', animation: 'spin 0.8s linear infinite'
    }} />
  </div>
);

const EmptyState = ({ icon: Icon, title, subtitle }) => (
  <div style={{ textAlign: 'center', padding: '48px 24px', color: '#475569' }}>
    <Icon size={36} style={{ margin: '0 auto 12px', opacity: 0.4 }} />
    <div style={{ color: '#64748b', fontWeight: 600, marginBottom: 4 }}>{title}</div>
    {subtitle && <div style={{ fontSize: 13, opacity: 0.7 }}>{subtitle}</div>}
  </div>
);

// ── Attack Graph Canvas ───────────────────────────────────────────────────────

const AttackGraph = ({ nodes, edges }) => {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const stateRef = useRef({ nodes: [], dragging: null, offsetX: 0, offsetY: 0, pan: { x: 0, y: 0 }, zoom: 1 });

  const W = 800, H = 440;

  // Initialize node positions with force layout seed
  useEffect(() => {
    if (!nodes?.length) return;
    const cx = W / 2, cy = H / 2;
    const positionedNodes = nodes.map((n, i) => {
      const angle = (2 * Math.PI * i) / nodes.length;
      const r = Math.min(W, H) * 0.32;
      return {
        ...n,
        x: cx + r * Math.cos(angle),
        y: cy + r * Math.sin(angle),
        vx: 0, vy: 0, radius: n.type === 'INCIDENT' ? 30 : 20,
      };
    });
    stateRef.current.nodes = positionedNodes;
  }, [nodes]);

  // Force-directed animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !nodes?.length) return;
    const ctx = canvas.getContext('2d');

    const tick = () => {
      const s = stateRef.current;
      const ns = s.nodes;
      const { pan, zoom } = s;

      // Force: repulsion
      for (let i = 0; i < ns.length; i++) {
        for (let j = i + 1; j < ns.length; j++) {
          const dx = ns[j].x - ns[i].x, dy = ns[j].y - ns[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = 2800 / (dist * dist);
          const fx = (dx / dist) * force, fy = (dy / dist) * force;
          ns[i].vx -= fx; ns[i].vy -= fy;
          ns[j].vx += fx; ns[j].vy += fy;
        }
      }

      // Force: edge attraction
      (edges || []).forEach(e => {
        const src = ns.find(n => n.id === e.source);
        const tgt = ns.find(n => n.id === e.target);
        if (!src || !tgt) return;
        const dx = tgt.x - src.x, dy = tgt.y - src.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const strength = 0.04 * (dist - 120);
        src.vx += (dx / dist) * strength; src.vy += (dy / dist) * strength;
        tgt.vx -= (dx / dist) * strength; tgt.vy -= (dy / dist) * strength;
      });

      // Force: gravity to center
      ns.forEach(n => {
        if (n === s.dragging) return;
        n.vx += (W / 2 - n.x) * 0.008;
        n.vy += (H / 2 - n.y) * 0.008;
        n.vx *= 0.82; n.vy *= 0.82;
        n.x += n.vx; n.y += n.vy;
      });

      // Draw
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      ctx.translate(pan.x, pan.y);
      ctx.scale(zoom, zoom);

      // Edges
      (edges || []).forEach(e => {
        const src = ns.find(n => n.id === e.source);
        const tgt = ns.find(n => n.id === e.target);
        if (!src || !tgt) return;
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = 'rgba(99,102,241,0.35)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Arrow
        const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
        const aLen = 9, aWidth = 4;
        const ex = tgt.x - (tgt.radius + 4) * Math.cos(angle);
        const ey = tgt.y - (tgt.radius + 4) * Math.sin(angle);
        ctx.beginPath();
        ctx.moveTo(ex, ey);
        ctx.lineTo(ex - aLen * Math.cos(angle - 0.4), ey - aLen * Math.sin(angle - 0.4));
        ctx.lineTo(ex - aLen * Math.cos(angle + 0.4), ey - aLen * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fillStyle = 'rgba(99,102,241,0.6)';
        ctx.fill();

        // Edge label
        ctx.font = '9px Inter, sans-serif';
        ctx.fillStyle = 'rgba(148,163,184,0.7)';
        ctx.fillText(e.type, (src.x + tgt.x) / 2, (src.y + tgt.y) / 2 - 5);
      });

      // Nodes
      ns.forEach(n => {
        const colors = NODE_COLORS[n.type] || NODE_COLORS.default;
        const r = n.radius;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = colors.bg;
        ctx.fill();
        ctx.strokeStyle = colors.border;
        ctx.lineWidth = 2;
        ctx.stroke();

        // Icon
        ctx.font = `${r * 0.8}px sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(NODE_ICONS[n.type] || NODE_ICONS.default, n.x, n.y - 1);

        // Label
        ctx.font = '10px Inter, sans-serif';
        ctx.fillStyle = '#cbd5e1';
        ctx.fillText(truncate(n.label, 16), n.x, n.y + r + 12);
      });

      ctx.restore();
      animRef.current = requestAnimationFrame(tick);
    };

    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [nodes, edges]);

  // Mouse drag
  const onMouseDown = (e) => {
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = (e.clientX - rect.left - stateRef.current.pan.x) / stateRef.current.zoom;
    const my = (e.clientY - rect.top - stateRef.current.pan.y) / stateRef.current.zoom;
    const hit = stateRef.current.nodes.find(n => Math.hypot(n.x - mx, n.y - my) < n.radius + 4);
    if (hit) {
      stateRef.current.dragging = hit;
      stateRef.current.offsetX = hit.x - mx;
      stateRef.current.offsetY = hit.y - my;
    }
  };
  const onMouseMove = (e) => {
    const s = stateRef.current;
    if (!s.dragging) return;
    const rect = canvasRef.current.getBoundingClientRect();
    s.dragging.x = (e.clientX - rect.left - s.pan.x) / s.zoom + s.offsetX;
    s.dragging.y = (e.clientY - rect.top - s.pan.y) / s.zoom + s.offsetY;
    s.dragging.vx = 0; s.dragging.vy = 0;
  };
  const onMouseUp = () => { stateRef.current.dragging = null; };

  if (!nodes?.length) return <EmptyState icon={Network} title="No graph data" subtitle="Graph will populate as threats are detected" />;

  return (
    <div style={{ position: 'relative', background: 'rgba(0,0,0,0.3)', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ position: 'absolute', top: 8, right: 10, fontSize: 11, color: '#475569', zIndex: 1 }}>
        Drag nodes · {nodes.length} nodes · {edges.length} edges
      </div>
      <canvas
        ref={canvasRef}
        width={W} height={H}
        style={{ width: '100%', display: 'block', cursor: 'grab' }}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
      />
    </div>
  );
};

// ── Timeline ──────────────────────────────────────────────────────────────────

const TimelineView = ({ events }) => {
  if (!events?.length) return <EmptyState icon={Clock} title="No timeline events" subtitle="Events appear as threats are detected" />;
  return (
    <div style={{ position: 'relative', paddingLeft: 28 }}>
      <div style={{ position: 'absolute', left: 10, top: 0, bottom: 0, width: 2, background: 'rgba(99,102,241,0.25)', borderRadius: 2 }} />
      {events.map((ev, i) => {
        const sev = getSeverityStyle(ev.severity);
        return (
          <div key={i} style={{ position: 'relative', marginBottom: 20 }}>
            <div style={{
              position: 'absolute', left: -22, top: 5, width: 12, height: 12, borderRadius: '50%',
              background: sev.dot, boxShadow: `0 0 8px ${sev.dot}60`
            }} />
            <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 8, padding: '10px 14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6, flexWrap: 'wrap', gap: 6 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>{ev.event_type}</span>
                  <SeverityBadge severity={ev.severity} />
                  {ev.mitre_technique && (
                    <span style={{ background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.3)', color: '#a5b4fc', borderRadius: 4, padding: '1px 6px', fontSize: 10 }}>
                      {ev.mitre_technique}
                    </span>
                  )}
                </div>
                <span style={{ fontSize: 11, color: '#64748b', whiteSpace: 'nowrap' }}>{formatDate(ev.timestamp)}</span>
              </div>
              <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>
                <span style={{ color: '#64748b' }}>Entity: </span>{ev.entity}
                <span style={{ color: '#64748b', marginLeft: 10 }}>Source: </span>{ev.source}
                <span style={{ color: '#64748b', marginLeft: 10 }}>Risk: </span>
                <span style={{ color: getSeverityStyle(ev.severity).text }}>{ev.risk_score}</span>
              </div>
              {ev.correlation_reason && (
                <div style={{ fontSize: 11, color: '#475569', fontStyle: 'italic' }}>{ev.correlation_reason}</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ── Evidence Panel ────────────────────────────────────────────────────────────

const EvidencePanel = ({ evidence }) => {
  const importanceColors = { HIGH: '#ef4444', MEDIUM: '#f97316', LOW: '#22c55e' };
  if (!evidence?.length) return <EmptyState icon={FileText} title="No evidence collected" subtitle="Evidence is gathered automatically from detections" />;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {evidence.map((ev, i) => (
        <div key={i} style={{
          background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.07)',
          borderLeft: `3px solid ${importanceColors[ev.importance] || '#475569'}`,
          borderRadius: 8, padding: '10px 14px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5, flexWrap: 'wrap', gap: 6 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>{ev.evidence_type}</span>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: '#64748b', background: 'rgba(255,255,255,0.05)', borderRadius: 4, padding: '1px 6px' }}>{ev.source}</span>
              <span style={{ fontSize: 10, color: '#64748b' }}>Conf: {ev.confidence}%</span>
              <span style={{ fontSize: 11, color: '#64748b' }}>{formatDate(ev.timestamp)}</span>
            </div>
          </div>
          <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: ev.value_indicator ? 5 : 0 }}>{ev.description}</div>
          {ev.value_indicator && (
            <div style={{ fontSize: 11, color: '#7dd3fc', fontFamily: 'monospace', background: 'rgba(0,0,0,0.3)', borderRadius: 4, padding: '3px 8px', display: 'inline-block' }}>
              {ev.value_indicator}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

// ── Attack Path ───────────────────────────────────────────────────────────────

const AttackPath = ({ steps }) => {
  if (!steps?.length) return <EmptyState icon={GitBranch} title="No attack path" subtitle="Path is reconstructed from correlated events" />;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {steps.map((step, i) => (
        <div key={i} style={{ display: 'flex', gap: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 36 }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%',
              background: 'rgba(99,102,241,0.2)', border: '2px solid rgba(99,102,241,0.5)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, fontWeight: 700, color: '#a5b4fc', flexShrink: 0
            }}>{step.step}</div>
            {i < steps.length - 1 && (
              <div style={{ width: 2, flex: 1, minHeight: 20, background: 'rgba(99,102,241,0.2)', margin: '2px 0' }} />
            )}
          </div>
          <div style={{ flex: 1, paddingBottom: 14, paddingLeft: 10, paddingTop: 2 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0', marginBottom: 2 }}>{step.label}</div>
            <div style={{ fontSize: 11, color: '#64748b', marginBottom: 2 }}>{step.description}</div>
            <div style={{ fontSize: 10, color: '#475569' }}>{formatDate(step.timestamp)}</div>
          </div>
        </div>
      ))}
    </div>
  );
};

// ── MITRE Techniques ──────────────────────────────────────────────────────────

const MitreTechniques = ({ techniques }) => {
  if (!techniques?.length) return <EmptyState icon={Target} title="No MITRE techniques" subtitle="Technique mappings are inferred from scan results" />;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {techniques.map((t, i) => (
        <div key={i} style={{
          background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)',
          borderRadius: 8, padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center'
        }}>
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#a5b4fc', fontWeight: 700 }}>{t.technique_id}</span>
              <span style={{ fontSize: 12, color: '#e2e8f0', fontWeight: 600 }}>{t.technique}</span>
            </div>
            <div style={{ fontSize: 11, color: '#64748b' }}>Tactic: {t.tactic} · Seen {t.count}×</div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 16, fontWeight: 800, color: t.max_risk_score >= 80 ? '#ef4444' : '#fb923c' }}>{t.max_risk_score}</div>
            <div style={{ fontSize: 10, color: '#475569' }}>risk</div>
          </div>
        </div>
      ))}
    </div>
  );
};

// ── Incident Detail ───────────────────────────────────────────────────────────

const TABS = [
  { id: 'graph',    label: 'Attack Graph',  icon: Network },
  { id: 'timeline', label: 'Timeline',      icon: Clock },
  { id: 'evidence', label: 'Evidence',      icon: FileText },
  { id: 'path',     label: 'Attack Path',   icon: GitBranch },
  { id: 'mitre',    label: 'MITRE ATT&CK', icon: Target },
];

const IncidentDetail = ({ incident, onStatusChange }) => {
  const [activeTab, setActiveTab] = useState('graph');
  const [tabData, setTabData] = useState({});
  const [loading, setLoading] = useState(false);
  const [statusChanging, setStatusChanging] = useState(false);
  const prevId = useRef(null);

  const fetchTab = useCallback(async (tab) => {
    if (!incident) return;
    const token = localStorage.getItem('token');
    const id = incident.id;
    const endpointMap = {
      graph: `/incidents/${id}/graph`,
      timeline: `/incidents/${id}/timeline`,
      evidence: `/incidents/${id}/evidence`,
      path: `/incidents/${id}/attack-path`,
      mitre: `/incidents/${id}/mitre`,
    };
    setLoading(true);
    try {
      const res = await api(token).get(endpointMap[tab]);
      setTabData(prev => ({ ...prev, [tab]: res.data }));
    } catch (e) {
      console.error('Tab fetch error:', e);
    } finally {
      setLoading(false);
    }
  }, [incident]);

  useEffect(() => {
    if (!incident) return;
    if (incident.id !== prevId.current) {
      prevId.current = incident.id;
      setTabData({});
      setActiveTab('graph');
      fetchTab('graph');
    }
  }, [incident, fetchTab]);

  useEffect(() => {
    if (!tabData[activeTab] && incident) {
      fetchTab(activeTab);
    }
  }, [activeTab, tabData, incident, fetchTab]);

  const cycleStatus = async () => {
    const cycle = { OPEN: 'INVESTIGATING', INVESTIGATING: 'RESOLVED', RESOLVED: 'OPEN' };
    const next = cycle[incident.status] || 'OPEN';
    setStatusChanging(true);
    try {
      const token = localStorage.getItem('token');
      await axios.put(`${API_BASE}/incidents/${incident.id}/status`,
        { status: next }, { headers: { Authorization: `Bearer ${token}` } }
      );
      onStatusChange(incident.id, next);
    } catch (e) {
      console.error('Status update failed:', e);
    } finally {
      setStatusChanging(false);
    }
  };

  if (!incident) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#475569' }}>
        <div style={{ textAlign: 'center' }}>
          <Shield size={40} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Select an incident</div>
          <div style={{ fontSize: 13 }}>Choose an incident from the list to investigate</div>
        </div>
      </div>
    );
  }

  const sev = getSeverityStyle(incident.severity);

  const renderTabContent = () => {
    if (loading) return <Spinner />;
    const data = tabData[activeTab];
    if (!data) return <Spinner />;
    switch (activeTab) {
      case 'graph':    return <AttackGraph nodes={data.nodes} edges={data.edges} />;
      case 'timeline': return <TimelineView events={data.timeline} />;
      case 'evidence': return <EvidencePanel evidence={data.evidence} />;
      case 'path':     return <AttackPath steps={data.attack_path} />;
      case 'mitre':    return <MitreTechniques techniques={data.techniques} />;
      default:         return null;
    }
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{
        padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.07)',
        background: 'rgba(0,0,0,0.2)'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 11, color: '#475569', fontFamily: 'monospace' }}>{incident.id.slice(0, 8)}…</span>
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} onClick={cycleStatus} />
              {statusChanging && <span style={{ fontSize: 11, color: '#64748b' }}>Updating…</span>}
            </div>
            <div style={{ fontSize: 14, color: '#94a3b8' }}>
              <span>First seen: {formatDate(incident.first_seen)}</span>
              <span style={{ margin: '0 10px', color: '#334155' }}>·</span>
              <span>Last seen: {formatDate(incident.last_seen)}</span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {[
              { label: 'Risk', value: incident.risk_score },
              { label: 'Conf.', value: `${incident.confidence}%` },
              { label: 'Alerts', value: (incident.related_alerts || []).length },
              { label: 'MITRE', value: (incident.mitre_techniques || []).length },
            ].map(({ label, value }) => (
              <div key={label} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 18, fontWeight: 800, color: '#f1f5f9' }}>{value}</div>
                <div style={{ fontSize: 10, color: '#64748b' }}>{label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Asset pills */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
          {(incident.affected_ips || []).map(ip => (
            <span key={ip} style={{ background: 'rgba(14,165,233,0.1)', border: '1px solid rgba(14,165,233,0.25)', color: '#38bdf8', borderRadius: 4, padding: '2px 8px', fontSize: 11 }}>
              🖥 {ip}
            </span>
          ))}
          {(incident.affected_urls_domains || []).map(u => (
            <span key={u} style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', color: '#4ade80', borderRadius: 4, padding: '2px 8px', fontSize: 11 }}>
              🔗 {truncate(u, 30)}
            </span>
          ))}
          {(incident.mitre_techniques || []).map(t => (
            <span key={t} style={{ background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.3)', color: '#a5b4fc', borderRadius: 4, padding: '2px 8px', fontSize: 11 }}>
              🎯 {t}
            </span>
          ))}
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid rgba(255,255,255,0.07)', background: 'rgba(0,0,0,0.1)', overflowX: 'auto' }}>
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '10px 16px',
              background: 'none', border: 'none', borderBottom: activeTab === id ? '2px solid #FF6A3D' : '2px solid transparent',
              color: activeTab === id ? '#FF6A3D' : '#64748b', cursor: 'pointer',
              fontSize: 12, fontWeight: 600, whiteSpace: 'nowrap', transition: 'color 0.15s'
            }}
          >
            <Icon size={13} />
            {label}
          </button>
        ))}
      </div>

      {/* Tab body */}
      <div style={{ flex: 1, overflow: 'auto', padding: '16px 20px' }}>
        {renderTabContent()}
      </div>
    </div>
  );
};

// ── Main Page ─────────────────────────────────────────────────────────────────

const IncidentsPage = () => {
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterSev, setFilterSev] = useState('');

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams({ limit: '100' });
      if (filterStatus) params.append('status', filterStatus);
      if (filterSev) params.append('severity', filterSev);
      const res = await api(token).get(`/incidents?${params.toString()}`);
      setIncidents(res.data.incidents || []);
      setTotal(res.data.total || 0);
      if (res.data.incidents?.length && !selected) {
        setSelected(res.data.incidents[0]);
      }
    } catch (e) {
      console.error('Failed to load incidents:', e);
    } finally {
      setLoading(false);
    }
  }, [filterStatus, filterSev]);

  useEffect(() => { loadIncidents(); }, [loadIncidents]);

  const handleStatusChange = (id, newStatus) => {
    setIncidents(prev => prev.map(inc => inc.id === id ? { ...inc, status: newStatus } : inc));
    if (selected?.id === id) setSelected(prev => ({ ...prev, status: newStatus }));
  };

  const filtered = incidents.filter(inc =>
    !search ||
    inc.id.includes(search.toLowerCase()) ||
    (inc.affected_ips || []).some(ip => ip.includes(search)) ||
    (inc.mitre_techniques || []).some(t => t.toLowerCase().includes(search.toLowerCase())) ||
    inc.severity.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 0 }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 4px; }
      `}</style>

      <PageHeader
        icon={<Layers size={20} />}
        title="Incident Stories"
        subtitle={`${total} correlated attack campaigns across all vectors`}
      />

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', gap: 0, minHeight: 0 }}>

        {/* Left panel: incident list */}
        <div style={{
          width: 310, flexShrink: 0, borderRight: '1px solid rgba(255,255,255,0.07)',
          display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.15)'
        }}>
          {/* Filters */}
          <div style={{ padding: '12px 14px', borderBottom: '1px solid rgba(255,255,255,0.07)', display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ position: 'relative' }}>
              <Search size={13} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: '#475569' }} />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search incidents…"
                style={{
                  width: '100%', boxSizing: 'border-box', paddingLeft: 28, paddingRight: 10,
                  height: 32, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: 6, color: '#e2e8f0', fontSize: 12, outline: 'none'
                }}
              />
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {[
                { key: 'status', value: filterStatus, set: setFilterStatus, options: ['', 'OPEN', 'INVESTIGATING', 'RESOLVED'], label: 'Status' },
                { key: 'sev', value: filterSev, set: setFilterSev, options: ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], label: 'Severity' },
              ].map(({ key, value, set, options, label }) => (
                <select
                  key={key}
                  value={value}
                  onChange={e => set(e.target.value)}
                  style={{
                    flex: 1, height: 30, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: 6, color: value ? '#e2e8f0' : '#475569', fontSize: 11, padding: '0 6px', outline: 'none'
                  }}
                >
                  {options.map(o => <option key={o} value={o} style={{ background: '#0f172a' }}>{o || label}</option>)}
                </select>
              ))}
              <button
                onClick={loadIncidents}
                title="Refresh"
                style={{
                  width: 30, height: 30, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: 6, color: '#64748b', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center'
                }}
              >
                <RefreshCw size={12} />
              </button>
            </div>
          </div>

          {/* List */}
          <div style={{ flex: 1, overflow: 'auto' }}>
            {loading ? <Spinner /> : filtered.length === 0 ? (
              <EmptyState icon={Shield} title="No incidents found" subtitle="Incidents appear when related alerts are correlated" />
            ) : filtered.map(inc => {
              const sev = getSeverityStyle(inc.severity);
              const sts = getStatusStyle(inc.status);
              const isActive = selected?.id === inc.id;
              return (
                <div
                  key={inc.id}
                  onClick={() => setSelected(inc)}
                  style={{
                    padding: '12px 14px', cursor: 'pointer', borderBottom: '1px solid rgba(255,255,255,0.04)',
                    background: isActive ? 'rgba(255,106,61,0.08)' : 'transparent',
                    borderLeft: isActive ? '3px solid #FF6A3D' : '3px solid transparent',
                    transition: 'background 0.15s'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <SeverityBadge severity={inc.severity} />
                      <span style={{ fontSize: 10, color: sts.text, background: sts.bg, borderRadius: 4, padding: '2px 6px' }}>
                        {sts.label}
                      </span>
                    </div>
                    <span style={{ fontSize: 10, color: '#475569' }}>{formatDate(inc.last_seen)}</span>
                  </div>
                  <div style={{ marginBottom: 5 }}>
                    <RiskBar score={inc.risk_score} />
                  </div>
                  <div style={{ display: 'flex', gap: 10, fontSize: 11, color: '#64748b' }}>
                    <span>🚨 {(inc.related_alerts || []).length}</span>
                    <span>🖥 {(inc.affected_ips || []).length}</span>
                    <span>🎯 {(inc.mitre_techniques || []).length}</span>
                    <span>👤 {(inc.affected_users || []).length}</span>
                  </div>
                  {(inc.correlation_reasons || []).length > 0 && (
                    <div style={{ fontSize: 10, color: '#475569', marginTop: 4 }}>
                      {inc.correlation_reasons.slice(0, 2).join(', ')}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right panel: incident detail */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <IncidentDetail
            incident={selected}
            onStatusChange={handleStatusChange}
          />
        </div>
      </div>
    </div>
  );
};

export default IncidentsPage;
