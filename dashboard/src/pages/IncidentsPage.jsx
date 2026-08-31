import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import {
  Network, Clock, Shield, RefreshCw,
  FileText, Target, Layers, GitBranch, Search,
} from 'lucide-react';
import API_BASE from '../config/api';
import PageHeader from '../components/PageHeader';

const SEVERITY_COLORS = {
  CRITICAL: { bg: 'rgba(239,68,68,0.15)', border: '#ef4444', text: '#f87171', dot: '#ef4444' },
  HIGH:     { bg: 'rgba(249,115,22,0.15)', border: '#f97316', text: '#fb923c', dot: '#f97316' },
  MEDIUM:   { bg: 'rgba(234,179,8,0.15)',  border: '#eab308', text: '#facc15', dot: '#eab308' },
  LOW:      { bg: 'rgba(34,197,94,0.12)',  border: '#22c55e', text: '#4ade80', dot: '#22c55e' },
};
const STATUS_STYLES = {
  OPEN:          { bg: 'rgba(239,68,68,0.12)',  text: '#f87171', label: 'Open' },
  INVESTIGATING: { bg: 'rgba(249,115,22,0.12)', text: '#fb923c', label: 'Investigating' },
  RESOLVED:      { bg: 'rgba(34,197,94,0.12)',  text: '#4ade80', label: 'Resolved' },
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
  INCIDENT:'INC', ALERT:'ALT', IP:'IP', URL:'URL', DOMAIN:'DOM',
  EMAIL:'EML', USER:'USR', MITRE_TECHNIQUE:'TTP', NETWORK_EVENT:'NET', default:'?',
};

const apiCall = (token) => ({
  get: (url) => axios.get(`${API_BASE}${url}`, { headers: { Authorization: `Bearer ${token}` } }),
});
const getSeverityStyle = (s) => SEVERITY_COLORS[(s||'LOW').toUpperCase()] || SEVERITY_COLORS.LOW;
const getStatusStyle   = (s) => STATUS_STYLES[(s||'OPEN').toUpperCase()] || STATUS_STYLES.OPEN;
const formatDate = (iso) => { if (!iso) return '-'; const d = new Date(iso); return d.toLocaleString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' }); };
const truncate = (str, n=28) => str && str.length > n ? str.slice(0,n)+'...' : (str||'');

const SeverityBadge = ({ severity }) => {
  const s = getSeverityStyle(severity);
  return <span style={{ background:s.bg, border:`1px solid ${s.border}`, color:s.text, borderRadius:6, padding:'2px 8px', fontSize:11, fontWeight:700 }}>{(severity||'LOW').toUpperCase()}</span>;
};
const StatusBadge = ({ status, onClick }) => {
  const s = getStatusStyle(status);
  return <span onClick={onClick} title={onClick?'Click to cycle status':undefined} style={{ background:s.bg, color:s.text, borderRadius:6, padding:'3px 10px', fontSize:11, fontWeight:700, cursor:onClick?'pointer':'default' }}>{s.label}</span>;
};
const RiskBar = ({ score }) => (
  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
    <div style={{ flex:1, height:4, background:'rgba(255,255,255,0.08)', borderRadius:4, overflow:'hidden' }}>
      <div style={{ height:'100%', width:`${score}%`, borderRadius:4, background: score>=80?'#ef4444':score>=60?'#f97316':score>=40?'#eab308':'#22c55e', transition:'width 0.4s ease' }} />
    </div>
    <span style={{ fontSize:11, color:'#94a3b8', minWidth:28 }}>{score}</span>
  </div>
);
const Spinner = () => (
  <div style={{ display:'flex', justifyContent:'center', padding:'40px 0' }}>
    <div style={{ width:28, height:28, border:'3px solid rgba(255,255,255,0.1)', borderTopColor:'#FF6A3D', borderRadius:'50%', animation:'spin 0.8s linear infinite' }} />
  </div>
);
const EmptyState = ({ icon: Icon, title, subtitle }) => (
  <div style={{ textAlign:'center', padding:'48px 24px', color:'#475569' }}>
    <Icon size={36} style={{ margin:'0 auto 12px', opacity:0.4 }} />
    <div style={{ color:'#64748b', fontWeight:600, marginBottom:4 }}>{title}</div>
    {subtitle && <div style={{ fontSize:13, opacity:0.7 }}>{subtitle}</div>}
  </div>
);

const AttackGraph = ({ nodes, edges }) => {
  const canvasRef = useRef(null);
  const animRef   = useRef(null);
  const stateRef  = useRef({ nodes:[], dragging:null, offsetX:0, offsetY:0 });
  const W=800, H=440;

  useEffect(() => {
    if (!nodes||!nodes.length) return;
    const cx=W/2, cy=H/2;
    stateRef.current.nodes = nodes.map((n,i) => {
      const angle = (2*Math.PI*i)/nodes.length;
      const r = Math.min(W,H)*0.32;
      return { ...n, x:cx+r*Math.cos(angle), y:cy+r*Math.sin(angle), vx:0, vy:0, radius:n.type==='INCIDENT'?30:20 };
    });
  }, [nodes]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas||!nodes||!nodes.length) return;
    const ctx = canvas.getContext('2d');
    const tick = () => {
      const { nodes:ns } = stateRef.current;
      for (let i=0;i<ns.length;i++) for (let j=i+1;j<ns.length;j++) {
        const dx=ns[j].x-ns[i].x, dy=ns[j].y-ns[i].y;
        const dist=Math.sqrt(dx*dx+dy*dy)||1;
        const f=2800/(dist*dist);
        ns[i].vx-=(dx/dist)*f; ns[i].vy-=(dy/dist)*f;
        ns[j].vx+=(dx/dist)*f; ns[j].vy+=(dy/dist)*f;
      }
      (edges||[]).forEach(e => {
        const s=ns.find(n=>n.id===e.source), t=ns.find(n=>n.id===e.target);
        if (!s||!t) return;
        const dx=t.x-s.x, dy=t.y-s.y, dist=Math.sqrt(dx*dx+dy*dy)||1, str=0.04*(dist-120);
        s.vx+=(dx/dist)*str; s.vy+=(dy/dist)*str; t.vx-=(dx/dist)*str; t.vy-=(dy/dist)*str;
      });
      ns.forEach(n => {
        if (n===stateRef.current.dragging) return;
        n.vx+=(W/2-n.x)*0.008; n.vy+=(H/2-n.y)*0.008;
        n.vx*=0.82; n.vy*=0.82; n.x+=n.vx; n.y+=n.vy;
      });
      ctx.clearRect(0,0,W,H);
      (edges||[]).forEach(e => {
        const s=ns.find(n=>n.id===e.source), t=ns.find(n=>n.id===e.target);
        if (!s||!t) return;
        ctx.beginPath(); ctx.moveTo(s.x,s.y); ctx.lineTo(t.x,t.y);
        ctx.strokeStyle='rgba(99,102,241,0.35)'; ctx.lineWidth=1.5; ctx.stroke();
        const ang=Math.atan2(t.y-s.y,t.x-s.x);
        const ex=t.x-(t.radius+4)*Math.cos(ang), ey=t.y-(t.radius+4)*Math.sin(ang);
        ctx.beginPath(); ctx.moveTo(ex,ey);
        ctx.lineTo(ex-9*Math.cos(ang-0.4),ey-9*Math.sin(ang-0.4));
        ctx.lineTo(ex-9*Math.cos(ang+0.4),ey-9*Math.sin(ang+0.4));
        ctx.closePath(); ctx.fillStyle='rgba(99,102,241,0.6)'; ctx.fill();
        ctx.font='9px sans-serif'; ctx.fillStyle='rgba(148,163,184,0.7)'; ctx.textAlign='center';
        ctx.fillText(e.type,(s.x+t.x)/2,(s.y+t.y)/2-5);
      });
      ns.forEach(n => {
        const c=NODE_COLORS[n.type]||NODE_COLORS.default;
        ctx.beginPath(); ctx.arc(n.x,n.y,n.radius,0,2*Math.PI);
        ctx.fillStyle=c.bg; ctx.fill(); ctx.strokeStyle=c.border; ctx.lineWidth=2; ctx.stroke();
        ctx.font='bold 8px sans-serif'; ctx.textAlign='center'; ctx.textBaseline='middle';
        ctx.fillStyle='#e2e8f0'; ctx.fillText(NODE_ICONS[n.type]||'?',n.x,n.y);
        ctx.font='10px sans-serif'; ctx.fillStyle='#cbd5e1';
        ctx.fillText(truncate(n.label,16),n.x,n.y+n.radius+12);
      });
      animRef.current = requestAnimationFrame(tick);
    };
    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [nodes, edges]);

  const onMouseDown = (e) => {
    const rect=canvasRef.current.getBoundingClientRect();
    const mx=e.clientX-rect.left, my=e.clientY-rect.top;
    const hit=stateRef.current.nodes.find(n=>Math.hypot(n.x-mx,n.y-my)<n.radius+4);
    if (hit) { stateRef.current.dragging=hit; stateRef.current.offsetX=hit.x-mx; stateRef.current.offsetY=hit.y-my; }
  };
  const onMouseMove = (e) => {
    const s=stateRef.current; if (!s.dragging) return;
    const rect=canvasRef.current.getBoundingClientRect();
    s.dragging.x=(e.clientX-rect.left)+s.offsetX; s.dragging.y=(e.clientY-rect.top)+s.offsetY;
    s.dragging.vx=0; s.dragging.vy=0;
  };
  const onMouseUp = () => { stateRef.current.dragging=null; };

  if (!nodes||!nodes.length) return <EmptyState icon={Network} title="No graph data" subtitle="Graph populates as threats are detected" />;
  return (
    <div style={{ position:'relative', background:'rgba(0,0,0,0.3)', borderRadius:10, overflow:'hidden' }}>
      <div style={{ position:'absolute', top:8, right:10, fontSize:11, color:'#475569', zIndex:1 }}>
        Drag nodes | {nodes.length} nodes | {(edges||[]).length} edges
      </div>
      <canvas ref={canvasRef} width={W} height={H} style={{ width:'100%', display:'block', cursor:'grab' }}
        onMouseDown={onMouseDown} onMouseMove={onMouseMove} onMouseUp={onMouseUp} onMouseLeave={onMouseUp} />
    </div>
  );
};

const TimelineView = ({ events }) => {
  if (!events||!events.length) return <EmptyState icon={Clock} title="No timeline events" subtitle="Events appear as threats are detected" />;
  return (
    <div style={{ position:'relative', paddingLeft:28 }}>
      <div style={{ position:'absolute', left:10, top:0, bottom:0, width:2, background:'rgba(99,102,241,0.25)', borderRadius:2 }} />
      {events.map((ev,i) => {
        const sev=getSeverityStyle(ev.severity);
        return (
          <div key={i} style={{ position:'relative', marginBottom:20 }}>
            <div style={{ position:'absolute', left:-22, top:5, width:12, height:12, borderRadius:'50%', background:sev.dot, boxShadow:`0 0 8px ${sev.dot}60` }} />
            <div style={{ background:'rgba(255,255,255,0.03)', border:'1px solid rgba(255,255,255,0.07)', borderRadius:8, padding:'10px 14px' }}>
              <div style={{ display:'flex', justifyContent:'space-between', flexWrap:'wrap', gap:6, marginBottom:6 }}>
                <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
                  <span style={{ fontSize:12, fontWeight:700, color:'#e2e8f0' }}>{ev.event_type}</span>
                  <SeverityBadge severity={ev.severity} />
                  {ev.mitre_technique && <span style={{ background:'rgba(99,102,241,0.15)', border:'1px solid rgba(99,102,241,0.3)', color:'#a5b4fc', borderRadius:4, padding:'1px 6px', fontSize:10 }}>{ev.mitre_technique}</span>}
                </div>
                <span style={{ fontSize:11, color:'#64748b', whiteSpace:'nowrap' }}>{formatDate(ev.timestamp)}</span>
              </div>
              <div style={{ fontSize:12, color:'#94a3b8', marginBottom:4 }}>
                <span style={{ color:'#64748b' }}>Entity: </span>{ev.entity}
                <span style={{ color:'#64748b', marginLeft:10 }}>Source: </span>{ev.source}
                <span style={{ color:'#64748b', marginLeft:10 }}>Risk: </span><span style={{ color:sev.text }}>{ev.risk_score}</span>
              </div>
              {ev.correlation_reason && <div style={{ fontSize:11, color:'#475569', fontStyle:'italic' }}>{ev.correlation_reason}</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
};

const EvidencePanel = ({ evidence }) => {
  const importanceColors = { HIGH:'#ef4444', MEDIUM:'#f97316', LOW:'#22c55e' };
  if (!evidence||!evidence.length) return <EmptyState icon={FileText} title="No evidence collected" subtitle="Evidence is gathered automatically from detections" />;
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
      {evidence.map((ev,i) => (
        <div key={i} style={{ background:'rgba(255,255,255,0.025)', border:'1px solid rgba(255,255,255,0.07)', borderLeft:`3px solid ${importanceColors[ev.importance]||'#475569'}`, borderRadius:8, padding:'10px 14px' }}>
          <div style={{ display:'flex', justifyContent:'space-between', flexWrap:'wrap', gap:6, marginBottom:5 }}>
            <span style={{ fontSize:12, fontWeight:700, color:'#e2e8f0' }}>{ev.evidence_type}</span>
            <div style={{ display:'flex', gap:6, alignItems:'center' }}>
              <span style={{ fontSize:10, color:'#64748b', background:'rgba(255,255,255,0.05)', borderRadius:4, padding:'1px 6px' }}>{ev.source}</span>
              <span style={{ fontSize:10, color:'#64748b' }}>Conf: {ev.confidence}%</span>
              <span style={{ fontSize:11, color:'#64748b' }}>{formatDate(ev.timestamp)}</span>
            </div>
          </div>
          <div style={{ fontSize:12, color:'#94a3b8', marginBottom:ev.value_indicator?5:0 }}>{ev.description}</div>
          {ev.value_indicator && <div style={{ fontSize:11, color:'#7dd3fc', fontFamily:'monospace', background:'rgba(0,0,0,0.3)', borderRadius:4, padding:'3px 8px', display:'inline-block' }}>{ev.value_indicator}</div>}
        </div>
      ))}
    </div>
  );
};

const AttackPath = ({ steps }) => {
  if (!steps||!steps.length) return <EmptyState icon={GitBranch} title="No attack path" subtitle="Path is reconstructed from correlated events" />;
  return (
    <div>
      {steps.map((step,i) => (
        <div key={i} style={{ display:'flex', gap:0 }}>
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', width:36 }}>
            <div style={{ width:28, height:28, borderRadius:'50%', background:'rgba(99,102,241,0.2)', border:'2px solid rgba(99,102,241,0.5)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:11, fontWeight:700, color:'#a5b4fc', flexShrink:0 }}>{step.step}</div>
            {i<steps.length-1 && <div style={{ width:2, flex:1, minHeight:20, background:'rgba(99,102,241,0.2)', margin:'2px 0' }} />}
          </div>
          <div style={{ flex:1, paddingBottom:14, paddingLeft:10, paddingTop:2 }}>
            <div style={{ fontSize:12, fontWeight:700, color:'#e2e8f0', marginBottom:2 }}>{step.label}</div>
            <div style={{ fontSize:11, color:'#64748b', marginBottom:2 }}>{step.description}</div>
            <div style={{ fontSize:10, color:'#475569' }}>{formatDate(step.timestamp)}</div>
          </div>
        </div>
      ))}
    </div>
  );
};

const MitreTechniques = ({ techniques }) => {
  if (!techniques||!techniques.length) return <EmptyState icon={Target} title="No MITRE techniques" subtitle="Technique mappings are inferred from scan results" />;
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
      {techniques.map((t,i) => (
        <div key={i} style={{ background:'rgba(99,102,241,0.08)', border:'1px solid rgba(99,102,241,0.2)', borderRadius:8, padding:'10px 14px', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <div>
            <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:4 }}>
              <span style={{ fontSize:11, fontFamily:'monospace', color:'#a5b4fc', fontWeight:700 }}>{t.technique_id}</span>
              <span style={{ fontSize:12, color:'#e2e8f0', fontWeight:600 }}>{t.technique}</span>
            </div>
            <div style={{ fontSize:11, color:'#64748b' }}>Tactic: {t.tactic} | Seen {t.count}x</div>
          </div>
          <div style={{ textAlign:'right' }}>
            <div style={{ fontSize:16, fontWeight:800, color:t.max_risk_score>=80?'#ef4444':'#fb923c' }}>{t.max_risk_score}</div>
            <div style={{ fontSize:10, color:'#475569' }}>risk</div>
          </div>
        </div>
      ))}
    </div>
  );
};

const TABS = [
  { id:'graph',    label:'Attack Graph',  Icon: Network },
  { id:'timeline', label:'Timeline',      Icon: Clock },
  { id:'evidence', label:'Evidence',      Icon: FileText },
  { id:'path',     label:'Attack Path',   Icon: GitBranch },
  { id:'mitre',    label:'MITRE ATT&CK',  Icon: Target },
];

const IncidentDetail = ({ incident, onStatusChange }) => {
  const [activeTab, setActiveTab]           = useState('graph');
  const [tabData, setTabData]               = useState({});
  const [loading, setLoading]               = useState(false);
  const [statusChanging, setStatusChanging] = useState(false);
  const prevId = useRef(null);

  const fetchTab = useCallback(async (tab) => {
    if (!incident) return;
    const token = localStorage.getItem('token');
    const endpoints = {
      graph:    `/incidents/${incident.id}/graph`,
      timeline: `/incidents/${incident.id}/timeline`,
      evidence: `/incidents/${incident.id}/evidence`,
      path:     `/incidents/${incident.id}/attack-path`,
      mitre:    `/incidents/${incident.id}/mitre`,
    };
    setLoading(true);
    try {
      const res = await apiCall(token).get(endpoints[tab]);
      setTabData(prev => ({ ...prev, [tab]: res.data }));
    } catch (err) { console.error('Tab fetch error:', err); }
    finally { setLoading(false); }
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

  useEffect(() => { if (!tabData[activeTab] && incident) fetchTab(activeTab); }, [activeTab, tabData, incident, fetchTab]);

  const cycleStatus = async () => {
    const cycle = { OPEN:'INVESTIGATING', INVESTIGATING:'RESOLVED', RESOLVED:'OPEN' };
    const next = cycle[incident.status] || 'OPEN';
    setStatusChanging(true);
    try {
      const token = localStorage.getItem('token');
      await axios.put(`${API_BASE}/incidents/${incident.id}/status`, { status: next }, { headers: { Authorization: `Bearer ${token}` } });
      onStatusChange(incident.id, next);
    } catch (err) { console.error('Status update failed:', err); }
    finally { setStatusChanging(false); }
  };

  if (!incident) return (
    <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center', color:'#475569' }}>
      <div style={{ textAlign:'center' }}>
        <Shield size={40} style={{ margin:'0 auto 12px', opacity:0.3 }} />
        <div style={{ fontWeight:600, marginBottom:4 }}>Select an incident</div>
        <div style={{ fontSize:13 }}>Choose an incident from the list to investigate</div>
      </div>
    </div>
  );

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
    <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
      <div style={{ padding:'16px 20px', borderBottom:'1px solid rgba(255,255,255,0.07)', background:'rgba(0,0,0,0.2)' }}>
        <div style={{ display:'flex', justifyContent:'space-between', flexWrap:'wrap', gap:10, marginBottom:8 }}>
          <div>
            <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:6, flexWrap:'wrap' }}>
              <span style={{ fontSize:11, color:'#475569', fontFamily:'monospace' }}>{incident.id.slice(0,8)}...</span>
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} onClick={cycleStatus} />
              {statusChanging && <span style={{ fontSize:11, color:'#64748b' }}>Updating...</span>}
            </div>
            <div style={{ fontSize:14, color:'#94a3b8' }}>
              First seen: {formatDate(incident.first_seen)} | Last seen: {formatDate(incident.last_seen)}
            </div>
          </div>
          <div style={{ display:'flex', gap:16, flexWrap:'wrap' }}>
            {[{label:'Risk',value:incident.risk_score},{label:'Conf.',value:`${incident.confidence}%`},{label:'Alerts',value:(incident.related_alerts||[]).length},{label:'MITRE',value:(incident.mitre_techniques||[]).length}].map(({label,value}) => (
              <div key={label} style={{ textAlign:'center' }}>
                <div style={{ fontSize:18, fontWeight:800, color:'#f1f5f9' }}>{value}</div>
                <div style={{ fontSize:10, color:'#64748b' }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
        <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
          {(incident.affected_ips||[]).map(ip => <span key={ip} style={{ background:'rgba(14,165,233,0.1)', border:'1px solid rgba(14,165,233,0.25)', color:'#38bdf8', borderRadius:4, padding:'2px 8px', fontSize:11 }}>IP: {ip}</span>)}
          {(incident.affected_urls_domains||[]).map(u => <span key={u} style={{ background:'rgba(34,197,94,0.08)', border:'1px solid rgba(34,197,94,0.2)', color:'#4ade80', borderRadius:4, padding:'2px 8px', fontSize:11 }}>URL: {truncate(u,30)}</span>)}
          {(incident.mitre_techniques||[]).map(t => <span key={t} style={{ background:'rgba(99,102,241,0.12)', border:'1px solid rgba(99,102,241,0.3)', color:'#a5b4fc', borderRadius:4, padding:'2px 8px', fontSize:11 }}>TTP: {t}</span>)}
        </div>
      </div>
      <div style={{ display:'flex', borderBottom:'1px solid rgba(255,255,255,0.07)', background:'rgba(0,0,0,0.1)', overflowX:'auto' }}>
        {TABS.map(({ id, label, Icon }) => (
          <button key={id} onClick={() => setActiveTab(id)} style={{ display:'flex', alignItems:'center', gap:6, padding:'10px 16px', background:'none', border:'none', borderBottom:activeTab===id?'2px solid #FF6A3D':'2px solid transparent', color:activeTab===id?'#FF6A3D':'#64748b', cursor:'pointer', fontSize:12, fontWeight:600, whiteSpace:'nowrap', transition:'color 0.15s' }}>
            <Icon size={13} />{label}
          </button>
        ))}
      </div>
      <div style={{ flex:1, overflow:'auto', padding:'16px 20px' }}>{renderTabContent()}</div>
    </div>
  );
};

const IncidentsPage = () => {
  const [incidents, setIncidents]         = useState([]);
  const [selected, setSelected]           = useState(null);
  const [total, setTotal]                 = useState(0);
  const [loading, setLoading]             = useState(false);
  const [search, setSearch]               = useState('');
  const [filterStatus, setFilterStatus]   = useState('');
  const [filterSev, setFilterSev]         = useState('');

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams({ limit:'100' });
      if (filterStatus) params.append('status', filterStatus);
      if (filterSev)    params.append('severity', filterSev);
      const res = await apiCall(token).get(`/incidents?${params.toString()}`);
      const list = res.data.incidents || [];
      setIncidents(list);
      setTotal(res.data.total || 0);
      if (list.length && !selected) setSelected(list[0]);
    } catch (err) { console.error('Failed to load incidents:', err); }
    finally { setLoading(false); }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterStatus, filterSev]);

  useEffect(() => { loadIncidents(); }, [loadIncidents]);

  const handleStatusChange = (id, newStatus) => {
    setIncidents(prev => prev.map(inc => inc.id===id ? {...inc, status:newStatus} : inc));
    if (selected?.id===id) setSelected(prev => ({...prev, status:newStatus}));
  };

  const filtered = incidents.filter(inc =>
    !search ||
    inc.id.toLowerCase().includes(search.toLowerCase()) ||
    (inc.affected_ips||[]).some(ip => ip.includes(search)) ||
    (inc.mitre_techniques||[]).some(t => t.toLowerCase().includes(search.toLowerCase())) ||
    inc.severity.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ height:'100%', display:'flex', flexDirection:'column' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <PageHeader icon={Layers} title="Incident Stories" subtitle={`${total} correlated attack campaign${total!==1?'s':''} across all vectors`} />
      <div style={{ flex:1, display:'flex', overflow:'hidden', minHeight:0 }}>
        <div style={{ width:310, flexShrink:0, borderRight:'1px solid rgba(255,255,255,0.07)', display:'flex', flexDirection:'column', background:'rgba(0,0,0,0.15)' }}>
          <div style={{ padding:'12px 14px', borderBottom:'1px solid rgba(255,255,255,0.07)', display:'flex', flexDirection:'column', gap:8 }}>
            <div style={{ position:'relative' }}>
              <Search size={13} style={{ position:'absolute', left:9, top:'50%', transform:'translateY(-50%)', color:'#475569' }} />
              <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search incidents..." style={{ width:'100%', boxSizing:'border-box', paddingLeft:28, paddingRight:10, height:32, background:'rgba(255,255,255,0.05)', border:'1px solid rgba(255,255,255,0.1)', borderRadius:6, color:'#e2e8f0', fontSize:12, outline:'none' }} />
            </div>
            <div style={{ display:'flex', gap:6 }}>
              {[{key:'status',value:filterStatus,set:setFilterStatus,options:['','OPEN','INVESTIGATING','RESOLVED'],label:'Status'},{key:'sev',value:filterSev,set:setFilterSev,options:['','CRITICAL','HIGH','MEDIUM','LOW'],label:'Severity'}].map(({key,value,set,options,label}) => (
                <select key={key} value={value} onChange={e=>set(e.target.value)} style={{ flex:1, height:30, background:'rgba(255,255,255,0.05)', border:'1px solid rgba(255,255,255,0.1)', borderRadius:6, color:value?'#e2e8f0':'#475569', fontSize:11, padding:'0 6px', outline:'none' }}>
                  {options.map(o => <option key={o} value={o} style={{ background:'#0f172a' }}>{o||label}</option>)}
                </select>
              ))}
              <button onClick={loadIncidents} title="Refresh" style={{ width:30, height:30, background:'rgba(255,255,255,0.05)', border:'1px solid rgba(255,255,255,0.1)', borderRadius:6, color:'#64748b', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center' }}>
                <RefreshCw size={12} />
              </button>
            </div>
          </div>
          <div style={{ flex:1, overflowY:'auto' }}>
            {loading ? <Spinner /> : filtered.length===0 ? (
              <EmptyState icon={Shield} title="No incidents found" subtitle="Incidents appear when related alerts are correlated" />
            ) : filtered.map(inc => {
              const sts=getStatusStyle(inc.status);
              const isActive=selected?.id===inc.id;
              return (
                <div key={inc.id} onClick={()=>setSelected(inc)} style={{ padding:'12px 14px', cursor:'pointer', borderBottom:'1px solid rgba(255,255,255,0.04)', background:isActive?'rgba(255,106,61,0.08)':'transparent', borderLeft:isActive?'3px solid #FF6A3D':'3px solid transparent', transition:'background 0.15s' }}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:5 }}>
                    <div style={{ display:'flex', gap:6 }}>
                      <SeverityBadge severity={inc.severity} />
                      <span style={{ fontSize:10, color:sts.text, background:sts.bg, borderRadius:4, padding:'2px 6px' }}>{sts.label}</span>
                    </div>
                    <span style={{ fontSize:10, color:'#475569' }}>{formatDate(inc.last_seen)}</span>
                  </div>
                  <div style={{ marginBottom:5 }}><RiskBar score={inc.risk_score} /></div>
                  <div style={{ display:'flex', gap:10, fontSize:11, color:'#64748b' }}>
                    <span>Alerts: {(inc.related_alerts||[]).length}</span>
                    <span>IPs: {(inc.affected_ips||[]).length}</span>
                    <span>TTPs: {(inc.mitre_techniques||[]).length}</span>
                    <span>Users: {(inc.affected_users||[]).length}</span>
                  </div>
                  {(inc.correlation_reasons||[]).length>0 && <div style={{ fontSize:10, color:'#475569', marginTop:4 }}>{inc.correlation_reasons.slice(0,2).join(', ')}</div>}
                </div>
              );
            })}
          </div>
        </div>
        <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
          <IncidentDetail incident={selected} onStatusChange={handleStatusChange} />
        </div>
      </div>
    </div>
  );
};

export default IncidentsPage;