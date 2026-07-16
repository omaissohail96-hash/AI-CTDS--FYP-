import { useEffect, useState } from 'react';
import axios from 'axios';
import { CheckCircle, XCircle, Clock, ShieldCheck } from 'lucide-react';
import PageHeader from '../components/PageHeader';
import API_BASE from '../config/api';

const FeedbackDashboardPage = () => {
  const [stats, setStats] = useState({ total: 0, correct: 0, false_positives: 0, false_negatives: 0, approval_rate: 0, by_model: {} });
  const [items, setItems] = useState([]); const [status, setStatus] = useState('pending'); const [search, setSearch] = useState('');
  const load = async () => { 
      try { 
          const token = localStorage.getItem('token');
          const [s, f] = await Promise.all([
              axios.get(`${API_BASE}/feedback/stats`, { headers: { Authorization: `Bearer ${token}` } }), 
              axios.get(`${API_BASE}/feedback`, { params: { status, search }, headers: { Authorization: `Bearer ${token}` } })
          ]); 
          setStats(s.data); 
          setItems(f.data); 
      } catch (e) { 
          console.error('Unable to load feedback', e); 
      } 
  };
  useEffect(() => { load(); }, [status]);
  const action = async (id, verb) => { 
      const token = localStorage.getItem('token');
      await axios.put(`${API_BASE}/feedback/${id}/${verb}`, {}, { headers: { Authorization: `Bearer ${token}` } }); 
      load(); 
  };
  const cards = [['Total Feedback', stats.total, ShieldCheck], ['Correct Predictions', stats.correct, CheckCircle], ['False Positives', stats.false_positives, XCircle], ['False Negatives', stats.false_negatives, Clock]];
  return <div className="space-y-6">
    <PageHeader icon={ShieldCheck} iconColor="#36D399" title="AI Feedback Review" subtitle="Verified analyst feedback for offline model improvement. Production models never retrain automatically." badges={[]} />
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">{cards.map(([label, value, Icon]) => <div key={label} className="glass-card p-4"><Icon size={18} className="text-cyber-success mb-3"/><p className="text-xs text-gray-500 uppercase">{label}</p><p className="text-2xl font-bold text-white">{value}</p></div>)}</div>
    <div className="glass-card p-4 flex flex-wrap gap-3 items-center"><input className="input-field flex-1" placeholder="Search entity" value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && load()} />{['pending','approved','rejected'].map(v => <button key={v} onClick={() => setStatus(v)} className={status === v ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm'}>{v}</button>)}<span className="text-sm text-gray-400">Approval rate: {stats.approval_rate}%</span></div>
    <div className="glass-card overflow-hidden"><table className="w-full text-sm"><thead className="text-left text-gray-500 border-b border-white/10"><tr><th className="p-4">Entity</th><th>Prediction</th><th>Feedback</th><th>Status</th><th></th></tr></thead><tbody>{items.map(item => <tr key={item.id} className="border-b border-white/5 text-gray-300"><td className="p-4 font-mono">{item.entity}</td><td>{item.predicted_label} ({Math.round(item.confidence)}%)</td><td>{item.feedback_type}</td><td>{item.review_status}</td><td className="p-3 flex gap-2">{item.review_status === 'pending' && <><button onClick={() => action(item.id, 'approve')} className="btn btn-success btn-sm">Approve</button><button onClick={() => action(item.id, 'reject')} className="btn btn-danger btn-sm">Reject</button></>}</td></tr>)}</tbody></table>{items.length === 0 && <p className="p-8 text-center text-gray-500">No matching feedback.</p>}</div>
  </div>;
};
export default FeedbackDashboardPage;
