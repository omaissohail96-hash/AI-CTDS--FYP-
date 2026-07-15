import { useState } from 'react';
import axios from 'axios';
import API_BASE from '../config/api';

export default function FeedbackButtons({ scanId }) {
  const [type, setType] = useState(null); const [comments, setComments] = useState(''); const [done, setDone] = useState(false);
  const submit = async (feedback_type) => {
    try { await axios.post(`${API_BASE}/feedback`, { scan_id: scanId, feedback_type, comments: comments || null }, { withCredentials: true }); setDone(true); }
    catch (e) { alert(e.response?.data?.detail || 'Feedback could not be submitted.'); }
  };
  if (!scanId || done) return done ? <p className="text-xs text-cyber-success mt-3">Feedback submitted for analyst review.</p> : null;
  return <div className="mt-4 pt-3 border-t border-white/10"><p className="text-xs text-gray-400 mb-2">Was this prediction correct?</p><div className="flex flex-wrap gap-2"><button className="btn btn-success btn-sm" onClick={() => submit('correct')}>Correct prediction</button><button className="btn btn-danger btn-sm" onClick={() => setType(type ? null : 'incorrect')}>Incorrect prediction</button></div>{type && <div className="mt-3 flex flex-wrap gap-2"><button className="btn btn-secondary btn-sm" onClick={() => submit('false_positive')}>False positive</button><button className="btn btn-secondary btn-sm" onClick={() => submit('false_negative')}>False negative</button><button className="btn btn-secondary btn-sm" onClick={() => submit('wrong_category')}>Wrong category</button><input className="input-field text-xs" placeholder="Optional comment" value={comments} onChange={e => setComments(e.target.value)} /></div>}</div>;
}
