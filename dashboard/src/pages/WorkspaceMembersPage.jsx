import { useEffect, useState } from 'react'
import axios from 'axios'
import { ShieldCheck, UserPlus, Trash2, RefreshCw, Users, CheckCircle, ChevronDown } from 'lucide-react'
import API_BASE from '../config/api'
import PageHeader from '../components/PageHeader'
import { useAuth } from '../context/AuthContext'

const roleOptions = ['admin', 'analyst', 'operator', 'viewer']

const RoleSelect = ({ value, onChange, roles, compact = false }) => (
  <div className={`workspace-role-select${compact ? ' workspace-role-select--compact' : ''}`}>
    <select value={value} onChange={onChange} aria-label="Workspace role">
      {roles.map((role) => <option key={role} value={role}>{role}</option>)}
    </select>
    <ChevronDown size={14} aria-hidden="true" />
  </div>
)

const WorkspaceMembersPage = () => {
  const { user, hasPermission } = useAuth()
  const [members, setMembers] = useState([])
  const [email, setEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('viewer')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const canManage = hasPermission('workspace:members:manage')
  const headers = { Authorization: `Bearer ${localStorage.getItem('token')}` }

  const loadMembers = async () => {
    setLoading(true)
    setError('')
    try {
      const response = await axios.get(`${API_BASE}/workspace/members`, { headers })
      setMembers(response.data.members || [])
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to load workspace members.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadMembers() }, [])

  const invite = async (event) => {
    event.preventDefault()
    setSaving(true)
    setError('')
    try {
      await axios.post(`${API_BASE}/workspace/invite`, { email, role: inviteRole }, { headers })
      setEmail('')
      setInviteRole('viewer')
      await loadMembers()
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to invite this user.')
    } finally {
      setSaving(false)
    }
  }

  const changeRole = async (memberId, role) => {
    try {
      await axios.patch(`${API_BASE}/workspace/member/${memberId}/role`, { role }, { headers })
      await loadMembers()
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to change this role.')
    }
  }

  const approveMember = async (memberId, role) => {
    try {
      await axios.post(`${API_BASE}/workspace/member/${memberId}/approve`, { role }, { headers })
      await loadMembers()
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to approve this member.')
    }
  }

  const removeMember = async (member) => {
    if (!window.confirm(`Remove ${member.email} from this workspace?`)) return
    try {
      await axios.delete(`${API_BASE}/workspace/member/${member.id}`, { headers })
      await loadMembers()
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to remove this member.')
    }
  }

  const availableRoles = user?.role === 'admin' ? roleOptions.filter((role) => role !== 'admin') : roleOptions

  return (
    <div className="space-y-6">
      <PageHeader icon={Users} title="Workspace Members" subtitle="Manage workspace access and security roles" />
      {canManage && (
        <form onSubmit={invite} className="glass-card p-5 flex flex-col md:flex-row gap-3">
          <input className="glass-input flex-1" type="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="member@company.com" />
          <RoleSelect value={inviteRole} onChange={(event) => setInviteRole(event.target.value)} roles={availableRoles} />
          <button className="btn btn-primary" disabled={saving} type="submit">
            {saving ? <RefreshCw size={15} className="animate-spin" /> : <UserPlus size={15} />} Invite member
          </button>
        </form>
      )}
      {error && <div className="glass-card p-4 text-sm text-red-300">{error}</div>}
      <div className="glass-card overflow-hidden">
        <div className="p-5 border-b border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-2 text-white font-semibold"><ShieldCheck size={17} /> Members</div>
          <button className="btn-action" onClick={loadMembers} title="Refresh members"><RefreshCw size={14} /></button>
        </div>
        {loading ? <div className="p-8 text-sm text-slate-400">Loading members...</div> : (
          <div className="overflow-x-auto"><table className="glass-table"><thead><tr><th>Member</th><th>Role</th><th>Joined</th><th>Status</th>{canManage && <th className="text-right">Actions</th>}</tr></thead>
            <tbody>{members.map((member) => {
              const isCurrentUser = member.user_id === user?.user_id
              const canEdit = canManage && !isCurrentUser && member.role !== 'owner'
              return <tr key={member.id}><td><div className="font-semibold text-white">{member.name || 'Unnamed user'}</div><div className="text-xs text-slate-400">{member.email}</div></td>
                <td>{canEdit ? <RoleSelect compact value={member.role} onChange={(event) => member.status === 'pending' ? approveMember(member.id, event.target.value) : changeRole(member.id, event.target.value)} roles={availableRoles} /> : <span className="badge badge-info">{member.role}</span>}</td>
                <td className="text-xs">{member.joined_at ? new Date(member.joined_at).toLocaleDateString() : '-'}</td><td><span className="badge badge-success">{member.status}</span></td>
                {canManage && <td className="text-right">{canEdit && member.status === 'pending' && <button className="btn-action" onClick={() => approveMember(member.id, member.role)} title="Approve member"><CheckCircle size={14} /></button>}{canEdit && <button className="btn-action danger" onClick={() => removeMember(member)} title="Remove member"><Trash2 size={14} /></button>}</td>}</tr>
            })}</tbody></table></div>
        )}
      </div>
    </div>
  )
}

export default WorkspaceMembersPage
