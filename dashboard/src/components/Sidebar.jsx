import { motion } from 'framer-motion';
import {
  LayoutDashboard, Globe, Mail, Activity, ShieldAlert, Settings, LogOut,
  Shield, AlertCircle, Lock, Search, BrainCircuit, ActivitySquare,
  CheckSquare, Network, Crosshair, ChevronRight, Zap, User, MapPin, Users
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const navGroups = [
  {
    label: 'Overview',
    items: [
      { id: 'dashboard',    label: 'Dashboard',      icon: LayoutDashboard, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'health',       label: 'System Health',  icon: ActivitySquare, roles: ['super_admin', 'workspace_admin'] },
      { id: 'monitoring',   label: 'Monitoring',     icon: Activity, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'alerts',       label: 'Alert Center',   icon: AlertCircle, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'review_queue', label: 'Review Queue',   icon: CheckSquare, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'feedback',     label: 'AI Feedback',    icon: BrainCircuit, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
    ]
  },
  {
    label: 'Detection',
    items: [
      { id: 'hunting',    label: 'Threat Hunting',  icon: Crosshair, roles: ['super_admin', 'workspace_admin', 'security_analyst'] },
      { id: 'uba',        label: 'User Behavior',   icon: BrainCircuit, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'prevention', label: 'Prevention',      icon: Lock, roles: ['super_admin', 'workspace_admin', 'security_analyst'] },
    ]
  },
  {
    label: 'Scanners',
    items: [
      { id: 'url',     label: 'URL Scanner',    icon: Globe, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'email',   label: 'Email Scanner',  icon: Mail, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'network', label: 'Network IDS',    icon: Network, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'web',     label: 'Web Attack',     icon: ShieldAlert, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
    ]
  },
  {
    label: 'System',
    items: [
      { id: 'ip_tracking', label: 'IP Tracking', icon: MapPin, roles: ['super_admin', 'workspace_admin', 'security_analyst', 'viewer'] },
      { id: 'members', label: 'Members', icon: Users, roles: ['owner', 'admin'] },
      { id: 'settings', label: 'Settings & API', icon: Settings, roles: ['super_admin', 'workspace_admin'] },
    ]
  }
];

const Sidebar = ({ activeTab, setActiveTab, onLogout, isOpen, onClose }) => {
  const { user, hasRole } = useAuth();
  return (
    <>
      <div
        className={`sidebar-overlay ${isOpen ? 'open' : ''}`}
        onClick={onClose}
        aria-hidden="true"
      />
      <aside className={`sidebar ${isOpen ? 'sidebar-open' : ''}`} style={{
      position: 'fixed',
      top: 0,
      left: 0,
      width: 'var(--sidebar-width, 260px)',
      height: '100vh',
      background: '#0C0D10',
      borderRight: '1px solid rgba(255,255,255,0.055)',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 100,
      overflowY: 'auto',
    }}>

      {/* ── Logo ── */}
      <div style={{
        padding: '22px 18px 18px',
        borderBottom: '1px solid rgba(255,255,255,0.055)',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
      }}>
        <motion.div
          whileHover={{ scale: 1.05 }}
          style={{
            width: '38px', height: '38px', borderRadius: '12px',
            background: 'linear-gradient(135deg, #FF6A3D, #FF8C42)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 24px rgba(255,106,61,0.45)',
            flexShrink: 0,
            cursor: 'default',
          }}>
          <Shield size={18} color="white" />
        </motion.div>
        <div>
          <div style={{ fontSize: '0.875rem', fontWeight: 800, color: '#F8FAFC', lineHeight: 1.2, letterSpacing: '-0.01em' }}>CyberGuard</div>
          <div style={{ fontSize: '0.65rem', color: '#FF8C42', fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase' }}>AI Platform</div>
        </div>
      </div>

      {/* ── Nav Groups ── */}
      <nav style={{ flex: 1, padding: '14px 10px', overflowY: 'auto' }}>
        {navGroups.map((group) => {
          const visibleItems = group.items.filter(item => hasRole(item.roles));
          if (visibleItems.length === 0) return null;
          return (
          <div key={group.label} style={{ marginBottom: '6px' }}>
            <div style={{
              fontSize: '0.62rem', fontWeight: 800, color: '#334155',
              textTransform: 'uppercase', letterSpacing: '0.12em',
              padding: '10px 12px 4px',
            }}>
              {group.label}
            </div>
            {visibleItems.map(({ id, label, icon: Icon }) => {
              const isActive = activeTab === id;
              return (
                <motion.button
                  key={id}
                  onClick={() => { setActiveTab(id); onClose?.(); }}
                  whileHover={{ x: 3 }}
                  whileTap={{ scale: 0.97 }}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    padding: '10px 12px',
                    borderRadius: '12px',
                    border: 'none',
                    cursor: 'pointer',
                    textAlign: 'left',
                    marginBottom: '2px',
                    transition: 'all 0.15s ease',
                    background: isActive
                      ? 'linear-gradient(135deg, rgba(255,106,61,0.18), rgba(255,140,66,0.09))'
                      : 'transparent',
                    color: isActive ? '#FF6A3D' : '#64748B',
                    fontFamily: 'Inter, sans-serif',
                    fontSize: '0.845rem',
                    fontWeight: isActive ? 700 : 500,
                    position: 'relative',
                    boxShadow: isActive ? '0 0 0 1px rgba(255,106,61,0.22) inset' : 'none',
                  }}
                >
                  {/* Active indicator bar */}
                  {isActive && (
                    <div style={{
                      position: 'absolute', left: 0, top: '50%', transform: 'translateY(-50%)',
                      width: '3px', height: '20px',
                      background: 'linear-gradient(180deg, #FF6A3D, #FF8C42)',
                      borderRadius: '0 3px 3px 0',
                      boxShadow: '0 0 8px rgba(255,106,61,0.6)',
                    }} />
                  )}
                  <Icon
                    size={17}
                    style={{
                      color: isActive ? '#FF6A3D' : '#475569',
                      flexShrink: 0,
                      filter: isActive ? 'drop-shadow(0 0 6px rgba(255,106,61,0.55))' : 'none',
                    }}
                  />
                  <span style={{ flex: 1 }}>{label}</span>
                  {isActive && <ChevronRight size={13} style={{ color: '#FF6A3D', opacity: 0.7 }} />}
                </motion.button>
              );
            })}
          </div>
          );
        })}
      </nav>

      {/* ── Footer ── */}
      <div style={{
        padding: '12px 10px 14px',
        borderTop: '1px solid rgba(255,255,255,0.055)',
      }}>
        {/* Live status */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '8px 12px', marginBottom: '4px',
        }}>
          <div style={{ position: 'relative', width: '8px', height: '8px', flexShrink: 0 }}>
            <div style={{
              width: '8px', height: '8px', borderRadius: '50%',
              background: '#36D399',
              boxShadow: '0 0 8px rgba(54,211,153,0.8)',
              position: 'absolute',
            }} />
            <div style={{
              width: '8px', height: '8px', borderRadius: '50%',
              background: '#36D399', opacity: 0.5,
              animation: 'pulse 2s ease-in-out infinite',
              position: 'absolute',
            }} />
          </div>
          <span style={{ fontSize: '0.73rem', color: '#36D399', fontWeight: 700, letterSpacing: '0.03em' }}>All Systems Online</span>
        </div>

        {/* User profile row */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '10px',
          padding: '10px 12px', marginBottom: '6px',
          borderRadius: '12px',
          background: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.06)',
        }}>
          <div style={{
            width: '30px', height: '30px', borderRadius: '9px',
            background: 'linear-gradient(135deg, #FF6A3D, #FF8C42)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '0.7rem', fontWeight: 800, color: 'white',
            boxShadow: '0 0 12px rgba(255,106,61,0.35)',
            flexShrink: 0,
          }}>
            {user?.email ? user.email.substring(0, 2).toUpperCase() : 'CG'}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: '0.81rem', fontWeight: 600, color: '#E2E8F0', lineHeight: 1.2, textOverflow: 'ellipsis', overflow: 'hidden' }}>
              {user?.email || 'User'}
            </div>
            <div style={{ fontSize: '0.65rem', color: '#475569', marginTop: '1px', textTransform: 'capitalize' }}>
              {user?.role?.replace('_', ' ') || 'Viewer'}
            </div>
          </div>
          <Zap size={12} style={{ color: '#FF8C42', flexShrink: 0 }} />
        </div>

        {/* Logout */}
        <motion.button
          onClick={onLogout}
          whileHover={{ x: 3 }}
          whileTap={{ scale: 0.97 }}
          style={{
            width: '100%', display: 'flex', alignItems: 'center', gap: '10px',
            padding: '10px 12px', borderRadius: '12px',
            border: '1px solid rgba(255, 61, 87, 0.15)',
            cursor: 'pointer', background: 'rgba(255,61,87,0.06)',
            color: '#FF3D57', fontFamily: 'Inter, sans-serif',
            fontSize: '0.845rem', fontWeight: 600,
            transition: 'all 0.15s ease',
          }}
        >
          <LogOut size={16} />
          Sign Out
        </motion.button>
      </div>
    </aside>
    </>
  );
};

export default Sidebar;
