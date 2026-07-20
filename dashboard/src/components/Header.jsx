import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bell, Search, Shield, ChevronDown, Activity, Menu } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Header = ({ activeTab, onMenuClick }) => {
  const { user } = useAuth();
  const [searchVal, setSearchVal] = useState('');
  const [searchFocused, setSearchFocused] = useState(false);

  const pageTitles = {
    dashboard:    'Dashboard',
    health:       'System Health',
    alerts:       'Alert Center',
    review_queue: 'Review Queue',
    hunting:      'Threat Hunting',
    uba:          'User Behavior Analytics',
    prevention:   'Prevention Center',
    url:          'URL Scanner',
    email:        'Email Scanner',
    network:      'Network IDS',
    web:          'Web Attack Scanner',
    settings:     'Settings & API Keys',
    ip_tracking:  'IP & Session Tracking',
    members:      'Workspace Members',
  };

  const title = pageTitles[activeTab] || 'Dashboard';

  return (
    <header style={{
      height: 'var(--header-height, 64px)',
      background: 'rgba(9,9,11,0.90)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      borderBottom: '1px solid rgba(255,255,255,0.055)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 32px',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      gap: '20px',
    }}>

      {/* ── Left: Breadcrumb ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0, flexShrink: 0 }}>
        <button
          type="button"
          onClick={onMenuClick}
          className="sidebar-menu-btn"
          aria-label="Open navigation"
          style={{
            display: 'none',
            width: '38px', height: '38px', borderRadius: '11px',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.07)',
            alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer', color: '#94A3B8', flexShrink: 0,
          }}
        >
          <Menu size={18} />
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
        <div style={{
          width: '28px', height: '28px', borderRadius: '8px',
          background: 'linear-gradient(135deg, rgba(255,106,61,0.2), rgba(255,140,66,0.1))',
          border: '1px solid rgba(255,106,61,0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Shield size={13} style={{ color: '#FF6A3D' }} />
        </div>
        <span style={{ fontSize: '0.78rem', color: '#475569', fontWeight: 500 }}>CyberGuard AI</span>
        <span style={{ color: '#2D3748', fontSize: '0.75rem', fontWeight: 300 }}>/</span>
        <span style={{ fontSize: '0.9rem', fontWeight: 700, color: '#F1F5F9', letterSpacing: '-0.01em' }}>{title}</span>
        </div>
      </div>

      {/* ── Center: Search ── */}
      <div className="header-search" style={{
        flex: 1,
        maxWidth: '480px',
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
      }}>
        <Search size={14} style={{
          position: 'absolute', left: '14px',
          color: searchFocused ? '#FF6A3D' : '#475569',
          pointerEvents: 'none',
          transition: 'color 0.15s ease',
        }} />
        <input
          type="text"
          placeholder="Search threats, IPs, domains..."
          value={searchVal}
          onChange={(e) => setSearchVal(e.target.value)}
          onFocus={() => setSearchFocused(true)}
          onBlur={() => setSearchFocused(false)}
          style={{
            width: '100%',
            background: searchFocused ? 'rgba(255,255,255,0.055)' : 'rgba(255,255,255,0.04)',
            border: searchFocused ? '1px solid rgba(255,106,61,0.35)' : '1px solid rgba(255,255,255,0.07)',
            borderRadius: '12px',
            padding: '8px 48px 8px 40px',
            fontSize: '0.845rem',
            color: '#F1F5F9',
            outline: 'none',
            fontFamily: 'Inter, sans-serif',
            transition: 'all 0.2s ease',
            boxShadow: searchFocused ? '0 0 0 3px rgba(255,106,61,0.1)' : 'none',
          }}
        />
        {/* Keyboard shortcut badge */}
        <div style={{
          position: 'absolute', right: '12px',
          display: 'flex', alignItems: 'center', gap: '2px',
          opacity: searchFocused ? 0 : 0.5,
          transition: 'opacity 0.15s ease',
        }}>
          <span style={{
            fontSize: '0.65rem', color: '#475569', fontWeight: 600,
            background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: '4px', padding: '1px 5px', fontFamily: 'monospace',
          }}>⌘K</span>
        </div>
      </div>

      {/* ── Right: Actions ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>

        {/* Notification Bell */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          style={{
            position: 'relative',
            width: '38px', height: '38px', borderRadius: '11px',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.07)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer', color: '#64748B',
            transition: 'all 0.15s ease',
          }}
        >
          <Bell size={16} />
          {/* Alert dot */}
          <div style={{
            position: 'absolute', top: '7px', right: '7px',
            width: '7px', height: '7px', borderRadius: '50%',
            background: '#FF3D57',
            boxShadow: '0 0 6px rgba(255,61,87,0.9)',
            animation: 'pulse 2s ease-in-out infinite',
          }} />
        </motion.button>

        {/* System Live Badge */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          padding: '6px 13px', borderRadius: '9px',
          background: 'rgba(54,211,153,0.07)',
          border: '1px solid rgba(54,211,153,0.18)',
        }}>
          <Activity size={12} style={{ color: '#36D399' }} />
          <span style={{ fontSize: '0.7rem', color: '#36D399', fontWeight: 800, letterSpacing: '0.06em' }}>
            LIVE
          </span>
        </div>

        {/* User menu */}
        <motion.div
          whileHover={{ opacity: 0.85 }}
          style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            padding: '6px 10px', borderRadius: '11px',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.07)',
            cursor: 'pointer',
          }}
        >
          <div style={{
            width: '28px', height: '28px', borderRadius: '9px',
            background: 'linear-gradient(135deg, #FF6A3D, #FF8C42)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '0.68rem', fontWeight: 800, color: 'white',
            boxShadow: '0 0 12px rgba(255,106,61,0.4)',
          }}>
            {(user?.email || 'CG').slice(0, 2).toUpperCase()}
          </div>
          <span style={{ fontSize: '0.84rem', color: '#CBD5E1', fontWeight: 600 }}>{user?.role || 'Viewer'}</span>
          {user?.workspace_id && <button type="button" onClick={() => navigator.clipboard.writeText(user.workspace_id)} title="Copy full workspace ID" style={{ fontSize: '0.64rem', color: '#FF8C42', background: 'transparent', border: 'none', cursor: 'pointer', whiteSpace: 'nowrap' }}>Workspace {user.workspace_id.slice(0, 8)}</button>}
          <ChevronDown size={12} style={{ color: '#475569' }} />
        </motion.div>
      </div>
    </header>
  );
};

export default Header;
