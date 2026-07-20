import { useState, useEffect } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import './index.css'
import { Sidebar } from './components'
import Header from './components/Header'
import { useAuth } from './context/AuthContext'
import {
  DashboardPage,
  URLScannerPage,
  EmailScannerPage,
  NetworkMonitorPage,
  WebAttackPage,
  LoginPage,
  RegisterPage,
  SettingsPage,
  LandingPage,
  AlertsPage,
  PreventionCenter,
  ThreatHuntingPage,
  UserBehaviorAnalyticsPage,
  SystemHealthPage,
  ReviewQueuePage,
  MonitoringCenterPage,
  FeedbackDashboardPage,
  IPTrackingPage,
  WorkspaceMembersPage
} from './pages'

const pageVariants = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.25, ease: 'easeOut' } },
  exit: { opacity: 0, y: -8, transition: { duration: 0.15 } }
}

const AccessDenied = () => (
  <div className="flex flex-col items-center justify-center h-full p-8 text-center text-gray-400">
    <div className="text-4xl mb-4">🔒</div>
    <h2 className="text-xl font-bold text-white mb-2">Access Denied</h2>
    <p>You do not have permission to view this page.</p>
  </div>
);

const PendingWorkspaceAccess = ({ onLogout }) => (
  <div className="min-h-screen bg-[#09090B] flex flex-col items-center justify-center gap-4 p-8 text-center">
    <div className="text-[#FF8C42] text-lg font-bold">Workspace access pending</div>
    <p className="max-w-md text-sm text-slate-400">Your request has been sent to the workspace owner. You can access CyberGuard after the owner assigns your role.</p>
    <button className="btn btn-primary" onClick={onLogout}>Sign out</button>
  </div>
);

function App() {
  const { isAuthenticated, login, logout, loading, hasRole, hasPermission, user } = useAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [view, setView] = useState('landing'); // landing, login, register, app
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const handleLogin = (token) => {
    login(token);
    setView('app');
  };

  const handleLogout = () => {
    logout();
    setView('login');
  };

  if (loading) {
    return <div className="flex items-center justify-center h-screen bg-[#0a0a0a] text-white">Loading...</div>;
  }

  // Auth Routing
  if (!isAuthenticated) {
    if (view === 'register') {
      return <RegisterPage onLogin={handleLogin} onToggleForm={() => setView('login')} />;
    }
    if (view === 'login') {
      return <LoginPage onLogin={handleLogin} onToggleForm={() => setView('register')} />;
    }
    return <LandingPage onLogin={() => setView('login')} onRegister={() => setView('register')} />;
  }

  if (user?.role === 'pending') {
    return <PendingWorkspaceAccess onLogout={handleLogout} />;
  }

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard': return <DashboardPage />;
      case 'health': 
        return hasRole(['super_admin', 'workspace_admin']) ? <SystemHealthPage /> : <AccessDenied />;
      case 'monitoring': return <MonitoringCenterPage />;
      case 'review_queue': return <ReviewQueuePage />;
      case 'feedback': return <FeedbackDashboardPage />;
      case 'alerts': return <AlertsPage />;
      case 'prevention': return <PreventionCenter />;
      case 'hunting': return <ThreatHuntingPage />;
      case 'uba': return <UserBehaviorAnalyticsPage />;
      case 'url': return <URLScannerPage />;
      case 'email': return <EmailScannerPage />;
      case 'network': return <NetworkMonitorPage />;
      case 'web': return <WebAttackPage />;
      case 'ip_tracking': return <IPTrackingPage />;
      case 'members': return <WorkspaceMembersPage />;
      case 'settings': 
        return hasRole(['super_admin', 'workspace_admin']) ? <SettingsPage /> : <AccessDenied />;
      default: return <DashboardPage />;
    }
  };

  return (
    <div className="app-layout">
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onLogout={handleLogout}
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />
      <main className="main-content">
        <Header activeTab={activeTab} onMenuClick={() => setSidebarOpen(true)} />
        <div className="page-body">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              variants={pageVariants}
              initial="initial"
              animate="animate"
              exit="exit"
            >
              {renderContent()}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
  )
}

export default App
