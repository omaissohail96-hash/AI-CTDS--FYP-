import { useState } from 'react'
import './index.css'
import { Sidebar } from './components'
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
  UserBehaviorAnalyticsPage
} from './pages'

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));
  const [view, setView] = useState('landing'); // landing, login, register, app

  const handleLogin = (token) => {
    localStorage.setItem('token', token); // Store token on successful login
    setIsAuthenticated(true);
    setView('app');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsAuthenticated(false);
    setView('login');
  };

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

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <DashboardPage />;
      case 'alerts':
        return <AlertsPage />;
      case 'prevention':
        return <PreventionCenter />;
      case 'hunting':
        return <ThreatHuntingPage />;
      case 'uba':
        return <UserBehaviorAnalyticsPage />;
      case 'url':
        return <URLScannerPage />;
      case 'email':
        return <EmailScannerPage />;
      case 'network':
        return <NetworkMonitorPage />;
      case 'web':
        return <WebAttackPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <DashboardPage />;
    }
  };

  return (
    <div className="app-layout">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} onLogout={handleLogout} />
      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  )
}

export default App
