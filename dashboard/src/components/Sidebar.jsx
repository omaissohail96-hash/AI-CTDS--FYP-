import { LayoutDashboard, Globe, Mail, Activity, ShieldAlert, Settings, LogOut, Shield, AlertCircle, Lock, Search, BrainCircuit } from 'lucide-react';

const Sidebar = ({ activeTab, setActiveTab, onLogout }) => {
    const menuItems = [
        { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
        { id: 'alerts', label: 'Alerts', icon: AlertCircle },
        { id: 'hunting', label: 'Threat Hunting', icon: Search },
        { id: 'uba', label: 'User Behavior', icon: BrainCircuit },
        { id: 'prevention', label: 'Prevention Center', icon: Lock },
        { id: 'url', label: 'URL Scanner', icon: Globe },
        { id: 'email', label: 'Email Scan', icon: Mail },
        { id: 'network', label: 'Network IDS', icon: Activity },
        { id: 'web', label: 'Web Attack', icon: ShieldAlert },
        { id: 'settings', label: 'Settings', icon: Settings },
    ];

    return (
        <aside className="sidebar">
            <div className="logo" style={{ cursor: 'pointer' }} onClick={() => setActiveTab('dashboard')}>
                <div className="logo-icon">
                    <Shield size={24} color="white" />
                </div>
                <span className="logo-text">CyberGuard AI</span>
            </div>

            <nav>
                <ul className="nav-menu">
                    {menuItems.map((item) => (
                        <li
                            key={item.id}
                            className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
                            onClick={() => setActiveTab(item.id)}
                        >
                            <span className="nav-icon"><item.icon size={20} /></span>
                            <span className="nav-text">{item.label}</span>
                        </li>
                    ))}
                </ul>
            </nav>

            <div className="sidebar-footer">
                <button className="nav-item logout-btn" onClick={onLogout}>
                    <LogOut size={20} />
                    <span>Logout</span>
                </button>
            </div>
        </aside>
    );
};

export default Sidebar
