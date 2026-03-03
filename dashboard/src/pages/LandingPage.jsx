import React from 'react';
import {
    Shield,
    Lock,
    Target,
    Users,
    Zap,
    Award,
    Database,
    Activity,
    ArrowRight,
    ChevronDown,
    Mail,
    Network,
    Globe,
    Cpu
} from 'lucide-react';

const LandingPage = ({ onLogin, onRegister }) => {
    return (
        <div className="landing-wrapper">
            {/* Navigation */}
            <nav className="landing-nav">
                <div className="landing-logo">
                    <div className="logo-icon">
                        <Shield size={24} />
                    </div>
                    <span className="logo-text">CYBERGUARD AI</span>
                </div>
                <div className="nav-actions">
                    <button className="nav-link" onClick={onLogin}>Login</button>
                    <button className="btn-primary" onClick={onRegister}>Sign Up Free</button>
                </div>
            </nav>

            {/* Hero Section */}
            <header className="hero-section">
                <div className="hero-content">
                    <div className="badge-glow">Next-Gen AI Security</div>
                    <h1 className="hero-title">
                        Tired of dealing with <br />
                        <span className="text-gradient">cyber threats</span> <br />
                        every single day?
                    </h1>
                    <p className="hero-subtitle">
                        CyberGuard AI automatically detects, analyzes, and neutralizes threats — across your network, email, and endpoints — in real time, 24/7, with zero manual configuration.
                    </p>
                    <div className="hero-cta">
                        <button className="btn-primary btn-xl" onClick={onRegister}>
                            Get Started for Free <ArrowRight size={20} />
                        </button>
                        <button className="btn-secondary btn-xl" onClick={onLogin}>
                            View Dashboard
                        </button>
                    </div>
                </div>
                <div className="hero-visual">
                    <div className="hero-image-container">
                        <img src="/cyberguard_hero_banner.png" alt="CyberGuard Interface" className="hero-img" />
                        <div className="hero-glow"></div>
                    </div>
                    <div className="stat-floater accuracy">
                        <Activity size={20} className="text-cyan" />
                        <div>
                            <div className="stat-val">93%</div>
                            <div className="stat-label">Model Accuracy</div>
                        </div>
                    </div>
                    <div className="stat-floater speed">
                        <Zap size={20} className="text-purple" />
                        <div>
                            <div className="stat-val">Real-Time</div>
                            <div className="stat-label">Detection Speed</div>
                        </div>
                    </div>
                </div>
            </header>

            {/* Mission & Vision Section */}
            <section className="mission-section">
                <div className="section-header">
                    <h2 className="section-title">Our Mission & Goal</h2>
                    <p className="section-subtitle">Pioneering the future of autonomous digital defense.</p>
                </div>
                <div className="mission-grid">
                    <div className="mission-card glass-panel">
                        <div className="card-icon cyan">
                            <Target size={24} />
                        </div>
                        <h3>Our Mission</h3>
                        <p>To deliver enterprise-grade AI security that automatically detects malware, phishing, network intrusions, and zero-day anomalies across all surfaces — in real time, with complete analyst transparency.</p>
                    </div>
                    <div className="mission-card glass-panel">
                        <div className="card-icon purple">
                            <Shield size={24} />
                        </div>
                        <h3>Our Goal</h3>
                        <p>To transition from reactive protection to proactive defense by utilizing a 24-hour lookback engine and cross-vector correlation that identifies patterns before they become catastrophic breaches.</p>
                    </div>
                    <div className="mission-card glass-panel">
                        <div className="card-icon green">
                            <Award size={24} />
                        </div>
                        <h3>Our Objective</h3>
                        <p>To reduce analyst fatigue by delivering 38% fewer false alarms than conventional rule-based IDS systems, allowing security teams to focus on high-impact strategic hardening.</p>
                    </div>
                </div>
            </section>

            {/* Core Capabilities */}
            <section className="capabilities-section">
                <div className="split-layout">
                    <div className="split-content">
                        <div className="badge-outline">Our Capabilities</div>
                        <h2 className="split-title">Advanced 4-Model Ensemble Pipeline</h2>
                        <div className="capability-list">
                            <div className="capability-item">
                                <div className="item-icon"><Globe size={20} /></div>
                                <div>
                                    <h4>URL Phishing Detection</h4>
                                    <p>Random Forest models trained on phishing features with feature importance breakdown.</p>
                                </div>
                            </div>
                            <div className="capability-item">
                                <div className="item-icon"><Mail size={20} /></div>
                                <div>
                                    <h4>Intelligent Email Filter</h4>
                                    <p>LSTM and NLP-based analysis for subject and body integrity checks.</p>
                                </div>
                            </div>
                            <div className="capability-item">
                                <div className="item-icon"><Network size={20} /></div>
                                <div>
                                    <h4>Network Intrusion Detection</h4>
                                    <p>Anomaly detection across network flows to catch zero-day exploits.</p>
                                </div>
                            </div>
                            <div className="capability-item">
                                <div className="item-icon"><Lock size={20} /></div>
                                <div>
                                    <h4>Web Attack Prevention</h4>
                                    <p>Real-time blocking of SQL injection, XSS, and command injection attempts.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="split-visual">
                        <div className="ensemble-graphic glass-panel">
                            <div className="ensemble-center">
                                <div className="ensemble-core">AI</div>
                            </div>
                            <div className="ensemble-node n1">URL</div>
                            <div className="ensemble-node n2">Email</div>
                            <div className="ensemble-node n3">Network</div>
                            <div className="ensemble-node n4">Web</div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Team Section */}
            <section className="team-section">
                <div className="section-header">
                    <h2 className="section-title">The Engineering Team</h2>
                    <p className="section-subtitle">Final Year Project - Batch 2022F - Group 17</p>
                </div>
                <div className="team-grid">
                    {[
                        { name: "Muhammad Farooq Azam", id: "2022F-BCE-051" },
                        { name: "Duraid Khalid", id: "2022F-BCE-099" },
                        { name: "Omais Sohail", id: "2022F-BCE-223" },
                        { name: "Bilal Jawed", id: "2022F-BCE-247" }
                    ].map((member, i) => (
                        <div key={i} className="team-card glass-panel">
                            <div className="member-avatar">
                                <Users size={40} />
                            </div>
                            <h4>{member.name}</h4>
                            <p className="member-id">{member.id}</p>
                            <p className="member-role">Full Stack AI Developer</p>
                        </div>
                    ))}
                </div>
            </section>

            {/* Final CTA */}
            <section className="cta-banner">
                <div className="glass-panel cta-inner">
                    <h2>Ready to secure your workspace?</h2>
                    <p>Join thousands of security professionals using CyberGuard AI.</p>
                    <button className="btn-primary btn-xl" onClick={onRegister}>Create Free Account</button>
                </div>
            </section>

            {/* Institution Footer */}
            <footer className="landing-footer">
                <div className="footer-content">
                    <div className="footer-brand">
                        <h3 className="logo-text">CYBERGUARD AI</h3>
                        <p>Sir Syed University of Engineering & Technology<br />Department of Computer Engineering</p>
                    </div>
                    <div className="footer-info">
                        <div className="info-stat">
                            <div className="val">93%</div>
                            <div className="label">Accuracy</div>
                        </div>
                        <div className="info-stat">
                            <div className="val">91.7%</div>
                            <div className="label">F1 Score</div>
                        </div>
                        <div className="info-stat">
                            <div className="val">5M+</div>
                            <div className="label">Tested Records</div>
                        </div>
                    </div>
                </div>
                <div className="footer-bottom">
                    <p>&copy; 2026 CyberGuard AI - Project Batch 2022F. All Rights Reserved.</p>
                </div>
            </footer>
        </div>
    );
};

export default LandingPage;
