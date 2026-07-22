import React, { useState, useEffect, useRef } from 'react';
import { motion, useScroll, useTransform, AnimatePresence } from 'framer-motion';
import {
    Shield, Lock, Target, Users, Zap, Award,
    Globe, Mail, Network, Cpu, Database, Activity,
    ArrowRight, CheckCircle, BarChart2, Eye, Key,
    TrendingUp, AlertTriangle, Layers, BrainCircuit,
    ChevronRight, Star, Sparkles, Menu, X as XIcon
} from 'lucide-react';

/* ─── animation variants ─────────────────────────── */
const fadeUp = {
    hidden: { opacity: 0, y: 30 },
    show:   { opacity: 1, y: 0,  transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] } }
};
const fadeIn = {
    hidden: { opacity: 0 },
    show:   { opacity: 1, transition: { duration: 0.5, ease: 'easeOut' } }
};
const stagger = {
    show: { transition: { staggerChildren: 0.09 } }
};

/* ─── Animated Counter ───────────────────────────── */
const Counter = ({ end, suffix = '', prefix = '', duration = 2000 }) => {
    const [count, setCount] = useState(0);
    const ref = useRef(null);
    const [started, setStarted] = useState(false);

    useEffect(() => {
        const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setStarted(true); }, { threshold: 0.5 });
        if (ref.current) obs.observe(ref.current);
        return () => obs.disconnect();
    }, []);

    useEffect(() => {
        if (!started) return;
        const numEnd = parseFloat(end);
        let start = 0;
        const step = (numEnd / duration) * 16;
        const timer = setInterval(() => {
            start += step;
            if (start >= numEnd) { setCount(numEnd); clearInterval(timer); }
            else setCount(start);
        }, 16);
        return () => clearInterval(timer);
    }, [started, end, duration]);

    const display = Number.isInteger(parseFloat(end)) ? Math.floor(count) : count.toFixed(1);
    return <span ref={ref}>{prefix}{display}{suffix}</span>;
};

/* ─── reusable components ────────────────────────── */
const PillBadge = ({ children }) => (
    <span className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-[#FF6A3D]/10 border border-[#FF6A3D]/25 text-[11px] font-bold text-[#FF6A3D] uppercase tracking-[0.12em]">
        {children}
    </span>
);

const FeatureCard = ({ icon: Icon, color, title, desc, delay = 0 }) => (
    <motion.div
        variants={fadeUp}
        whileHover={{ y: -6, transition: { duration: 0.2 } }}
        className="group relative bg-[#111318] border border-white/[0.07] rounded-2xl p-7 space-y-5 hover:border-white/[0.14] transition-colors cursor-default overflow-hidden"
        style={{ animationDelay: `${delay}ms` }}
    >
        <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
            style={{ background: 'radial-gradient(ellipse 60% 50% at 50% 0%, rgba(255,106,61,0.05), transparent)' }} />
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${color}`}>
            <Icon size={22} />
        </div>
        <div>
            <h3 className="font-bold text-white text-[15px] mb-2">{title}</h3>
            <p className="text-[13px] text-slate-500 leading-relaxed">{desc}</p>
        </div>
        <div className="flex items-center gap-1 text-[11px] font-semibold text-[#FF6A3D]/0 group-hover:text-[#FF6A3D]/80 transition-all duration-300">
            Learn more <ChevronRight size={12} />
        </div>
    </motion.div>
);

/* ─── Animated Live Terminal ─────────────────────── */
const LiveTerminal = () => {
    const entries = [
        { type: '⚡ THREAT', val: 'http://malware-drop.ru/exec.php', color: '#FF3D57', delay: 0 },
        { type: '✓ BLOCKED', val: 'phishing@bankupdate.net → quarantined', color: '#36D399', delay: 800 },
        { type: '⚠ INTRUSION', val: 'SYN Flood 192.168.1.14 → blocked', color: '#FF8C42', delay: 1600 },
        { type: '✓ CLEAN', val: 'GET /api/v1/health → 200 OK', color: '#36D399', delay: 2400 },
        { type: '⚡ XSS', val: "<script>alert('xss')</script>", color: '#FF3D57', delay: 3200 },
        { type: '✓ PASS', val: 'user@corp.com attachment scanned', color: '#36D399', delay: 4000 },
    ];

    const [visible, setVisible] = useState([]);
    useEffect(() => {
        entries.forEach((e, i) => {
            setTimeout(() => setVisible(prev => [...prev, i]), e.delay);
        });
        // loop
        const loop = setInterval(() => {
            setVisible([]);
            entries.forEach((e, i) => {
                setTimeout(() => setVisible(prev => [...prev, i]), e.delay + 100);
            });
        }, entries.length * 800 + 1200);
        return () => clearInterval(loop);
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    return (
        <div className="space-y-2">
            {entries.map((row, i) => (
                <motion.div
                    key={`${i}-${visible.includes(i)}`}
                    initial={{ opacity: 0, x: -10 }}
                    animate={visible.includes(i) ? { opacity: 1, x: 0 } : { opacity: 0, x: -10 }}
                    transition={{ duration: 0.3 }}
                    className="flex items-center gap-3 py-2 px-3.5 rounded-lg bg-black/30 border border-white/[0.04]"
                >
                    <span className="font-bold text-[10px] w-[88px] flex-shrink-0 font-mono" style={{ color: row.color }}>{row.type}</span>
                    <span className="text-slate-400 text-[11px] font-mono truncate">{row.val}</span>
                </motion.div>
            ))}
        </div>
    );
};

/* ─── Hero Dashboard Mock ────────────────────────── */
const HeroDashboard = () => (
    <motion.div
        initial={{ opacity: 0, scale: 0.93, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.8, delay: 0.3, ease: [0.22, 1, 0.36, 1] }}
        className="relative w-full max-w-[520px] mx-auto"
    >
        {/* Glow behind card */}
        <div className="absolute inset-0 bg-gradient-to-br from-[#FF6A3D]/20 to-transparent blur-3xl -z-10 scale-110 rounded-3xl" />

        {/* Main card */}
        <div className="relative bg-[#111318] border border-white/[0.09] rounded-2xl overflow-hidden shadow-2xl">
            {/* Scanline overlay */}
            <div className="absolute inset-0 pointer-events-none overflow-hidden z-10">
                <div style={{ position: 'absolute', width: '100%', height: '2px', background: 'linear-gradient(90deg, transparent, rgba(255,106,61,0.15), transparent)', animation: 'scanline 4s linear infinite' }} />
            </div>

            {/* Top bar */}
            <div className="flex items-center gap-2 px-5 py-3.5 border-b border-white/[0.07] bg-black/20">
                <div className="w-3 h-3 rounded-full bg-[#FF3D57]" />
                <div className="w-3 h-3 rounded-full bg-[#FBBF24]" />
                <div className="w-3 h-3 rounded-full bg-[#36D399]" />
                <span className="ml-3 text-[10px] font-mono text-slate-600 tracking-wider">CYBERGUARD AI — LIVE CONSOLE</span>
                <div className="ml-auto flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-[#36D399] animate-ping" />
                    <span className="text-[9px] text-[#36D399] font-mono font-bold">ACTIVE</span>
                </div>
            </div>

            <div className="p-5 space-y-5">
                {/* Mini stats row */}
                <div className="grid grid-cols-3 gap-3">
                    {[
                        { label: 'Threats Blocked', val: '2,847', color: '#FF3D57', icon: '🛡' },
                        { label: 'Detection Rate', val: '93%', color: '#36D399', icon: '🎯' },
                        { label: 'Response Time', val: '<15ms', color: '#5AA9FF', icon: '⚡' },
                    ].map(s => (
                        <div key={s.label} className="bg-black/30 border border-white/[0.05] rounded-xl p-3 text-center">
                            <div className="text-base font-extrabold font-mono" style={{ color: s.color }}>{s.val}</div>
                            <div className="text-[9px] text-slate-600 uppercase tracking-wide mt-0.5">{s.label}</div>
                        </div>
                    ))}
                </div>

                {/* Live Terminal */}
                <LiveTerminal />

                {/* Mini chart bars */}
                <div className="flex items-end gap-1.5 h-14 px-1">
                    {[35, 58, 42, 76, 55, 88, 62, 74, 51, 90, 67, 83].map((h, i) => (
                        <motion.div
                            key={i}
                            initial={{ scaleY: 0 }}
                            animate={{ scaleY: 1 }}
                            transition={{ duration: 0.4, delay: i * 0.05 + 0.5 }}
                            className="flex-1 rounded-sm origin-bottom"
                            style={{ height: `${h}%`, background: i === 11 ? '#FF6A3D' : i > 8 ? 'rgba(255,106,61,0.4)' : 'rgba(90,169,255,0.25)' }}
                        />
                    ))}
                </div>

                {/* Risk score gauge row */}
                <div className="flex items-center gap-3 p-3 bg-black/25 border border-white/[0.05] rounded-xl">
                    <div className="relative w-10 h-10 flex-shrink-0">
                        <svg viewBox="0 0 36 36" className="w-10 h-10 -rotate-90">
                            <circle cx="18" cy="18" r="14" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="4" />
                            <circle cx="18" cy="18" r="14" fill="none" stroke="#FF6A3D" strokeWidth="4"
                                strokeDasharray="61 88" strokeLinecap="round" />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center text-[9px] font-extrabold text-[#FF6A3D]">69</div>
                    </div>
                    <div>
                        <div className="text-[11px] font-bold text-white">Risk Score: Medium-High</div>
                        <div className="text-[9px] text-slate-600 mt-0.5">3 active threats detected · Last scan 2s ago</div>
                    </div>
                    <div className="ml-auto">
                        <span className="text-[9px] font-bold text-[#FF8C42] bg-[#FF8C42]/10 border border-[#FF8C42]/20 rounded px-2 py-0.5 uppercase tracking-wide">Alert</span>
                    </div>
                </div>
            </div>
        </div>

        {/* Floating accuracy card */}
        <motion.div
            animate={{ y: [0, -7, 0] }}
            transition={{ repeat: Infinity, duration: 3.5, ease: 'easeInOut' }}
            className="absolute -top-6 -left-8 bg-[#111318] border border-white/10 rounded-xl px-3.5 py-3 flex items-center gap-3 shadow-2xl"
        >
            <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                <Activity size={16} />
            </div>
            <div className="font-mono">
                <div className="text-sm font-extrabold text-white">93%</div>
                <div className="text-[9px] text-slate-600 uppercase tracking-wide">Accuracy</div>
            </div>
        </motion.div>

        {/* Floating latency card */}
        <motion.div
            animate={{ y: [0, 7, 0] }}
            transition={{ repeat: Infinity, duration: 4, ease: 'easeInOut' }}
            className="absolute -bottom-6 -right-8 bg-[#111318] border border-white/10 rounded-xl px-3.5 py-3 flex items-center gap-3 shadow-2xl"
        >
            <div className="w-9 h-9 rounded-lg bg-[#FF6A3D]/10 border border-[#FF6A3D]/20 flex items-center justify-center text-[#FF6A3D]">
                <Zap size={16} />
            </div>
            <div className="font-mono">
                <div className="text-sm font-extrabold text-white">&lt;15ms</div>
                <div className="text-[9px] text-slate-600 uppercase tracking-wide">Inference</div>
            </div>
        </motion.div>

        {/* Floating AI badge */}
        <motion.div
            animate={{ y: [0, -5, 0] }}
            transition={{ repeat: Infinity, duration: 5, ease: 'easeInOut', delay: 1 }}
            className="absolute top-1/2 -right-10 -translate-y-1/2 bg-[#111318] border border-purple-500/20 rounded-xl px-3 py-2.5 flex items-center gap-2 shadow-2xl"
        >
            <div className="w-7 h-7 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                <BrainCircuit size={13} />
            </div>
            <div className="font-mono">
                <div className="text-[10px] font-extrabold text-white">4 Models</div>
                <div className="text-[8px] text-slate-600 uppercase tracking-wide">AI Active</div>
            </div>
        </motion.div>
    </motion.div>
);

/* ─── main component ─────────────────────────────── */
const LandingPage = ({ onLogin, onRegister }) => {
    const [activeStep, setActiveStep] = useState(0);
    const [mobileNavOpen, setMobileNavOpen] = useState(false);
    const { scrollY } = useScroll();
    const navBg = useTransform(scrollY, [0, 80], ['rgba(9,9,11,0)', 'rgba(9,9,11,0.95)']);
    const navBorder = useTransform(scrollY, [0, 80], ['rgba(255,255,255,0)', 'rgba(255,255,255,0.06)']);

    useEffect(() => {
        const id = setInterval(() => setActiveStep(s => (s + 1) % 6), 1800);
        return () => clearInterval(id);
    }, []);

    const navLinks = ['Features', 'Dashboard', 'Pricing', 'Documentation', 'About'];

    const scrollToSection = (id) => {
        const targetId = id.toLowerCase();
        // Map some legacy or different name variants
        const sectionMap = {
            'api': 'documentation',
            'getting started': 'documentation',
            'api reference': 'documentation',
            'architecture': 'documentation',
            'system manual': 'documentation'
        };
        const resolvedId = sectionMap[targetId] || targetId;
        const element = document.getElementById(resolvedId);
        if (element) {
            element.scrollIntoView({ behavior: 'smooth' });
        }
    };

    const features = [
        { icon: Globe,       color: 'bg-blue-500/10 border border-blue-500/20 text-blue-400',       title: 'AI URL Detection',            desc: 'Random Forest classifiers trained on 500k+ phishing indicators verify URLs in under 15ms with 93% accuracy.' },
        { icon: Mail,        color: 'bg-[#FF8C42]/10 border border-[#FF8C42]/20 text-[#FF8C42]',    title: 'Email Phishing Filter',        desc: 'LSTM-powered NLP pipeline detects spam, spear-phishing, and BEC attacks at the SMTP layer in real time.' },
        { icon: Network,     color: 'bg-[#FF6A3D]/10 border border-[#FF6A3D]/20 text-[#FF6A3D]',    title: 'Network IDS',                  desc: 'Real-time traffic classifier intercepting anomalous flows, port scans, and lateral movement automatically.' },
        { icon: Shield,      color: 'bg-red-500/10 border border-red-500/20 text-red-400',           title: 'Web Attack Detection',         desc: 'HTTP log parser blocking XSS, SQLi, command injection, and SSRF payloads without false positives.' },
        { icon: Database,    color: 'bg-purple-500/10 border border-purple-500/20 text-purple-400',  title: 'Threat Intelligence',          desc: 'Cross-references IOCs against global threat feeds with sub-second enrichment and MITRE ATT&CK mapping.' },
        { icon: Eye,         color: 'bg-cyan-500/10 border border-cyan-500/20 text-cyan-400',        title: 'User Behavior Analytics',      desc: 'Detects insider threats, compromised accounts, and abnormal access patterns via advanced UBA models.' },
        { icon: BarChart2,   color: 'bg-green-500/10 border border-green-500/20 text-green-400',     title: 'Explainable AI',               desc: 'SHAP-value explanations and confidence scores attached to every alert for transparent analyst review.' },
        { icon: Key,         color: 'bg-yellow-500/10 border border-yellow-500/20 text-yellow-400', title: 'REST API Access',              desc: 'JWT-secured REST endpoints for CI/CD integration, SIEM export, and full automation of threat workflows.' },
    ];

    const stats = [
        { value: 93, suffix: '%', label: 'Detection Accuracy', color: '#FF6A3D' },
        { value: 5,  suffix: 'M+', label: 'Threats Scanned', color: '#36D399' },
        { value: 4,  suffix: '',   label: 'AI Models', color: '#5AA9FF' },
        { value: 15, prefix: '<', suffix: 'ms', label: 'Inference Time', color: '#A78BFA' },
    ];

    const workflow = [
        { num: 1, label: 'Input',      desc: 'URL · Email · Log', icon: '📥' },
        { num: 2, label: 'AI Scan',    desc: 'Ensemble inference', icon: '🤖' },
        { num: 3, label: 'Intel',      desc: 'Threat enrichment', icon: '🔍' },
        { num: 4, label: 'Risk Score', desc: 'Confidence rating', icon: '📊' },
        { num: 5, label: 'Alert',      desc: 'Real-time notify', icon: '🚨' },
        { num: 6, label: 'Dashboard',  desc: 'Analyst console', icon: '🖥' },
    ];

    const team = [
        { name: 'Farooq Azam', id: '2022F-BCE-051', initials: 'FA', role: 'AI and ML Backend engineer' },
        { name: 'Duraid Khalid', id: '2022F-BCE-099', initials: 'DK', role: 'Front end developer' },
        { name: 'Omais Sohail', id: '2022F-BCE-223', initials: 'OS', role: 'Dev Ops engineer' },
        { name: 'Bilal Jawed', id: '2022F-BCE-247', initials: 'BJ', role: 'Front end developer' },
    ];

    const techs = [
        { label: 'React 19',      color: 'bg-cyan-500/5 border-cyan-500/20 text-cyan-400' },
        { label: 'FastAPI',       color: 'bg-green-500/5 border-green-500/20 text-green-400' },
        { label: 'Scikit-Learn',  color: 'bg-orange-500/5 border-orange-500/20 text-orange-400' },
        { label: 'Random Forest', color: 'bg-[#FF6A3D]/5 border-[#FF6A3D]/20 text-[#FF6A3D]' },
        { label: 'TF-IDF / LSTM', color: 'bg-purple-500/5 border-purple-500/20 text-purple-400' },
        { label: 'Redis',         color: 'bg-red-500/5 border-red-500/20 text-red-400' },
        { label: 'Celery',        color: 'bg-blue-500/5 border-blue-500/20 text-blue-400' },
        { label: 'JWT Auth',      color: 'bg-yellow-500/5 border-yellow-500/20 text-yellow-400' },
        { label: 'SHAP / XAI',   color: 'bg-pink-500/5 border-pink-500/20 text-pink-400' },
        { label: 'Framer Motion', color: 'bg-violet-500/5 border-violet-500/20 text-violet-400' },
    ];

    return (
        <div className="min-h-screen bg-[#09090B] text-white flex flex-col font-inter relative overflow-x-hidden">

            {/* ── Ambient blobs ── */}
            <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[700px] pointer-events-none -z-10"
                style={{ background: 'radial-gradient(ellipse at 50% 0%, rgba(255,106,61,0.1) 0%, transparent 65%)' }} />
            <div className="fixed bottom-0 right-0 w-[600px] h-[600px] pointer-events-none -z-10"
                style={{ background: 'radial-gradient(ellipse at 100% 100%, rgba(255,140,66,0.06) 0%, transparent 55%)' }} />
            <div className="fixed bottom-1/3 left-0 w-[400px] h-[400px] pointer-events-none -z-10"
                style={{ background: 'radial-gradient(ellipse at 0% 50%, rgba(90,169,255,0.04) 0%, transparent 55%)' }} />

            {/* ── NAV ── */}
            <motion.nav
                style={{ backgroundColor: navBg, borderBottomColor: navBorder }}
                className="sticky top-0 z-50 w-full border-b backdrop-blur-2xl"
            >
                <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-8">
                    {/* Logo */}
                    <div className="flex items-center gap-3 flex-shrink-0">
                        <div className="w-9 h-9 rounded-xl overflow-hidden shadow-[0_0_20px_rgba(255,106,61,0.45)]">
                            <img
                                src="/ChatGPT Image Jul 22, 2026, 04_24_12 PM.png"
                                alt="CyberGuard AI Logo"
                                className="w-full h-full object-cover"
                            />
                        </div>
                        <div className="leading-tight">
                            <span className="block font-extrabold text-[13px] tracking-widest text-white">CYBERGUARD</span>
                            <span className="block text-[9px] font-bold text-[#FF6A3D] tracking-[0.25em] uppercase">AI Platform</span>
                        </div>
                    </div>

                    {/* Desktop nav links */}
                    <div className="hidden md:flex items-center gap-1">
                        {navLinks.map(l => (
                            <button
                                key={l}
                                onClick={() => scrollToSection(l)}
                                className="px-3.5 py-2 text-[13px] font-medium text-slate-400 hover:text-white rounded-lg hover:bg-white/[0.04] transition-all"
                            >
                                {l}
                            </button>
                        ))}
                    </div>

                    {/* CTA */}
                    <div className="flex items-center gap-3">
                        <button onClick={onLogin} className="hidden sm:block text-[13px] font-semibold text-slate-400 hover:text-white transition-colors px-4 py-2">
                            Sign In
                        </button>
                        <button
                            onClick={onRegister}
                            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-[#FF6A3D] to-[#FF8C42] text-white text-[13px] font-bold hover:shadow-[0_0_24px_rgba(255,106,61,0.5)] hover:scale-[1.02] active:scale-[0.98] transition-all shadow-[0_0_16px_rgba(255,106,61,0.3)]"
                        >
                            Get Started <ArrowRight size={13} />
                        </button>
                        {/* Mobile menu */}
                        <button onClick={() => setMobileNavOpen(v => !v)} className="md:hidden p-2 text-slate-400 hover:text-white transition-colors">
                            {mobileNavOpen ? <XIcon size={20} /> : <Menu size={20} />}
                        </button>
                    </div>
                </div>

                {/* Mobile nav */}
                <AnimatePresence>
                    {mobileNavOpen && (
                        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                            className="md:hidden border-t border-white/[0.06] bg-[#09090B]/98 overflow-hidden">
                            <div className="px-6 py-4 space-y-1">
                                {navLinks.map(l => (
                                    <button
                                        key={l}
                                        onClick={() => {
                                            scrollToSection(l);
                                            setMobileNavOpen(false);
                                        }}
                                        className="block w-full text-left px-3 py-2.5 text-[14px] text-slate-400 hover:text-white hover:bg-white/[0.04] rounded-lg transition-all"
                                    >
                                        {l}
                                    </button>
                                ))}
                                <div className="pt-3 border-t border-white/[0.06]">
                                    <button onClick={onLogin} className="block w-full text-left px-3 py-2.5 text-[14px] text-slate-400">Sign In</button>
                                </div>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </motion.nav>

            {/* ── HERO ── */}
            <section className="w-full max-w-7xl mx-auto px-6 pt-24 pb-32 grid grid-cols-1 lg:grid-cols-2 gap-20 items-center">
                <motion.div initial="hidden" animate="show" variants={stagger} className="space-y-8">
                    <motion.div variants={fadeUp}>
                        <PillBadge><Sparkles size={10} className="animate-pulse" /> Next-Gen ML Autonomous Security</PillBadge>
                    </motion.div>

                    <motion.h1 variants={fadeUp} className="text-5xl md:text-6xl xl:text-7xl font-extrabold leading-[1.08] tracking-tight">
                        Stop Cyber Threats<br />
                        Before They{' '}
                        <span style={{ background: 'linear-gradient(135deg, #FF6A3D 0%, #FF8C42 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
                            Strike
                        </span>
                    </motion.h1>

                    <motion.p variants={fadeUp} className="text-base md:text-lg text-slate-400 max-w-xl leading-relaxed">
                        AI-powered cybersecurity platform that detects <strong className="text-slate-300">phishing URLs</strong>, <strong className="text-slate-300">malicious emails</strong>, <strong className="text-slate-300">network intrusions</strong>, <strong className="text-slate-300">web attacks</strong>, <strong className="text-slate-300">threat intelligence</strong>, <strong className="text-slate-300">user behavior anomalies</strong> and <strong className="text-slate-300">API security</strong>.
                    </motion.p>

                    <motion.div variants={fadeUp} className="flex flex-wrap gap-4">
                        <button
                            onClick={onRegister}
                            className="inline-flex items-center gap-2.5 px-7 py-3.5 rounded-xl text-white font-bold text-[15px] transition-all active:scale-[0.97]"
                            style={{ background: 'linear-gradient(135deg, #FF6A3D, #FF8C42)', boxShadow: '0 0 32px rgba(255,106,61,0.45)' }}
                        >
                            Start Free Trial <ArrowRight size={16} />
                        </button>
                        <button
                            onClick={onLogin}
                            className="inline-flex items-center gap-2.5 px-7 py-3.5 rounded-xl border border-white/[0.12] bg-white/[0.04] text-white font-semibold text-[15px] hover:bg-white/[0.08] hover:border-white/[0.2] transition-all"
                        >
                            Open Dashboard
                        </button>
                    </motion.div>

                    {/* Trust row */}
                    <motion.div variants={fadeUp} className="flex flex-wrap gap-6 pt-2">
                        {[
                            { icon: '🎯', val: '93%', label: 'Detection Accuracy' },
                            { icon: '⚡', val: '<15ms', label: 'Response Time' },
                            { icon: '🤖', val: 'Real-time', label: 'AI Detection' },
                            { icon: '🔬', val: '4 Engines', label: 'Detection Models' },
                        ].map(({ icon, val, label }) => (
                            <div key={label} className="flex items-center gap-2">
                                <span className="text-sm">{icon}</span>
                                <span className="text-[13px] text-slate-300">
                                    <span className="font-bold text-white">{val}</span>{' '}{label}
                                </span>
                            </div>
                        ))}
                    </motion.div>
                </motion.div>

                {/* Hero dashboard mock */}
                <div className="flex justify-center lg:justify-end pr-10 lg:pr-16">
                    <HeroDashboard />
                </div>
            </section>

            {/* ── STATS STRIP ── */}
            <section className="w-full border-y border-white/[0.06] bg-[#0F1117]/60">
                <div className="max-w-7xl mx-auto px-6 py-14">
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="grid grid-cols-2 lg:grid-cols-4 gap-10"
                    >
                        {stats.map((s, i) => (
                            <motion.div key={s.label} variants={fadeUp} className="text-center space-y-2">
                                <div className="text-4xl font-extrabold font-mono" style={{ color: s.color }}>
                                    <Counter end={s.value} prefix={s.prefix} suffix={s.suffix} />
                                </div>
                                <div className="text-[12px] text-slate-500 uppercase tracking-[0.12em] font-semibold">{s.label}</div>
                            </motion.div>
                        ))}
                    </motion.div>
                </div>
            </section>

            {/* ── FEATURES SECTION ── */}
            <section id="features" className="w-full py-28">
                <div className="max-w-7xl mx-auto px-6">
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="text-center mb-20 space-y-4"
                    >
                        <motion.div variants={fadeUp}><PillBadge>Platform Capabilities</PillBadge></motion.div>
                        <motion.h2 variants={fadeUp} className="text-4xl font-extrabold text-white tracking-tight">
                            Eight Layers of AI Defense
                        </motion.h2>
                        <motion.p variants={fadeUp} className="text-[15px] text-slate-500 max-w-lg mx-auto leading-relaxed">
                            Every attack surface covered by a purpose-built ML model, unified in a single analyst console.
                        </motion.p>
                    </motion.div>

                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5"
                    >
                        {features.map((f, i) => <FeatureCard key={f.title} {...f} delay={i * 50} />)}
                    </motion.div>
                </div>
            </section>

            {/* ── DASHBOARD PREVIEW ── */}
            <section id="dashboard" className="w-full border-t border-white/[0.06] py-28 bg-[#0F1117]/50">
                <div className="max-w-7xl mx-auto px-6">
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="text-center mb-16 space-y-4"
                    >
                        <motion.div variants={fadeUp}><PillBadge>Live Console Preview</PillBadge></motion.div>
                        <motion.h2 variants={fadeUp} className="text-4xl font-extrabold text-white tracking-tight">
                            Your Security Command Center
                        </motion.h2>
                        <motion.p variants={fadeUp} className="text-[15px] text-slate-500 max-w-xl mx-auto leading-relaxed">
                            Real-time threat charts, alert timelines, risk gauges, and MITRE mappings — all in one glassmorphism analyst dashboard.
                        </motion.p>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 30 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
                        className="relative"
                    >
                        <div className="absolute inset-0 bg-gradient-to-br from-[#FF6A3D]/15 via-transparent to-[#5AA9FF]/10 blur-3xl -z-10 rounded-3xl" />

                        <div className="bg-[#111318]/90 border border-white/[0.08] rounded-3xl overflow-hidden shadow-2xl backdrop-blur-xl">
                            {/* Mock top bar */}
                            <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.06] bg-black/30">
                                <div className="flex items-center gap-3">
                                    <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#FF6A3D] to-[#FF8C42] flex items-center justify-center">
                                        <Shield size={14} className="text-white" />
                                    </div>
                                    <span className="text-[12px] font-bold text-white tracking-wider">CYBERGUARD ANALYST CONSOLE</span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <div className="w-2 h-2 rounded-full bg-[#36D399] animate-pulse" />
                                    <span className="text-[10px] text-[#36D399] font-bold">LIVE</span>
                                </div>
                            </div>

                            <div className="p-6 grid grid-cols-1 lg:grid-cols-12 gap-5">
                                {/* Stats row */}
                                {[
                                    { label: 'Threats Blocked', val: '2,847', color: '#FF3D57' },
                                    { label: 'Active Alerts', val: '23', color: '#FF6A3D' },
                                    { label: 'Scans Today', val: '1,204', color: '#5AA9FF' },
                                    { label: 'Risk Score', val: '69', color: '#A78BFA' },
                                ].map((s, i) => (
                                    <motion.div
                                        key={s.label}
                                        initial={{ opacity: 0, y: 10 }}
                                        whileInView={{ opacity: 1, y: 0 }}
                                        viewport={{ once: true }}
                                        transition={{ delay: i * 0.08 }}
                                        className="lg:col-span-3 bg-black/25 border border-white/[0.05] rounded-2xl p-5"
                                    >
                                        <div className="text-[10px] text-slate-600 uppercase tracking-widest mb-2">{s.label}</div>
                                        <div className="text-2xl font-extrabold font-mono" style={{ color: s.color }}>{s.val}</div>
                                    </motion.div>
                                ))}

                                {/* Threat chart */}
                                <div className="lg:col-span-7 bg-black/25 border border-white/[0.05] rounded-2xl p-5">
                                    <div className="text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-4">Threat Volume — 24h</div>
                                    <div className="flex items-end gap-2 h-32">
                                        {[28, 45, 38, 62, 55, 78, 48, 85, 62, 91, 74, 88].map((h, i) => (
                                            <motion.div
                                                key={i}
                                                initial={{ scaleY: 0 }}
                                                whileInView={{ scaleY: 1 }}
                                                viewport={{ once: true }}
                                                transition={{ delay: i * 0.04 + 0.2 }}
                                                className="flex-1 rounded-sm origin-bottom"
                                                style={{
                                                    height: `${h}%`,
                                                    background: i >= 9 ? '#FF6A3D' : i >= 6 ? 'rgba(255,106,61,0.5)' : 'rgba(90,169,255,0.3)',
                                                }}
                                            />
                                        ))}
                                    </div>
                                </div>

                                {/* Pie / severity */}
                                <div className="lg:col-span-5 bg-black/25 border border-white/[0.05] rounded-2xl p-5 flex flex-col items-center">
                                    <div className="text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-4 self-start">Severity Breakdown</div>
                                    <div className="relative w-28 h-28">
                                        <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                                            <circle cx="18" cy="18" r="14" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="5" />
                                            <circle cx="18" cy="18" r="14" fill="none" stroke="#36D399" strokeWidth="5" strokeDasharray="35 88" />
                                            <circle cx="18" cy="18" r="14" fill="none" stroke="#FFC857" strokeWidth="5" strokeDasharray="20 88" strokeDashoffset="-35" />
                                            <circle cx="18" cy="18" r="14" fill="none" stroke="#FF6A3D" strokeWidth="5" strokeDasharray="18 88" strokeDashoffset="-55" />
                                            <circle cx="18" cy="18" r="14" fill="none" stroke="#FF3D57" strokeWidth="5" strokeDasharray="15 88" strokeDashoffset="-73" />
                                        </svg>
                                    </div>
                                    <div className="flex flex-wrap gap-3 mt-4 justify-center">
                                        {[
                                            { c: '#36D399', l: 'Safe 40%' },
                                            { c: '#FFC857', l: 'Susp. 22%' },
                                            { c: '#FF6A3D', l: 'High 20%' },
                                            { c: '#FF3D57', l: 'Crit. 18%' },
                                        ].map(x => (
                                            <div key={x.l} className="flex items-center gap-1.5 text-[10px] text-slate-500">
                                                <div className="w-2 h-2 rounded-full" style={{ background: x.c }} />{x.l}
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Recent alerts */}
                                <div className="lg:col-span-4 bg-black/25 border border-white/[0.05] rounded-2xl p-5">
                                    <div className="text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-4">Recent Alerts</div>
                                    <div className="space-y-3">
                                        {[
                                            { title: 'SQL Injection Detected', entity: '192.168.1.44', sev: '#FF3D57' },
                                            { title: 'Phishing URL Blocked', entity: 'malware-drop.ru', sev: '#FF6A3D' },
                                            { title: 'Impossible Travel', entity: 'user@corp.com', sev: '#FFC857' },
                                        ].map(a => (
                                            <div key={a.title} className="flex items-start gap-3 p-3 bg-black/20 border border-white/[0.04] rounded-xl">
                                                <div className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0" style={{ background: a.sev }} />
                                                <div className="min-w-0">
                                                    <div className="text-[11px] font-bold text-white truncate">{a.title}</div>
                                                    <div className="text-[10px] text-slate-600 font-mono truncate">{a.entity}</div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Risk gauge */}
                                <div className="lg:col-span-4 bg-black/25 border border-white/[0.05] rounded-2xl p-5 flex flex-col items-center justify-center">
                                    <div className="text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-4 self-start">Workspace Risk</div>
                                    <div className="relative w-32 h-32">
                                        <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                                            <circle cx="18" cy="18" r="15" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3" />
                                            <circle cx="18" cy="18" r="15" fill="none" stroke="#FF6A3D" strokeWidth="3"
                                                strokeDasharray="58 94" strokeLinecap="round" />
                                        </svg>
                                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                                            <span className="text-2xl font-extrabold text-white">69</span>
                                            <span className="text-[9px] text-slate-600 uppercase">Medium-High</span>
                                        </div>
                                    </div>
                                </div>

                                {/* Heatmap / timeline */}
                                <div className="lg:col-span-4 bg-black/25 border border-white/[0.05] rounded-2xl p-5">
                                    <div className="text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-4">Login Heatmap</div>
                                    <div className="grid grid-cols-12 gap-1">
                                        {[0.04,0.04,0.08,0.15,0.22,0.35,0.45,0.55,0.62,0.48,0.3,0.12,0.04,0.04,0.06,0.1,0.18,0.28,0.4,0.52,0.65,0.5,0.35,0.15].map((op, i) => (
                                            <div
                                                key={i}
                                                className="aspect-square rounded-sm"
                                                style={{ background: `rgba(255,106,61,${op})` }}
                                            />
                                        ))}
                                    </div>
                                    <div className="mt-4 space-y-2">
                                        {['MITRE T1566 — Phishing', 'MITRE T1190 — Exploit Public'].map(t => (
                                            <div key={t} className="text-[10px] text-slate-500 font-mono flex items-center gap-2">
                                                <Target size={10} className="text-[#5AA9FF]" />{t}
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                </div>
            </section>

            {/* ── WHY CYBERGUARD ── */}
            <section className="w-full border-t border-white/[0.06] py-28 bg-[#0F1117]/40">
                <div className="max-w-7xl mx-auto px-6 grid grid-cols-1 lg:grid-cols-2 gap-20 items-center">
                    <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger} className="space-y-10">
                        <div className="space-y-5">
                            <PillBadge>Why CyberGuard AI</PillBadge>
                            <h2 className="text-4xl font-extrabold text-white tracking-tight">
                                Enterprise Security,<br />Zero Complexity
                            </h2>
                            <p className="text-[15px] text-slate-500 max-w-lg leading-relaxed">
                                Built for security teams who need results, not configuration. Deploy in minutes and get enterprise-grade threat coverage from day one.
                            </p>
                        </div>
                        <div className="space-y-5">
                            {[
                                { icon: TrendingUp,    color: '#FF6A3D', title: '93% Detection Accuracy',  desc: 'Industry-leading F1 score of 91.7% across all four threat vectors.' },
                                { icon: Zap,           color: '#5AA9FF', title: 'AI-Powered in Real-Time',  desc: 'Sub-15ms ensemble inference pipeline with zero analyst overhead.' },
                                { icon: Activity,      color: '#36D399', title: 'Continuous Monitoring',    desc: '24/7 autonomous watchdog with configurable alerting thresholds.' },
                                { icon: AlertTriangle, color: '#FFC857', title: '38% Fewer False Alarms',   desc: 'Contextual ML reduces noise so analysts focus on real threats only.' },
                                { icon: Layers,        color: '#A78BFA', title: 'Enterprise-Grade RBAC',    desc: 'Multi-tenant workspaces with audit logs, MFA, and SOC2-ready posture.' },
                            ].map(({ icon: Icon, color, title, desc }) => (
                                <motion.div key={title} variants={fadeUp} className="flex gap-4">
                                    <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 mt-0.5"
                                        style={{ background: `${color}14`, border: `1px solid ${color}25`, color }}>
                                        <Icon size={18} />
                                    </div>
                                    <div>
                                        <h4 className="text-[14px] font-bold text-white mb-1">{title}</h4>
                                        <p className="text-[13px] text-slate-500 leading-relaxed">{desc}</p>
                                    </div>
                                </motion.div>
                            ))}
                        </div>
                    </motion.div>

                    {/* Stats panel */}
                    <motion.div
                        initial={{ opacity: 0, x: 30 }} whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }} transition={{ duration: 0.65 }}
                        className="bg-[#111318] border border-white/[0.07] rounded-2xl p-10 space-y-8"
                    >
                        <div className="grid grid-cols-2 gap-8">
                            {[
                                { val: '93%', label: 'Detection Rate', color: '#FF6A3D' },
                                { val: '91.7%', label: 'F1 Score', color: '#36D399' },
                                { val: '5M+', label: 'Records Tested', color: '#5AA9FF' },
                                { val: '<15ms', label: 'Avg Latency', color: '#A78BFA' },
                            ].map(s => (
                                <div key={s.label} className="text-center space-y-1.5">
                                    <div className="text-3xl font-extrabold font-mono" style={{ color: s.color }}>{s.val}</div>
                                    <div className="text-[11px] text-slate-500 uppercase tracking-widest">{s.label}</div>
                                </div>
                            ))}
                        </div>
                        <div className="border-t border-white/[0.06] pt-7 space-y-4">
                            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-[0.12em] mb-4">Integrated AI Engines</div>
                            {[
                                { label: 'URL Phishing Classifier',  color: '#FF6A3D', acc: '94%' },
                                { label: 'Email LSTM Filter',         color: '#FF8C42', acc: '91%' },
                                { label: 'Network IDS Engine',        color: '#5AA9FF', acc: '92%' },
                                { label: 'Web Attack Blocker',        color: '#36D399', acc: '96%' },
                            ].map(m => (
                                <div key={m.label} className="flex items-center gap-3">
                                    <CheckCircle size={14} className="flex-shrink-0" style={{ color: m.color }} />
                                    <span className="text-[13px] text-slate-300 flex-1">{m.label}</span>
                                    <span className="text-[11px] font-bold font-mono" style={{ color: m.color }}>{m.acc}</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                </div>
            </section>

            {/* ── WORKFLOW ── */}
            <section id="documentation" className="w-full border-t border-white/[0.06] py-28">
                <div className="max-w-7xl mx-auto px-6">
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="text-center mb-20 space-y-4"
                    >
                        <motion.div variants={fadeUp}><PillBadge>Detection Pipeline</PillBadge></motion.div>
                        <motion.h2 variants={fadeUp} className="text-4xl font-extrabold text-white tracking-tight">How It Works</motion.h2>
                        <motion.p variants={fadeUp} className="text-[15px] text-slate-500 max-w-md mx-auto">
                            From raw input to analyst alert in milliseconds — fully autonomous.
                        </motion.p>
                    </motion.div>

                    <div className="flex flex-wrap justify-center items-start gap-3 md:gap-0">
                        {workflow.map((step, i) => (
                            <div key={step.label} className="flex items-start gap-0 md:px-6 first:pl-0 last:pr-0">
                                <div className={`flex flex-col items-center gap-3 transition-all duration-300 ${activeStep === i ? 'opacity-100' : 'opacity-40'}`}>
                                    <div className={`w-14 h-14 rounded-2xl flex items-center justify-center font-extrabold text-lg border-2 transition-all duration-300 ${
                                        activeStep === i
                                            ? 'border-transparent text-white shadow-[0_0_24px_rgba(255,106,61,0.5)]'
                                            : 'bg-[#111318] border-white/10 text-slate-500'
                                    }`}
                                        style={activeStep === i ? { background: 'linear-gradient(135deg, #FF6A3D, #FF8C42)' } : {}}>
                                        {step.icon}
                                    </div>
                                    <div className="text-center">
                                        <div className="text-[13px] font-bold text-white">{step.label}</div>
                                        <div className="text-[11px] text-slate-600 mt-0.5 max-w-[80px] text-center">{step.desc}</div>
                                    </div>
                                </div>
                                {i < workflow.length - 1 && (
                                    <div className="hidden md:flex items-center self-start mt-7 ml-6">
                                        <ArrowRight size={14} className="text-slate-700" />
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── TECHNOLOGY ── */}
            <section className="w-full border-t border-white/[0.06] py-24 bg-[#0F1117]/40">
                <div className="max-w-7xl mx-auto px-6">
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="text-center mb-12 space-y-4"
                    >
                        <motion.div variants={fadeUp}><PillBadge><Cpu size={10} /> Technology Stack</PillBadge></motion.div>
                        <motion.h2 variants={fadeUp} className="text-3xl font-extrabold text-white tracking-tight">
                            Built with Modern Infrastructure
                        </motion.h2>
                    </motion.div>
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="flex flex-wrap justify-center gap-3"
                    >
                        {techs.map(t => (
                            <motion.div
                                key={t.label} variants={fadeUp}
                                whileHover={{ y: -3, transition: { duration: 0.15 } }}
                                className={`px-5 py-2.5 rounded-xl border text-[13px] font-bold font-mono cursor-default ${t.color}`}
                            >
                                {t.label}
                            </motion.div>
                        ))}
                    </motion.div>
                </div>
            </section>

            {/* ── TEAM ── */}
            <section id="about" className="w-full border-t border-white/[0.06] py-28">
                <div className="max-w-7xl mx-auto px-6">
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="text-center mb-16 space-y-3"
                    >
                        <motion.div variants={fadeUp}><PillBadge>Engineering Team</PillBadge></motion.div>
                        <motion.h2 variants={fadeUp} className="text-3xl font-extrabold text-white tracking-tight">Meet the Builders</motion.h2>
                        <motion.p variants={fadeUp} className="text-[14px] text-slate-500">
                            Sir Syed University of Engineering &amp; Technology · Computer Engineering · Group 17
                        </motion.p>
                    </motion.div>
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5"
                    >
                        {team.map((m) => (
                            <motion.div
                                key={m.id} variants={fadeUp}
                                whileHover={{ y: -5, transition: { duration: 0.2 } }}
                                className="bg-[#111318] border border-white/[0.07] rounded-2xl p-7 text-center space-y-4 hover:border-white/[0.14] transition-colors group"
                            >
                                <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-[#FF6A3D] to-[#FF8C42] flex items-center justify-center text-white font-extrabold text-lg mx-auto shadow-[0_0_20px_rgba(255,106,61,0.3)] group-hover:shadow-[0_0_30px_rgba(255,106,61,0.45)] transition-shadow">
                                    {m.initials}
                                </div>
                                <div>
                                    <h4 className="font-bold text-white text-[14px]">{m.name}</h4>
                                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block mt-1">{m.id}</span>
                                </div>
                                <span className="inline-block text-[10px] font-bold text-blue-400 bg-blue-500/10 border border-blue-500/20 rounded-lg px-3 py-1 uppercase tracking-wider">
                                    {m.role}
                                </span>
                            </motion.div>
                        ))}
                    </motion.div>
                </div>
            </section>

            {/* ── CTA ── */}
            <section id="pricing" className="w-full border-t border-white/[0.06] py-28 bg-[#0F1117]/40">
                <div className="max-w-3xl mx-auto px-6 text-center">
                    <motion.div
                        initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}
                        className="space-y-8"
                    >
                        <motion.div variants={fadeUp}>
                            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-[#FF6A3D] to-[#FF8C42] mx-auto mb-6 shadow-[0_0_40px_rgba(255,106,61,0.5)]">
                                <Shield size={28} className="text-white" />
                            </div>
                        </motion.div>
                        <motion.h2 variants={fadeUp} className="text-4xl md:text-5xl font-extrabold text-white tracking-tight">
                            Ready to Secure Your<br />Infrastructure?
                        </motion.h2>
                        <motion.p variants={fadeUp} className="text-[15px] text-slate-500 max-w-md mx-auto leading-relaxed">
                            Spin up your private CyberGuard AI workspace in seconds. No credit card required. All 4 AI engines pre-configured.
                        </motion.p>
                        <motion.div variants={fadeUp} className="flex flex-wrap justify-center gap-4">
                            <button
                                onClick={onRegister}
                                className="inline-flex items-center gap-2.5 px-8 py-4 rounded-xl text-white font-bold text-[15px] active:scale-[0.97] transition-all"
                                style={{ background: 'linear-gradient(135deg, #FF6A3D, #FF8C42)', boxShadow: '0 0 40px rgba(255,106,61,0.5)' }}
                            >
                                Create Free Account <ArrowRight size={16} />
                            </button>
                            <button
                                onClick={onLogin}
                                className="inline-flex items-center gap-2.5 px-8 py-4 rounded-xl border border-white/[0.12] bg-white/[0.04] text-white font-semibold text-[15px] hover:bg-white/[0.08] transition-all"
                            >
                                Sign In to Console
                            </button>
                        </motion.div>
                        <motion.div variants={fadeUp} className="flex justify-center gap-6 pt-2">
                            {['No credit card', 'Deploy in 60s', 'MFA & RBAC built-in'].map(t => (
                                <div key={t} className="flex items-center gap-1.5 text-[12px] text-slate-600">
                                    <CheckCircle size={12} className="text-[#36D399]" /> {t}
                                </div>
                            ))}
                        </motion.div>
                    </motion.div>
                </div>
            </section>

            {/* ── FOOTER ── */}
            <footer className="w-full border-t border-white/[0.06] bg-[#080A0E]">
                <div className="max-w-7xl mx-auto px-6 py-14">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-10">
                        {/* Brand */}
                        <div className="md:col-span-1 space-y-4">
                            <div className="flex items-center gap-2.5">
                                <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-[#FF6A3D] to-[#FF8C42] flex items-center justify-center">
                                    <Shield size={15} className="text-white" />
                                </div>
                                <span className="font-extrabold text-[13px] tracking-widest text-white">CYBERGUARD AI</span>
                            </div>
                            <p className="text-[12px] text-slate-600 leading-relaxed">
                                AI-powered cybersecurity platform. Final Year Project — Sir Syed University of Engineering &amp; Technology
                            </p>
                            <div className="flex gap-3">
                                {['GH', 'TW', 'IN'].map(s => (
                                    <div key={s} className="w-8 h-8 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-[10px] font-bold text-slate-600 hover:border-white/[0.12] hover:text-slate-400 cursor-pointer transition-all">
                                        {s}
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Links */}
                        {[
                            { title: 'Product', links: ['Features', 'Dashboard', 'API', 'Pricing'] },
                            { title: 'Docs', links: ['Getting Started', 'API Reference', 'Architecture', 'System Manual'] },
                            { title: 'Company', links: ['About', 'Privacy Policy', 'Terms of Service', 'Contact'] },
                        ].map(col => (
                            <div key={col.title}>
                                <div className="text-[11px] font-bold text-slate-500 uppercase tracking-[0.12em] mb-4">{col.title}</div>
                                <div className="space-y-2.5">
                                    {col.links.map(l => (
                                        <div
                                            key={l}
                                            onClick={() => scrollToSection(l)}
                                            className="text-[13px] text-slate-500 hover:text-slate-300 cursor-pointer transition-colors"
                                        >
                                            {l}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
                <div className="border-t border-white/[0.04] py-5 text-center text-[11px] text-slate-700 font-mono">
                    &copy; 2026 CyberGuard AI &middot; Project Batch 2022F &middot; Department of Computer Engineering &middot; All Rights Reserved
                </div>
            </footer>
        </div>
    );
};

export default LandingPage;
