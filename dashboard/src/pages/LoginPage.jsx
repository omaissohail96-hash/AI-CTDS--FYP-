import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import API_BASE from '../config/api';
import {
    Shield, Mail, Lock, ArrowRight, Loader, Eye, EyeOff,
    AlertCircle, CheckCircle, Zap, Activity, Globe,
    Network, BrainCircuit, Target
} from 'lucide-react';

/* ── Shared InputField ───────────────────────────── */
const InputField = ({ label, icon: Icon, type = 'text', placeholder, value, onChange, required, rightSlot, autoComplete }) => (
    <div className="space-y-2">
        <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-[0.1em]">{label}</label>
        <div className="relative flex items-center group">
            <Icon size={15} className="absolute left-4 text-slate-600 pointer-events-none group-focus-within:text-[#FF6A3D] transition-colors" />
            <input
                type={type}
                placeholder={placeholder}
                value={value}
                onChange={onChange}
                required={required}
                autoComplete={autoComplete}
                className="w-full bg-[#0F1117] border border-white/[0.07] rounded-xl pl-11 pr-11 py-3.5 text-[14px] text-white placeholder-slate-700 focus:outline-none focus:border-[#FF6A3D]/50 focus:ring-2 focus:ring-[#FF6A3D]/12 focus:bg-[#0F1117] transition-all duration-200"
            />
            {rightSlot && <div className="absolute right-4">{rightSlot}</div>}
        </div>
    </div>
);

/* ── Main Component ──────────────────────────────── */
const LoginPage = ({ onLogin, onToggleForm }) => {
    const [email,    setEmail]    = useState('');
    const [password, setPassword] = useState('');
    const [showPw,   setShowPw]   = useState(false);
    const [error,    setError]    = useState('');
    const [loading,  setLoading]  = useState(false);

    // MFA
    const [requiresMfa, setRequiresMfa] = useState(false);
    const [mfaCode,     setMfaCode]     = useState('');
    const [mfaToken,    setMfaToken]    = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        if (requiresMfa) {
            try {
                const res = await axios.post(
                    `${API_BASE}/mfa/verify-login`,
                    { code: mfaCode },
                    { headers: { Authorization: `Bearer ${mfaToken}` } }
                );
                const token = res.data.access_token;
                localStorage.setItem('token', token);
                onLogin(token);
            } catch (err) {
                setError(err.response?.data?.detail || 'Invalid MFA code. Please try again.');
            } finally {
                setLoading(false);
            }
            return;
        }

        try {
            const fd = new FormData();
            fd.append('username', email);
            fd.append('password', password);
            const res = await axios.post(`${API_BASE}/login/access-token`, fd);
            if (res.data.token_type === 'mfa') {
                setRequiresMfa(true);
                setMfaToken(res.data.access_token);
            } else {
                const token = res.data.access_token;
                localStorage.setItem('token', token);
                onLogin(token);
            }
        } catch (err) {
            setError(err.response?.data?.detail || 'Invalid email or password. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const features = [
        { icon: Activity,    color: 'text-blue-400 bg-blue-500/10 border-blue-500/20',   label: '93% Detection Accuracy', sub: 'Ensemble ML classifier' },
        { icon: Zap,         color: 'text-[#FF6A3D] bg-[#FF6A3D]/10 border-[#FF6A3D]/20', label: '<15ms Inference Speed', sub: 'Real-time analysis' },
        { icon: BrainCircuit,color: 'text-purple-400 bg-purple-500/10 border-purple-500/20', label: '4 AI Detection Engines', sub: 'URL · Email · Network · Web' },
        { icon: Globe,       color: 'text-green-400 bg-green-500/10 border-green-500/20', label: '5M+ Threats Analyzed', sub: 'Production-grade models' },
    ];

    return (
        <div className="min-h-screen bg-[#09090B] flex items-stretch relative overflow-hidden font-inter">

            {/* Ambient glows */}
            <div className="fixed top-1/3 left-1/4 w-[600px] h-[600px] rounded-full pointer-events-none -z-10"
                style={{ background: 'radial-gradient(circle, rgba(255,106,61,0.07) 0%, transparent 65%)' }} />
            <div className="fixed bottom-0 right-0 w-[400px] h-[400px] rounded-full pointer-events-none -z-10"
                style={{ background: 'radial-gradient(circle at 100% 100%, rgba(255,140,66,0.05) 0%, transparent 55%)' }} />

            {/* ── LEFT INFO PANEL ── */}
            <div className="hidden lg:flex flex-col justify-between w-[480px] flex-shrink-0 bg-gradient-to-br from-[#111318] via-[#0F1117] to-[#09090B] p-12 border-r border-white/[0.06] relative overflow-hidden">
                {/* BG grid */}
                <div className="absolute inset-0 pointer-events-none"
                    style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)', backgroundSize: '40px 40px' }} />
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-[#09090B]/80 pointer-events-none" />

                <div className="relative z-10">
                    {/* Logo */}
                    <div className="flex items-center gap-3 mb-16">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#FF6A3D] to-[#FF8C42] flex items-center justify-center shadow-[0_0_24px_rgba(255,106,61,0.5)]">
                            <Shield size={19} className="text-white" />
                        </div>
                        <div className="leading-tight">
                            <span className="block font-extrabold text-[13px] tracking-widest text-white">CYBERGUARD</span>
                            <span className="block text-[9px] font-bold text-[#FF6A3D] tracking-[0.25em] uppercase">AI Platform</span>
                        </div>
                    </div>

                    {/* Headline */}
                    <div className="space-y-5 mb-14">
                        <h2 className="text-3xl font-extrabold text-white leading-tight tracking-tight">
                            Enterprise Threat<br />Intelligence Platform
                        </h2>
                        <p className="text-[14px] text-slate-500 leading-relaxed max-w-sm">
                            Autonomous AI detection across URLs, emails, network flows, and web attack surfaces — unified in a single analyst console.
                        </p>
                    </div>

                    {/* Feature list */}
                    <div className="space-y-4">
                        {features.map(({ icon: Icon, color, label, sub }) => (
                            <div key={label} className="flex items-center gap-4">
                                <div className={`w-10 h-10 rounded-xl flex items-center justify-center border flex-shrink-0 ${color}`}>
                                    <Icon size={17} />
                                </div>
                                <div>
                                    <div className="text-[13px] font-bold text-white">{label}</div>
                                    <div className="text-[11px] text-slate-600 mt-0.5">{sub}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Live status pill */}
                <div className="relative z-10 flex items-center gap-3 p-4 bg-[#161A22] border border-white/[0.07] rounded-xl">
                    <div className="relative">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#36D399]" />
                        <div className="absolute inset-0 rounded-full bg-[#36D399] animate-ping opacity-60" />
                    </div>
                    <div>
                        <div className="text-[12px] font-bold text-white">All AI Engines Active</div>
                        <div className="text-[10px] text-slate-600 mt-0.5">Sir Syed University of Engineering &amp; Technology</div>
                    </div>
                </div>
            </div>

            {/* ── RIGHT FORM PANEL ── */}
            <div className="flex-1 flex items-center justify-center p-8 md:p-12 lg:p-16">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
                    className="w-full max-w-md space-y-8"
                >
                    {/* Mobile brand header */}
                    <div className="lg:hidden flex items-center gap-3 mb-2">
                        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#FF6A3D] to-[#FF8C42] flex items-center justify-center shadow-[0_0_16px_rgba(255,106,61,0.4)]">
                            <Shield size={16} className="text-white" />
                        </div>
                        <span className="font-extrabold text-[13px] tracking-widest text-white">CYBERGUARD AI</span>
                    </div>

                    {/* Heading */}
                    <div className="space-y-2">
                        <h1 className="text-2xl font-extrabold text-white tracking-tight">
                            {requiresMfa ? 'Two-Factor Verification' : 'Welcome back'}
                        </h1>
                        <p className="text-[13px] text-slate-500">
                            {requiresMfa
                                ? 'Enter the 6-digit code from your authenticator app.'
                                : 'Sign in to your CyberGuard AI console.'}
                        </p>
                    </div>

                    {/* Error banner */}
                    <AnimatePresence>
                        {error && (
                            <motion.div
                                initial={{ opacity: 0, y: -8, height: 0 }}
                                animate={{ opacity: 1, y: 0,  height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                                className="flex items-start gap-3 p-4 bg-[#FF3D57]/10 border border-[#FF3D57]/20 rounded-xl overflow-hidden"
                            >
                                <AlertCircle size={15} className="text-[#FF3D57] flex-shrink-0 mt-0.5" />
                                <p className="text-[13px] text-[#FF3D57] leading-relaxed">{error}</p>
                            </motion.div>
                        )}
                    </AnimatePresence>

                    {/* Form */}
                    <form onSubmit={handleSubmit} className="space-y-5">
                        {!requiresMfa ? (
                            <>
                                <InputField
                                    label="Email Address"
                                    icon={Mail}
                                    type="email"
                                    placeholder="name@company.com"
                                    value={email}
                                    onChange={e => setEmail(e.target.value)}
                                    required
                                    autoComplete="email"
                                />
                                <InputField
                                    label="Password"
                                    icon={Lock}
                                    type={showPw ? 'text' : 'password'}
                                    placeholder="••••••••••"
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    required
                                    autoComplete="current-password"
                                    rightSlot={
                                        <button type="button" onClick={() => setShowPw(v => !v)}
                                            className="text-slate-600 hover:text-slate-400 transition-colors" tabIndex={-1}>
                                            {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                                        </button>
                                    }
                                />
                                <div className="flex items-center justify-between pt-1">
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input type="checkbox" className="w-4 h-4 accent-[#FF6A3D] rounded" />
                                        <span className="text-[12px] text-slate-500">Remember me</span>
                                    </label>
                                    <button type="button" className="text-[12px] text-[#FF6A3D] hover:underline font-semibold">
                                        Forgot password?
                                    </button>
                                </div>
                            </>
                        ) : (
                            <div className="space-y-2">
                                <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-[0.1em]">MFA Code</label>
                                <div className="relative flex items-center group">
                                    <Shield size={15} className="absolute left-4 text-slate-600 pointer-events-none" />
                                    <input
                                        type="text"
                                        inputMode="numeric"
                                        maxLength={8}
                                        placeholder="000 000"
                                        value={mfaCode}
                                        onChange={e => setMfaCode(e.target.value)}
                                        required
                                        className="w-full bg-[#0F1117] border border-white/[0.07] rounded-xl pl-11 pr-4 py-3.5 text-[15px] font-mono text-center tracking-[0.4em] text-white placeholder-slate-700 focus:outline-none focus:border-[#FF6A3D]/50 focus:ring-2 focus:ring-[#FF6A3D]/12 transition-all"
                                    />
                                </div>
                                <p className="text-[11px] text-slate-600 text-center mt-2">Enter the 6-digit code from your authenticator.</p>
                            </div>
                        )}

                        <motion.button
                            type="submit"
                            disabled={loading}
                            whileHover={{ scale: loading ? 1 : 1.01 }}
                            whileTap={{ scale: loading ? 1 : 0.98 }}
                            className="w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl font-bold text-[14px] text-white transition-all disabled:opacity-60 disabled:cursor-not-allowed"
                            style={{ background: 'linear-gradient(135deg, #FF6A3D, #FF8C42)', boxShadow: '0 0 24px rgba(255,106,61,0.35)' }}
                        >
                            {loading ? (
                                <><Loader size={15} className="animate-spin" /> Authenticating...</>
                            ) : (
                                <>{requiresMfa ? 'Verify Code' : 'Sign In'} <ArrowRight size={15} /></>
                            )}
                        </motion.button>
                    </form>

                    {/* Divider */}
                    <div className="relative flex items-center">
                        <div className="flex-1 border-t border-white/[0.06]" />
                        <span className="px-4 text-[11px] text-slate-700 uppercase tracking-widest">or continue with</span>
                        <div className="flex-1 border-t border-white/[0.06]" />
                    </div>

                    {/* Social buttons */}
                    <div className="grid grid-cols-2 gap-3">
                        {[
                            { label: 'Google', icon: '🔵' },
                            { label: 'GitHub', icon: '⚫' },
                        ].map(({ label, icon }) => (
                            <button
                                key={label}
                                type="button"
                                disabled
                                className="flex items-center justify-center gap-2.5 py-3 rounded-xl border border-white/[0.07] bg-white/[0.02] text-[13px] text-slate-600 cursor-not-allowed hover:border-white/[0.12] transition-colors"
                            >
                                <span>{icon}</span> {label}
                            </button>
                        ))}
                    </div>

                    <p className="text-center text-[13px] text-slate-600">
                        No account?{' '}
                        <button type="button" onClick={onToggleForm} className="text-[#FF6A3D] font-bold hover:underline">
                            Create workspace
                        </button>
                    </p>
                </motion.div>
            </div>
        </div>
    );
};

export default LoginPage;
