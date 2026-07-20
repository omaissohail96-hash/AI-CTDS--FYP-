import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import API_BASE from '../config/api';
import { supabase } from '../config/supabaseClient';
import {
    Shield, Mail, Lock, User, Building, ArrowRight,
    Loader, Eye, EyeOff, AlertCircle, CheckCircle, X
} from 'lucide-react';

/* ── password strength helper ────────────────────── */
const getStrength = (pw) => {
    let score = 0;
    if (pw.length >= 8)           score++;
    if (/[A-Z]/.test(pw))         score++;
    if (/[0-9]/.test(pw))         score++;
    if (/[^A-Za-z0-9]/.test(pw))  score++;
    return score; // 0-4
};
const strengthMeta = [
    { label: 'Too weak',    color: '#FF3D57', bg: 'bg-[#FF3D57]' },
    { label: 'Weak',        color: '#FF8C42', bg: 'bg-[#FF8C42]' },
    { label: 'Fair',        color: '#FBBF24', bg: 'bg-yellow-400' },
    { label: 'Strong',      color: '#36D399', bg: 'bg-[#36D399]' },
    { label: 'Very strong', color: '#36D399', bg: 'bg-[#36D399]' },
];

/* ── Field component ─────────────────────────────── */
const Field = ({ label, icon: Icon, type = 'text', name, placeholder, value, onChange, required, rightSlot, error }) => (
    <div className="space-y-2">
        <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-[0.1em]">{label}</label>
        <div className="relative flex items-center group">
            <Icon size={15} className="absolute left-4 text-slate-600 pointer-events-none group-focus-within:text-[#FF6A3D] transition-colors" />
            <input
                type={type}
                name={name}
                placeholder={placeholder}
                value={value}
                onChange={onChange}
                required={required}
                className={`w-full bg-[#0F1117] rounded-xl pl-11 pr-11 py-3.5 text-[14px] text-white placeholder-slate-700 border transition-all duration-200 focus:outline-none focus:ring-2
                    ${error
                        ? 'border-[#FF3D57]/40 focus:border-[#FF3D57]/60 focus:ring-[#FF3D57]/12'
                        : 'border-white/[0.07] focus:border-[#FF6A3D]/50 focus:ring-[#FF6A3D]/12'
                    }`}
            />
            {rightSlot && <div className="absolute right-4">{rightSlot}</div>}
        </div>
        <AnimatePresence>
            {error && (
                <motion.p
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="text-[11px] text-[#FF3D57] flex items-center gap-1.5 overflow-hidden"
                >
                    <X size={10} /> {error}
                </motion.p>
            )}
        </AnimatePresence>
    </div>
);

/* ── Requirement row ─────────────────────────────── */
const Req = ({ met, label }) => (
    <div className="flex items-center gap-1.5">
        {met
            ? <CheckCircle size={11} className="text-[#36D399] flex-shrink-0" />
            : <X          size={11} className="text-slate-700 flex-shrink-0" />}
        <span className={`text-[11px] ${met ? 'text-[#36D399]' : 'text-slate-600'}`}>{label}</span>
    </div>
);

/* ── Main Component ──────────────────────────────── */
const RegisterPage = ({ onLogin, onToggleForm }) => {
    const [form, setForm] = useState({
        full_name:      '',
        email:          '',
        workspace_name: '',
        workspace_id:   '',
        password:       '',
        confirmPassword:'',
    });
    const [showPw,    setShowPw]    = useState(false);
    const [showCpw,   setShowCpw]   = useState(false);
    const [error,     setError]     = useState('');
    const [loading,   setLoading]   = useState(false);
    const [fieldErrors, setFieldErrors] = useState({});
    const [workspaceMode, setWorkspaceMode] = useState('create');

    const strength = useMemo(() => getStrength(form.password), [form.password]);
    const meta     = strengthMeta[strength];

    const change = e => {
        const { name, value } = e.target;
        setForm(f => ({ ...f, [name]: value }));
        setFieldErrors(fe => ({ ...fe, [name]: '' }));
    };

    const validate = () => {
        const errs = {};
        if (!form.full_name.trim())                          errs.full_name      = 'Full name is required.';
        if (!form.email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) errs.email         = 'Enter a valid email address.';
        if (workspaceMode === 'create' && !form.workspace_name.trim()) errs.workspace_name = 'Workspace name is required.';
        if (workspaceMode === 'join' && !form.workspace_id.trim())     errs.workspace_id = 'Workspace ID is required.';
        if (form.password.length < 8)                         errs.password      = 'Password must be at least 8 characters.';
        if (form.password !== form.confirmPassword)           errs.confirmPassword= 'Passwords do not match.';
        return errs;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        const errs = validate();
        if (Object.keys(errs).length) { setFieldErrors(errs); return; }

        setLoading(true);
        try {
            const { confirmPassword, ...payload } = form;
            if (workspaceMode === 'create') delete payload.workspace_id;
            else delete payload.workspace_name;
            const res = await axios.post(`${API_BASE}/register`, payload);
            const token = res.data.access_token;
            localStorage.setItem('token', token);
            onLogin(token);
        } catch (err) {
            setError(err.response?.data?.detail || 'Registration failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const handleGoogleSignup = async () => {
        setError('');
        if (workspaceMode === 'join' && !form.workspace_id.trim()) {
            setFieldErrors({ workspace_id: 'Workspace ID is required to request access.' });
            return;
        }
        setLoading(true);

        const { error: oauthError } = await supabase.auth.signInWithOAuth({
            provider: 'google',
            options: {
                data: workspaceMode === 'join'
                    ? { workspace_id: form.workspace_id.trim() }
                    : { workspace_name: form.workspace_name.trim() },
            },
        });

        if (oauthError) {
            setError(oauthError.message);
            setLoading(false);
        }
    };

    const pwReqs = [
        { met: form.password.length >= 8,            label: 'At least 8 characters' },
        { met: /[A-Z]/.test(form.password),           label: 'One uppercase letter' },
        { met: /[0-9]/.test(form.password),           label: 'One number' },
        { met: /[^A-Za-z0-9]/.test(form.password),   label: 'One special character' },
    ];

    const perks = [
        '✓  No credit card required',
        '✓  Deploy in under 60 seconds',
        '✓  4 AI engines pre-configured',
        '✓  MFA & RBAC out of the box',
        '✓  Full REST API access',
        '✓  SHAP explainability included',
    ];

    return (
        <div className="min-h-screen bg-[#09090B] flex items-stretch relative overflow-hidden font-inter">

            {/* Ambient glows */}
            <div className="fixed top-1/4 right-1/4 w-[600px] h-[600px] rounded-full pointer-events-none -z-10"
                style={{ background: 'radial-gradient(circle, rgba(255,106,61,0.07) 0%, transparent 65%)' }} />
            <div className="fixed bottom-0 left-0 w-[400px] h-[400px] rounded-full pointer-events-none -z-10"
                style={{ background: 'radial-gradient(circle at 0% 100%, rgba(255,140,66,0.05) 0%, transparent 55%)' }} />

            {/* ── LEFT INFO PANEL ── */}
            <div className="hidden lg:flex flex-col justify-between w-[440px] flex-shrink-0 bg-gradient-to-br from-[#111318] via-[#0F1117] to-[#09090B] p-12 border-r border-white/[0.06] relative overflow-hidden">
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
                    <div className="space-y-5 mb-12">
                        <h2 className="text-3xl font-extrabold text-white leading-tight tracking-tight">
                            Set Up Your Private<br />Security Workspace
                        </h2>
                        <p className="text-[14px] text-slate-500 leading-relaxed">
                            Deploy a multi-tenant CyberGuard AI instance with full API access, analyst dashboards, and real-time threat monitoring.
                        </p>
                    </div>

                    {/* Perks list */}
                    <div className="space-y-3.5 mb-12">
                        {perks.map(t => (
                            <div key={t} className="text-[13px] text-slate-400 font-medium">{t}</div>
                        ))}
                    </div>
                </div>

                {/* Live stat pill */}
                <div className="relative z-10 bg-[#161A22] border border-white/[0.07] rounded-xl p-4 flex items-center gap-4">
                    <div className="relative">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#36D399]" />
                        <div className="absolute inset-0 rounded-full bg-[#36D399] animate-ping opacity-60" />
                    </div>
                    <div>
                        <div className="text-[13px] font-bold text-white">93% Detection Accuracy</div>
                        <div className="text-[11px] text-slate-600 mt-0.5">Across 5M+ test records · Batch 2022F</div>
                    </div>
                </div>
            </div>

            {/* ── RIGHT FORM PANEL ── */}
            <div className="flex-1 flex items-center justify-center p-8 md:p-10 lg:p-14 overflow-y-auto">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
                    className="w-full max-w-md space-y-7 py-8"
                >
                    {/* Mobile brand */}
                    <div className="lg:hidden flex items-center gap-3">
                        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#FF6A3D] to-[#FF8C42] flex items-center justify-center shadow-[0_0_16px_rgba(255,106,61,0.4)]">
                            <Shield size={16} className="text-white" />
                        </div>
                        <span className="font-extrabold text-[13px] tracking-widest text-white">CYBERGUARD AI</span>
                    </div>

                    {/* Heading */}
                    <div className="space-y-2">
                        <h1 className="text-2xl font-extrabold text-white tracking-tight">Create your workspace</h1>
                        <p className="text-[13px] text-slate-500">Fill in the details below to get started.</p>
                    </div>

                    {/* Error banner */}
                    <AnimatePresence>
                        {error && (
                            <motion.div
                                initial={{ opacity: 0, y: -8, height: 0 }}
                                animate={{ opacity: 1, y: 0, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                                className="flex items-start gap-3 p-4 bg-[#FF3D57]/10 border border-[#FF3D57]/20 rounded-xl overflow-hidden"
                            >
                                <AlertCircle size={15} className="text-[#FF3D57] flex-shrink-0 mt-0.5" />
                                <p className="text-[13px] text-[#FF3D57] leading-relaxed">{error}</p>
                            </motion.div>
                        )}
                    </AnimatePresence>

                    <form onSubmit={handleSubmit} className="space-y-5" noValidate>
                        <Field
                            label="Full Name"
                            icon={User}
                            name="full_name"
                            placeholder="John Doe"
                            value={form.full_name}
                            onChange={change}
                            required
                            error={fieldErrors.full_name}
                        />
                        <div className="space-y-2">
                            <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-[0.1em]">Workspace Access</label>
                            <div className="grid grid-cols-2 gap-2">
                                <button type="button" onClick={() => setWorkspaceMode('create')} className={`py-3 rounded-xl border text-[12px] font-bold ${workspaceMode === 'create' ? 'border-[#FF6A3D]/50 bg-[#FF6A3D]/10 text-white' : 'border-white/[0.07] text-slate-500'}`}>Create workspace</button>
                                <button type="button" onClick={() => setWorkspaceMode('join')} className={`py-3 rounded-xl border text-[12px] font-bold ${workspaceMode === 'join' ? 'border-[#FF6A3D]/50 bg-[#FF6A3D]/10 text-white' : 'border-white/[0.07] text-slate-500'}`}>Join workspace</button>
                            </div>
                        </div>
                        {workspaceMode === 'create' ? (
                            <Field label="Workspace Name" icon={Building} name="workspace_name" placeholder="Acme Security Operations" value={form.workspace_name} onChange={change} required error={fieldErrors.workspace_name} />
                        ) : (
                            <Field label="Workspace ID" icon={Building} name="workspace_id" placeholder="Paste the workspace ID shared by its owner" value={form.workspace_id} onChange={change} required error={fieldErrors.workspace_id} />
                        )}
                        <Field
                            label="Business Email"
                            icon={Mail}
                            type="email"
                            name="email"
                            placeholder="you@company.com"
                            value={form.email}
                            onChange={change}
                            required
                            error={fieldErrors.email}
                        />

                        {/* Password */}
                        <Field
                            label="Password"
                            icon={Lock}
                            type={showPw ? 'text' : 'password'}
                            name="password"
                            placeholder="Create a strong password"
                            value={form.password}
                            onChange={change}
                            required
                            error={fieldErrors.password}
                            rightSlot={
                                <button type="button" onClick={() => setShowPw(v => !v)}
                                    className="text-slate-600 hover:text-slate-400 transition-colors" tabIndex={-1}>
                                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                                </button>
                            }
                        />

                        {/* Strength bar */}
                        {form.password && (
                            <div className="space-y-2.5 pl-0.5">
                                <div className="flex gap-1.5">
                                    {[1,2,3,4].map(i => (
                                        <div key={i} className={`h-1.5 flex-1 rounded-full transition-all duration-300 ${i <= strength ? meta.bg : 'bg-white/[0.06]'}`} />
                                    ))}
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-[11px] font-bold" style={{ color: meta.color }}>{meta.label}</span>
                                </div>
                                <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                                    {pwReqs.map(r => <Req key={r.label} {...r} />)}
                                </div>
                            </div>
                        )}

                        <Field
                            label="Confirm Password"
                            icon={Lock}
                            type={showCpw ? 'text' : 'password'}
                            name="confirmPassword"
                            placeholder="Re-enter your password"
                            value={form.confirmPassword}
                            onChange={change}
                            required
                            error={fieldErrors.confirmPassword}
                            rightSlot={
                                <button type="button" onClick={() => setShowCpw(v => !v)}
                                    className="text-slate-600 hover:text-slate-400 transition-colors" tabIndex={-1}>
                                    {showCpw ? <EyeOff size={15} /> : <Eye size={15} />}
                                </button>
                            }
                        />

                        {/* Terms */}
                        <label className="flex items-start gap-3 cursor-pointer pt-1">
                            <input type="checkbox" required className="w-4 h-4 accent-[#FF6A3D] mt-0.5 flex-shrink-0 rounded" />
                            <span className="text-[12px] text-slate-500 leading-relaxed">
                                I agree to the{' '}
                                <span className="text-[#FF6A3D] hover:underline cursor-pointer">Terms of Service</span>
                                {' '}and{' '}
                                <span className="text-[#FF6A3D] hover:underline cursor-pointer">Privacy Policy</span>.
                            </span>
                        </label>

                        <motion.button
                            type="submit"
                            disabled={loading}
                            whileHover={{ scale: loading ? 1 : 1.01 }}
                            whileTap={{ scale: loading ? 1 : 0.98 }}
                            className="w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl font-bold text-[14px] text-white transition-all disabled:opacity-60 disabled:cursor-not-allowed mt-2"
                            style={{ background: 'linear-gradient(135deg, #FF6A3D, #FF8C42)', boxShadow: '0 0 24px rgba(255,106,61,0.35)' }}
                        >
                            {loading ? (
                                <><Loader size={15} className="animate-spin" /> Creating workspace...</>
                            ) : (
                                <>Create Secure Account <ArrowRight size={15} /></>
                            )}
                        </motion.button>
                    </form>

                    {/* Divider */}
                    <div className="relative flex items-center">
                        <div className="flex-1 border-t border-white/[0.06]" />
                        <span className="px-4 text-[11px] text-slate-700 uppercase tracking-widest">or sign up with</span>
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
                                onClick={label === 'Google' ? handleGoogleSignup : undefined}
                                disabled={label !== 'Google' || loading}
                                className={`flex items-center justify-center gap-2.5 py-3 rounded-xl border border-white/[0.07] bg-white/[0.02] text-[13px] transition-colors ${label === 'Google' ? 'text-white hover:border-white/[0.12] disabled:cursor-not-allowed disabled:opacity-60' : 'text-slate-600 cursor-not-allowed'}`}
                            >
                                {label === 'Google' && loading ? <Loader size={15} className="animate-spin" /> : <span>{icon}</span>} {label === 'Google' && loading ? 'Redirecting...' : label}
                            </button>
                        ))}
                    </div>

                    <p className="text-center text-[13px] text-slate-600">
                        Already have a workspace?{' '}
                        <button type="button" onClick={onToggleForm} className="text-[#FF6A3D] font-bold hover:underline">
                            Sign in
                        </button>
                    </p>
                </motion.div>
            </div>
        </div>
    );
};

export default RegisterPage;
