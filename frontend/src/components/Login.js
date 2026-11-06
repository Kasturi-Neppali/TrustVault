import React, { useState } from 'react';
import { authService } from '../services/api';
import { Shield, Lock, Mail, User, Eye, EyeOff, CheckCircle2, AlertCircle } from 'lucide-react';

const Login = ({ onLoginSuccess }) => {
  const [isRegistering, setIsRegistering] = useState(false);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  // Password complexity helpers
  const passCriteria = {
    length: password.length >= 8,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)
  };
  const isPasswordValid = Object.values(passCriteria).every(Boolean);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsLoading(true);

    try {
      if (isRegistering) {
        if (!name.trim()) {
          setError('Please provide your full name.');
          setIsLoading(false);
          return;
        }
        if (!isPasswordValid) {
          setError('Password does not fulfill security requirements.');
          setIsLoading(false);
          return;
        }

        await authService.register(name.trim(), email.trim().toLowerCase(), password);
        setSuccess('Account created successfully! Please sign in with your credentials.');
        setIsRegistering(false);
        setPassword('');
      } else {
        const response = await authService.login(email.trim().toLowerCase(), password);
        const { token, user } = response.data;

        if (token) {
          localStorage.setItem('trustvault_token', token);
        }
        if (user) {
          localStorage.setItem('trustvault_user', JSON.stringify(user));
        }

        onLoginSuccess(user);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Authentication request failed. Please check credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900 px-4 py-12 sm:px-6 lg:px-8">
      <div className="max-w-md w-full bg-slate-800 rounded-2xl shadow-2xl border border-slate-700 p-8 space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 mb-2">
            <Shield className="w-8 h-8" />
          </div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white">
            Trust<span className="text-indigo-400">Vault</span>
          </h2>
          <p className="text-sm text-slate-400">
            {isRegistering
              ? 'Create a secure confidential workspace account'
              : 'Sign in to access your encrypted document vault'}
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex bg-slate-900/60 p-1 rounded-xl border border-slate-700/60">
          <button
            type="button"
            onClick={() => { setIsRegistering(false); setError(''); setSuccess(''); }}
            className={`flex-1 py-2 text-sm font-semibold rounded-lg transition-all ${
              !isRegistering
                ? 'bg-indigo-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setIsRegistering(true); setError(''); setSuccess(''); }}
            className={`flex-1 py-2 text-sm font-semibold rounded-lg transition-all ${
              isRegistering
                ? 'bg-indigo-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Create Account
          </button>
        </div>

        {/* Banners */}
        {error && (
          <div className="flex items-center gap-2 p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-300 text-sm">
            <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="flex items-center gap-2 p-3.5 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-300 text-sm">
            <CheckCircle2 className="w-5 h-5 flex-shrink-0 text-emerald-400" />
            <span>{success}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegistering && (
            <div>
              <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1.5">
                Full Name
              </label>
              <div className="relative">
                <User className="absolute left-3.5 top-3 w-5 h-5 text-slate-400" />
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Jane Doe"
                  className="w-full bg-slate-900/80 border border-slate-700 rounded-xl pl-11 pr-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm transition-all"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1.5">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-3 w-5 h-5 text-slate-400" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@example.com"
                className="w-full bg-slate-900/80 border border-slate-700 rounded-xl pl-11 pr-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1.5">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3.5 top-3 w-5 h-5 text-slate-400" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-900/80 border border-slate-700 rounded-xl pl-11 pr-11 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm transition-all"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3.5 top-3 text-slate-400 hover:text-slate-200 transition-colors"
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {/* Real-time Password Security Criteria for Registration */}
          {isRegistering && password && (
            <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-700/50 space-y-1.5 text-xs text-slate-400">
              <div className="font-semibold text-slate-300 mb-1">Security Requirements:</div>
              <div className={`flex items-center gap-1.5 ${passCriteria.length ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" /> 8+ Characters
              </div>
              <div className={`flex items-center gap-1.5 ${passCriteria.upper ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" /> At least one uppercase letter (A-Z)
              </div>
              <div className={`flex items-center gap-1.5 ${passCriteria.lower ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" /> At least one lowercase letter (a-z)
              </div>
              <div className={`flex items-center gap-1.5 ${passCriteria.number ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" /> At least one digit (0-9)
              </div>
              <div className={`flex items-center gap-1.5 ${passCriteria.special ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" /> At least one special symbol (!@#$...)
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading || (isRegistering && !isPasswordValid)}
            className="w-full mt-2 py-3 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-medium shadow-lg shadow-indigo-600/30 transition-all flex items-center justify-center gap-2"
          >
            {isLoading ? (
              <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
            ) : null}
            <span>{isRegistering ? 'Complete Registration' : 'Sign In Securely'}</span>
          </button>
        </form>

        {/* Demo Credentials Footer */}
        <div className="pt-4 border-t border-slate-700/60 text-center">
          <div className="text-xs text-slate-400 mb-2 font-medium">Demo / Evaluation Credentials:</div>
          <div className="flex justify-center gap-4 text-xs font-mono text-slate-300">
            <span className="bg-slate-900/80 px-2 py-1 rounded border border-slate-700">admin@trustvault.com</span>
            <span className="bg-slate-900/80 px-2 py-1 rounded border border-slate-700">TrustVault@Admin2026!</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
