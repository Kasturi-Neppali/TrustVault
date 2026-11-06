import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import AuditTrail from './components/AuditTrail';
import { authService } from './services/api';
import { Shield, LogOut, FileText, Activity } from 'lucide-react';

function App() {
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState('vault');
  const [isVerifyingSession, setIsVerifyingSession] = useState(true);

  // Authenticate and restore session against the backend on application load
  useEffect(() => {
    const verifySession = async () => {
      try {
        const response = await authService.getMe();
        if (response.data?.user) {
          setUser(response.data.user);
          localStorage.setItem('trustvault_user', JSON.stringify(response.data.user));
        }
      } catch (err) {
        // Backend rejected or session expired: clear local storage
        localStorage.removeItem('trustvault_token');
        localStorage.removeItem('trustvault_user');
        setUser(null);
      } finally {
        setIsVerifyingSession(false);
      }
    };

    verifySession();
  }, []);

  const handleLoginSuccess = (userData) => {
    setUser(userData);
    setActiveTab('vault');
  };

  const handleLogout = async () => {
    try {
      await authService.logout();
    } catch (e) {
      // Ignore network errors on logout
    } finally {
      localStorage.removeItem('trustvault_token');
      localStorage.removeItem('trustvault_user');
      setUser(null);
    }
  };

  if (isVerifyingSession) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-3 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
          <span className="text-sm font-medium text-slate-400">Verifying security session...</span>
        </div>
      </div>
    );
  }

  // If unauthenticated, show the Login/Register screen
  if (!user) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-slate-100/80 text-slate-900">
      {/* Top Navigation Bar */}
      <header className="bg-slate-900 border-b border-slate-800 text-white sticky top-0 z-40 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-md shadow-indigo-600/30">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="font-extrabold text-lg tracking-tight">Trust<span className="text-indigo-400">Vault</span></span>
              <span className="ml-2 text-[10px] tracking-wider uppercase font-semibold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                Confidential Document Engine
              </span>
            </div>
          </div>

          {/* User Profile & Logout */}
          <div className="flex items-center gap-4">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-semibold text-white">{user.name || 'User'}</div>
              <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5 justify-end">
                <span>{user.email}</span>
                <span className={`px-1.5 py-0.2 rounded text-[10px] uppercase font-bold ${
                  user.role === 'admin'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                }`}>
                  {user.role}
                </span>
              </div>
            </div>

            <button
              onClick={handleLogout}
              className="p-2 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded-xl transition-colors"
              title="Sign Out"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Navigation Tabs */}
        <div className="flex gap-2 border-b border-slate-200 pb-2">
          <button
            onClick={() => setActiveTab('vault')}
            className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all ${
              activeTab === 'vault'
                ? 'bg-white text-indigo-600 shadow-sm border border-slate-200'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Document Vault</span>
          </button>

          {user.role === 'admin' && (
            <button
              onClick={() => setActiveTab('audit')}
              className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all ${
                activeTab === 'audit'
                  ? 'bg-white text-indigo-600 shadow-sm border border-slate-200'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Audit Ledger & Hash Chain</span>
            </button>
          )}
        </div>

        {/* Tab Content */}
        {activeTab === 'vault' && <Dashboard user={user} />}
        {activeTab === 'audit' && user.role === 'admin' && <AuditTrail />}
      </main>
    </div>
  );
}

export default App;
