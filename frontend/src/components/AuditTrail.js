import React, { useState, useEffect } from 'react';
import { adminService } from '../services/api';
import {
  ShieldCheck, ShieldAlert, RefreshCw, Filter,
  ChevronLeft, ChevronRight, Hash, Search
} from 'lucide-react';

const AuditTrail = () => {
  const [logs, setLogs] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 15, total: 0, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Filters
  const [actionFilter, setActionFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [searchEmail, setSearchEmail] = useState('');

  // Cryptographic Verification State
  const [verifying, setVerifying] = useState(false);
  const [verifyReport, setVerifyReport] = useState(null);

  const fetchLogs = async (page = 1) => {
    setLoading(true);
    setError('');
    try {
      const params = {
        page,
        limit: pagination.limit
      };
      if (actionFilter) params.action = actionFilter;
      if (statusFilter) params.status = statusFilter;
      if (searchEmail.trim()) params.actorEmail = searchEmail.trim();

      const response = await adminService.getAuditLogs(params);
      setLogs(response.data.logs || []);
      setPagination(response.data.pagination || { page: 1, limit: 15, total: 0, totalPages: 1 });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load audit logs.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(1);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [actionFilter, statusFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchLogs(1);
  };

  const handleVerifyChain = async () => {
    setVerifying(true);
    setVerifyReport(null);
    try {
      const response = await adminService.verifyAuditLedger();
      setVerifyReport(response.data.report);
    } catch (err) {
      setVerifyReport({
        isValid: false,
        reason: err.response?.data?.error || 'Verification check failed to execute.'
      });
    } finally {
      setVerifying(false);
    }
  };

  const getActionBadgeClass = (action) => {
    switch (action) {
      case 'upload':
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
      case 'download':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'access_denied':
        return 'bg-rose-100 text-rose-800 border-rose-200';
      case 'delete':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'permission_granted':
        return 'bg-purple-100 text-purple-800 border-purple-200';
      case 'permission_revoked':
        return 'bg-amber-100 text-amber-800 border-amber-200';
      case 'admin_action':
        return 'bg-indigo-100 text-indigo-800 border-indigo-200';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-200';
    }
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-6 mt-8">
      {/* Header & Verification Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-900">Cryptographic Security Audit Trail</h2>
            <span className="text-xs font-semibold px-2.5 py-0.5 bg-slate-900 text-white rounded-full">
              Tamper-Evident SHA-256 Ledger
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Immutable chronological record of all system events, authentication, and access decisions.
          </p>
        </div>

        <button
          onClick={handleVerifyChain}
          disabled={verifying}
          className="px-4 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl border border-indigo-200 flex items-center gap-2 transition-all"
        >
          {verifying ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4 text-indigo-600" />}
          <span>{verifying ? 'Verifying Hashes...' : 'Verify Hash Chain Integrity'}</span>
        </button>
      </div>

      {/* Verification Report Banner */}
      {verifyReport && (
        <div className={`p-4 rounded-xl border flex items-start gap-3 ${
          verifyReport.isValid
            ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
            : 'bg-rose-50 border-rose-200 text-rose-900'
        }`}>
          {verifyReport.isValid ? (
            <ShieldCheck className="w-5 h-5 text-emerald-600 flex-shrink-0 mt-0.5" />
          ) : (
            <ShieldAlert className="w-5 h-5 text-rose-600 flex-shrink-0 mt-0.5" />
          )}
          <div className="text-xs space-y-1">
            <div className="font-bold text-sm">
              {verifyReport.isValid ? 'Audit Chain Status: Cryptographically Valid' : 'Audit Chain Compromised!'}
            </div>
            <div>{verifyReport.message || verifyReport.reason}</div>
            {verifyReport.latestHash && (
              <div className="font-mono text-[11px] text-slate-600 break-all">
                Latest Block Hash: {verifyReport.latestHash}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 bg-slate-50 p-3 rounded-xl border border-slate-100">
        <form onSubmit={handleSearchSubmit} className="relative md:col-span-2">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search by actor email..."
            value={searchEmail}
            onChange={(e) => setSearchEmail(e.target.value)}
            className="w-full bg-white border border-slate-200 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </form>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="w-full bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All Actions</option>
            <option value="upload">Upload</option>
            <option value="download">Download</option>
            <option value="access_denied">Access Denied</option>
            <option value="permission_granted">Permission Granted</option>
            <option value="permission_revoked">Permission Revoked</option>
            <option value="login">Login</option>
            <option value="register">Register</option>
            <option value="delete">Delete</option>
            <option value="admin_action">Admin Action</option>
          </select>
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-white border border-slate-200 rounded-lg px-2.5 py-1.5 text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All Statuses</option>
          <option value="success">Success Only</option>
          <option value="blocked">Blocked Only</option>
        </select>
      </div>

      {error && (
        <div className="p-3 bg-rose-50 border border-rose-200 text-rose-700 rounded-xl text-xs">
          {error}
        </div>
      )}

      {/* Logs Table */}
      <div className="overflow-x-auto border border-slate-200 rounded-xl">
        <table className="min-w-full text-left text-xs divide-y divide-slate-200">
          <thead className="bg-slate-50 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
            <tr>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Resource / Target</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">IP / Hash Chain</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 bg-white">
            {loading ? (
              <tr>
                <td colSpan="6" className="text-center py-10 text-slate-400">
                  Loading verified ledger...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan="6" className="text-center py-10 text-slate-400">
                  No audit events found matching filters.
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log._id} className="hover:bg-slate-50/70 transition-colors">
                  <td className="px-4 py-3 whitespace-nowrap text-slate-500 font-mono">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 font-medium text-slate-900">
                    <div>{log.actorEmail || log.actorId?.email || 'System / Unauth'}</div>
                    {log.actorId?.role && (
                      <span className="text-[10px] text-slate-400 uppercase">({log.actorId.role})</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getActionBadgeClass(log.action)}`}>
                      {log.action.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-700">
                    {log.documentId?.title ? (
                      <span className="font-medium text-slate-800">{log.documentId.title}</span>
                    ) : log.targetUserId?.email ? (
                      <span className="text-slate-600">User: {log.targetUserId.email}</span>
                    ) : log.metadata?.filename ? (
                      <span className="text-slate-600">{log.metadata.filename}</span>
                    ) : (
                      <span className="text-slate-400">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      log.status === 'success'
                        ? 'bg-emerald-100 text-emerald-800'
                        : 'bg-rose-100 text-rose-800'
                    }`}>
                      {log.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[11px] font-mono text-slate-500">
                    <div className="flex items-center gap-1.5">
                      <Hash className="w-3.5 h-3.5 text-slate-400" />
                      <span title={`Previous Hash: ${log.previousHash}\nCurrent Hash: ${log.currentHash}`}>
                        {log.previousHash ? log.previousHash.slice(0, 10) + '...' : 'Genesis'}
                      </span>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex items-center justify-between text-xs text-slate-500 pt-2">
        <div>
          Showing page <span className="font-semibold text-slate-800">{pagination.page}</span> of{' '}
          <span className="font-semibold text-slate-800">{pagination.totalPages || 1}</span> ({pagination.total} records)
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchLogs(pagination.page - 1)}
            disabled={pagination.page <= 1 || loading}
            className="px-3 py-1.5 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1"
          >
            <ChevronLeft className="w-3.5 h-3.5" /> Previous
          </button>
          <button
            onClick={() => fetchLogs(pagination.page + 1)}
            disabled={pagination.page >= pagination.totalPages || loading}
            className="px-3 py-1.5 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1"
          >
            Next <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default AuditTrail;
