import React, { useState, useEffect } from 'react';
import { documentService } from '../services/api';
import {
  Upload, Download, Share2, Trash2, Edit3, ShieldAlert,
  Users, CheckCircle2, FileText, Lock, RefreshCw, X, ShieldCheck
} from 'lucide-react';

const Dashboard = ({ user }) => {
  const [documents, setDocuments] = useState({ owned: [], granted: [] });
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState({ text: '', type: '' });

  // Upload Form State
  const [file, setFile] = useState(null);
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('');
  const [uploading, setUploading] = useState(false);

  // Modals State
  const [sharingDoc, setSharingDoc] = useState(null);
  const [shareEmail, setShareEmail] = useState('');
  const [shareRole, setShareRole] = useState('viewer');
  const [shareLoading, setShareLoading] = useState(false);

  const [permissionsDoc, setPermissionsDoc] = useState(null);
  const [activePermissions, setActivePermissions] = useState([]);
  const [loadingPerms, setLoadingPerms] = useState(false);

  const [editingDoc, setEditingDoc] = useState(null);
  const [editTitle, setEditTitle] = useState('');
  const [editCategory, setEditCategory] = useState('');
  const [editLoading, setEditLoading] = useState(false);

  const fetchDocuments = async () => {
    setLoading(true);
    try {
      const response = await documentService.getAll();
      setDocuments(response.data);
    } catch (error) {
      showMessage('Failed to load documents from secure server.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const showMessage = (text, type = 'success') => {
    setMessage({ text, type });
    setTimeout(() => setMessage({ text: '', type: '' }), 5000);
  };

  // Upload Document
  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return showMessage('Please choose a file to upload.', 'error');

    if (file.size > 5 * 1024 * 1024) {
      return showMessage('File size exceeds the 5MB security limit.', 'error');
    }

    const formData = new FormData();
    formData.append('document', file);
    formData.append('title', title || file.name);
    formData.append('category', category || 'General');

    setUploading(true);
    try {
      await documentService.upload(formData);
      showMessage('Document verified, encrypted, and uploaded successfully.');
      setFile(null);
      setTitle('');
      setCategory('');
      fetchDocuments();
    } catch (error) {
      showMessage(error.response?.data?.error || 'Upload rejected by server verification.', 'error');
    } finally {
      setUploading(false);
    }
  };

  // Secure Download
  const handleDownload = async (docId, originalFilename) => {
    try {
      const response = await documentService.download(docId);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', originalFilename || 'document');
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      showMessage(`Downloaded "${originalFilename}" securely.`);
    } catch (error) {
      showMessage(error.response?.data?.error || 'Access Denied: Unable to download file.', 'error');
    }
  };

  // Delete Document
  const handleDelete = async (docId, docTitle) => {
    if (!window.confirm(`Are you sure you want to permanently delete "${docTitle}"? All permissions will be revoked.`)) {
      return;
    }

    try {
      await documentService.delete(docId);
      showMessage('Document and active permissions permanently deleted.');
      fetchDocuments();
    } catch (error) {
      showMessage(error.response?.data?.error || 'Failed to delete document.', 'error');
    }
  };

  // Share Document
  const handleShareSubmit = async (e) => {
    e.preventDefault();
    if (!shareEmail.trim()) return;

    setShareLoading(true);
    try {
      await documentService.share(sharingDoc._id, shareEmail.trim().toLowerCase(), shareRole);
      showMessage(`Document shared successfully with ${shareEmail} as ${shareRole}.`);
      setSharingDoc(null);
      setShareEmail('');
      fetchDocuments();
    } catch (error) {
      showMessage(error.response?.data?.error || 'Failed to grant document permissions.', 'error');
    } finally {
      setShareLoading(false);
    }
  };

  // Load Permissions
  const openPermissionsModal = async (doc) => {
    setPermissionsDoc(doc);
    setLoadingPerms(true);
    try {
      const res = await documentService.getPermissions(doc._id);
      setActivePermissions(res.data.permissions || []);
    } catch (error) {
      showMessage('Unable to retrieve document permissions.', 'error');
    } finally {
      setLoadingPerms(false);
    }
  };

  // Revoke Access
  const handleRevokePermission = async (permissionId, userEmail) => {
    try {
      await documentService.revokeAccess(permissionsDoc._id, permissionId);
      showMessage(`Revoked access for ${userEmail} immediately.`);
      setActivePermissions(activePermissions.filter(p => p._id !== permissionId));
      fetchDocuments();
    } catch (error) {
      showMessage(error.response?.data?.error || 'Failed to revoke permission.', 'error');
    }
  };

  // Edit Metadata
  const openEditModal = (doc) => {
    setEditingDoc(doc);
    setEditTitle(doc.title);
    setEditCategory(doc.category || 'General');
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    setEditLoading(true);
    try {
      await documentService.updateMetadata(editingDoc._id, {
        title: editTitle.trim(),
        category: editCategory.trim()
      });
      showMessage('Document metadata updated successfully.');
      setEditingDoc(null);
      fetchDocuments();
    } catch (error) {
      showMessage(error.response?.data?.error || 'Failed to update metadata.', 'error');
    } finally {
      setEditLoading(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-8">
      {/* Alert Notification */}
      {message.text && (
        <div className={`p-4 rounded-xl flex items-center gap-3 border shadow-sm transition-all ${
          message.type === 'error'
            ? 'bg-rose-50 border-rose-200 text-rose-800'
            : 'bg-emerald-50 border-emerald-200 text-emerald-800'
        }`}>
          {message.type === 'error' ? <ShieldAlert className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
          <span className="text-sm font-medium">{message.text}</span>
        </div>
      )}

      {/* Upload Panel */}
      <div className="bg-slate-50 border border-slate-200 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-indigo-100 text-indigo-600 flex items-center justify-center">
            <Upload className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900">Upload Confidential Document</h2>
            <p className="text-xs text-slate-500">Allowed: PDF, PNG, JPG, TXT (Max 5MB). Files are validated via magic-byte signatures.</p>
          </div>
        </div>

        <form onSubmit={handleUpload} className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <input
            type="text"
            placeholder="Document Title (optional)"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="bg-white border border-slate-300 rounded-xl px-4 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <input
            type="text"
            placeholder="Category (e.g. Legal, Finance)"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="bg-white border border-slate-300 rounded-xl px-4 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <div className="relative">
            <input
              type="file"
              required
              onChange={(e) => setFile(e.target.files[0])}
              className="w-full text-xs text-slate-500 file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100 cursor-pointer"
            />
          </div>
          <button
            type="submit"
            disabled={uploading}
            className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-xl px-4 py-2 text-sm shadow-sm transition-all flex items-center justify-center gap-2"
          >
            {uploading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            <span>{uploading ? 'Validating...' : 'Secure Upload'}</span>
          </button>
        </form>
      </div>

      {/* Grid: My Documents & Shared With Me */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Owned Documents */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <FileText className="w-5 h-5 text-indigo-600" />
              <h3 className="font-bold text-slate-900">My Vault ({documents.owned.length})</h3>
            </div>
            <span className="text-xs font-semibold px-2.5 py-1 bg-indigo-50 text-indigo-700 rounded-full">
              Full Ownership
            </span>
          </div>

          {loading ? (
            <div className="text-center py-12 text-slate-400 text-sm">Loading documents...</div>
          ) : documents.owned.length === 0 ? (
            <div className="text-center py-12 border-2 border-dashed border-slate-200 rounded-xl">
              <Lock className="w-8 h-8 text-slate-300 mx-auto mb-2" />
              <p className="text-sm text-slate-500">No documents in your vault yet.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {documents.owned.map((doc) => (
                <div key={doc._id} className="p-4 rounded-xl border border-slate-100 bg-slate-50/70 hover:bg-slate-50 transition-colors flex flex-col gap-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-semibold text-slate-900 text-sm">{doc.title}</h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        {doc.originalFilename} • {formatFileSize(doc.size)} • {doc.category}
                      </p>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">
                      {new Date(doc.uploadDate).toLocaleDateString()}
                    </span>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 pt-2 border-t border-slate-200/60">
                    <button
                      onClick={() => handleDownload(doc._id, doc.originalFilename)}
                      className="px-3 py-1.5 text-xs font-medium text-indigo-700 bg-indigo-50 hover:bg-indigo-100 rounded-lg flex items-center gap-1.5 transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" /> Download
                    </button>
                    <button
                      onClick={() => setSharingDoc(doc)}
                      className="px-3 py-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 hover:bg-emerald-100 rounded-lg flex items-center gap-1.5 transition-colors"
                    >
                      <Share2 className="w-3.5 h-3.5" /> Share
                    </button>
                    <button
                      onClick={() => openPermissionsModal(doc)}
                      className="px-3 py-1.5 text-xs font-medium text-amber-700 bg-amber-50 hover:bg-amber-100 rounded-lg flex items-center gap-1.5 transition-colors"
                    >
                      <Users className="w-3.5 h-3.5" /> Access
                    </button>
                    <button
                      onClick={() => openEditModal(doc)}
                      className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
                      title="Edit metadata"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleDelete(doc._id, doc.title)}
                      className="px-2.5 py-1.5 text-xs font-medium text-rose-700 bg-rose-50 hover:bg-rose-100 rounded-lg transition-colors ml-auto"
                      title="Delete permanently"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Granted Documents */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Users className="w-5 h-5 text-emerald-600" />
              <h3 className="font-bold text-slate-900">Shared With Me ({documents.granted.length})</h3>
            </div>
            <span className="text-xs font-semibold px-2.5 py-1 bg-emerald-50 text-emerald-700 rounded-full">
              Controlled Access
            </span>
          </div>

          {loading ? (
            <div className="text-center py-12 text-slate-400 text-sm">Loading documents...</div>
          ) : documents.granted.length === 0 ? (
            <div className="text-center py-12 border-2 border-dashed border-slate-200 rounded-xl">
              <Lock className="w-8 h-8 text-slate-300 mx-auto mb-2" />
              <p className="text-sm text-slate-500">No documents shared with you.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {documents.granted.map((doc) => (
                <div key={doc._id} className="p-4 rounded-xl border border-slate-100 bg-slate-50/70 hover:bg-slate-50 transition-colors flex flex-col gap-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-semibold text-slate-900 text-sm">{doc.title}</h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Shared by: <strong className="text-slate-600">{doc.grantedBy?.email || 'Owner'}</strong> • {formatFileSize(doc.size)}
                      </p>
                    </div>
                    <span className={`text-[11px] font-semibold uppercase px-2 py-0.5 rounded ${
                      doc.accessLevel === 'edit'
                        ? 'bg-amber-100 text-amber-800'
                        : 'bg-blue-100 text-blue-800'
                    }`}>
                      {doc.accessLevel === 'edit' ? 'Editor' : 'Viewer'}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 pt-2 border-t border-slate-200/60">
                    <button
                      onClick={() => handleDownload(doc._id, doc.originalFilename)}
                      className="px-3 py-1.5 text-xs font-medium text-indigo-700 bg-indigo-50 hover:bg-indigo-100 rounded-lg flex items-center gap-1.5 transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" /> Download Securely
                    </button>
                    {doc.accessLevel === 'edit' && (
                      <button
                        onClick={() => openEditModal(doc)}
                        className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg flex items-center gap-1.5 transition-colors"
                      >
                        <Edit3 className="w-3.5 h-3.5" /> Edit Metadata
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Share Document Modal */}
      {sharingDoc && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-slate-200 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <h3 className="font-bold text-slate-900">Share "{sharingDoc.title}"</h3>
              <button onClick={() => setSharingDoc(null)} className="text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleShareSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase mb-1">
                  Recipient User Email
                </label>
                <input
                  type="email"
                  required
                  placeholder="colleague@example.com"
                  value={shareEmail}
                  onChange={(e) => setShareEmail(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase mb-1">
                  Access Level
                </label>
                <select
                  value={shareRole}
                  onChange={(e) => setShareRole(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  <option value="viewer">Viewer (Can view and download only)</option>
                  <option value="editor">Editor (Can view, download, and update metadata)</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setSharingDoc(null)}
                  className="px-4 py-2 text-xs font-medium text-slate-600 hover:bg-slate-100 rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={shareLoading}
                  className="px-4 py-2 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl flex items-center gap-1.5"
                >
                  {shareLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
                  <span>Grant Access</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Permissions / Revocation Modal */}
      {permissionsDoc && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <div>
                <h3 className="font-bold text-slate-900">Manage Access</h3>
                <p className="text-xs text-slate-500">{permissionsDoc.title}</p>
              </div>
              <button onClick={() => setPermissionsDoc(null)} className="text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            {loadingPerms ? (
              <div className="py-8 text-center text-sm text-slate-400">Loading active permissions...</div>
            ) : activePermissions.length === 0 ? (
              <div className="py-8 text-center text-sm text-slate-500">
                This document is strictly private. No external permissions have been granted.
              </div>
            ) : (
              <div className="max-h-60 overflow-y-auto space-y-2">
                {activePermissions.map((perm) => (
                  <div key={perm._id} className="p-3 bg-slate-50 rounded-xl border border-slate-100 flex items-center justify-between">
                    <div>
                      <div className="text-sm font-semibold text-slate-900">{perm.userId?.email || 'User'}</div>
                      <div className="text-xs text-slate-400">
                        Level: <span className="uppercase font-medium text-indigo-600">{perm.accessLevel}</span> • Granted: {new Date(perm.grantedAt).toLocaleDateString()}
                      </div>
                    </div>
                    <button
                      onClick={() => handleRevokePermission(perm._id, perm.userId?.email)}
                      className="text-xs text-rose-600 hover:text-rose-800 font-semibold px-3 py-1 bg-rose-50 hover:bg-rose-100 rounded-lg transition-colors"
                    >
                      Revoke
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setPermissionsDoc(null)}
                className="px-4 py-2 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-xl"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Metadata Modal */}
      {editingDoc && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-slate-200 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <h3 className="font-bold text-slate-900">Update Document Details</h3>
              <button onClick={() => setEditingDoc(null)} className="text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase mb-1">
                  Document Title
                </label>
                <input
                  type="text"
                  required
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase mb-1">
                  Category
                </label>
                <input
                  type="text"
                  required
                  value={editCategory}
                  onChange={(e) => setEditCategory(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingDoc(null)}
                  className="px-4 py-2 text-xs font-medium text-slate-600 hover:bg-slate-100 rounded-xl"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={editLoading}
                  className="px-4 py-2 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl flex items-center gap-1.5"
                >
                  {editLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
                  <span>Save Changes</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
