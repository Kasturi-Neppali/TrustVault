
import React, { useState, useEffect } from 'react';
import { documentService } from '../services/api';

const Dashboard = ({ user }) => {
    const [documents, setDocuments] = useState({ owned: [], granted: [] });
    const [file, setFile] = useState(null);
    const [title, setTitle] = useState('');
    const [category, setCategory] = useState('');
    const [targetUserId, setTargetUserId] = useState('');
    const [message, setMessage] = useState({ text: '', type: '' });

    const fetchDocuments = async () => {
        try {
            const response = await documentService.getAll();
            setDocuments(response.data);
        } catch (error) {
            showMessage('Failed to load documents.', 'error');
        }
    };

    useEffect(() => {
        fetchDocuments();
    }, []);

    const showMessage = (text, type) => {
        setMessage({ text, type });
        setTimeout(() => setMessage({ text: '', type: '' }), 5000);
    };

    const handleUpload = async (e) => {
        e.preventDefault();
        if (!file) return showMessage('Please select a file', 'error');

        const formData = new FormData();
        formData.append('document', file);
        formData.append('title', title);
        formData.append('category', category || 'General');

        try {
            await documentService.upload(formData);
            showMessage('Document uploaded successfully!', 'success');
            setFile(null);
            setTitle('');
            setCategory('');
            fetchDocuments();
        } catch (error) {
            showMessage(error.response?.data?.error || 'Upload failed.', 'error');
        }
    };

    const handleDownload = async (docId, filename) => {
        try {
            const response = await documentService.download(docId);
            // Create a blob link to download the file securely
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (error) {
            showMessage('Access Denied or Download failed.', 'error');
        }
    };

    const handleGrantAccess = async (docId) => {
        if (!targetUserId) return showMessage('Enter a User ID', 'error');
        try {
            await documentService.grantAccess(docId, targetUserId, 'read');
            showMessage('Access granted successfully.', 'success');
            setTargetUserId('');
        } catch (error) {
            showMessage(error.response?.data?.error || 'Grant failed.', 'error');
        }
    };

    const handleRevokeAccess = async (docId) => {
        if (!targetUserId) return showMessage('Enter a User ID', 'error');
        try {
            await documentService.revokeAccess(docId, targetUserId);
            showMessage('Access revoked immediately.', 'success');
            setTargetUserId('');
        } catch (error) {
            showMessage(error.response?.data?.error || 'Revoke failed.', 'error');
        }
    };

    return (
        <div className="space-y-8">
            {message.text && (
                <div className={`p-4 rounded-md ${message.type === 'error' ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
                    {message.text}
                </div>
            )}

            {/* Upload Section */}
            <div className="bg-white p-6 rounded-lg shadow-sm border">
                <h2 className="text-xl font-semibold mb-4">Upload Secure Document</h2>
                <form onSubmit={handleUpload} className="flex flex-col sm:flex-row gap-4">
                    <input type="text" placeholder="Title" value={title} onChange={e => setTitle(e.target.value)} required className="border p-2 rounded flex-1" />
                    <input type="text" placeholder="Category" value={category} onChange={e => setCategory(e.target.value)} className="border p-2 rounded flex-1" />
                    <input type="file" onChange={e => setFile(e.target.files[0])} required className="border p-2 rounded flex-1" />
                    <button type="submit" className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Upload</button>
                </form>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Owned Documents */}
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                    <h2 className="text-xl font-semibold mb-4 border-b pb-2">My Documents</h2>
                    {documents.owned.length === 0 ? <p className="text-gray-500">No documents uploaded yet.</p> : (
                        <ul className="space-y-4">
                            {documents.owned.map(doc => (
                                <li key={doc._id} className="border p-4 rounded bg-gray-50 flex flex-col gap-3">
                                    <div className="flex justify-between items-center">
                                        <span className="font-medium text-gray-800">{doc.title}</span>
                                        <button onClick={() => handleDownload(doc._id, doc.originalFilename)} className="text-blue-600 hover:underline text-sm">Download</button>
                                    </div>
                                    <div className="border-t pt-3 mt-2 flex gap-2">
                                        <input 
                                            type="text" 
                                            placeholder="Target User ID" 
                                            value={targetUserId} 
                                            onChange={e => setTargetUserId(e.target.value)} 
                                            className="border p-1 rounded text-sm flex-1" 
                                        />
                                        <button onClick={() => handleGrantAccess(doc._id)} className="bg-green-600 text-white text-xs px-3 py-1 rounded">Grant</button>
                                        <button onClick={() => handleRevokeAccess(doc._id)} className="bg-red-600 text-white text-xs px-3 py-1 rounded">Revoke</button>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>

                {/* Granted Documents */}
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                    <h2 className="text-xl font-semibold mb-4 border-b pb-2">Shared With Me</h2>
                    {documents.granted.length === 0 ? <p className="text-gray-500">No documents shared with you.</p> : (
                        <ul className="space-y-4">
                            {documents.granted.map(doc => (
                                <li key={doc._id} className="border p-4 rounded bg-gray-50 flex justify-between items-center">
                                    <span className="font-medium text-gray-800">{doc.title}</span>
                                    <button onClick={() => handleDownload(doc._id, doc.originalFilename)} className="text-blue-600 hover:underline text-sm">Download Securely</button>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Dashboard;