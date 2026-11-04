
import React, { useState, useEffect } from 'react';
import { adminService } from '../services/api';

const AuditTrail = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        const fetchLogs = async () => {
            try {
                const response = await adminService.getAuditLogs();
                setLogs(response.data.logs);
            } catch (err) {
                setError(err.response?.data?.error || 'Failed to load audit logs.');
            } finally {
                setLoading(false);
            }
        };

        fetchLogs();
    }, []);

    if (loading) return <div className="text-center p-4">Loading audit trail...</div>;
    if (error) return <div className="bg-red-100 text-red-700 p-4 rounded-md">{error}</div>;

    return (
        <div className="bg-white p-6 rounded-lg shadow-sm border mt-8">
            <h2 className="text-xl font-semibold mb-4 border-b pb-2 flex justify-between items-center">
                <span>Security Audit Trail</span>
                <span className="text-sm font-normal text-gray-500 bg-gray-100 px-2 py-1 rounded">
                    Admin View Only
                </span>
            </h2>
            
            <div className="overflow-x-auto">
                <table className="min-w-full text-left text-sm text-gray-600">
                    <thead className="bg-gray-50 border-b">
                        <tr>
                            <th className="px-4 py-3 font-medium text-gray-900">Timestamp</th>
                            <th className="px-4 py-3 font-medium text-gray-900">Actor</th>
                            <th className="px-4 py-3 font-medium text-gray-900">Action</th>
                            <th className="px-4 py-3 font-medium text-gray-900">Document</th>
                            <th className="px-4 py-3 font-medium text-gray-900">Status</th>
                            <th className="px-4 py-3 font-medium text-gray-900">IP / Hash Chain</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                        {logs.map((log) => (
                            <tr key={log._id} className="hover:bg-gray-50">
                                <td className="px-4 py-3 whitespace-nowrap">
                                    {new Date(log.timestamp).toLocaleString()}
                                </td>
                                <td className="px-4 py-3 font-medium">
                                    {log.actorId?.email || 'Unknown User'}
                                </td>
                                <td className="px-4 py-3">
                                    <span className="bg-blue-50 text-blue-700 px-2 py-1 rounded text-xs uppercase tracking-wider font-semibold">
                                        {log.action.replace('_', ' ')}
                                    </span>
                                </td>
                                <td className="px-4 py-3">
                                    {log.documentId?.title || '-'}
                                </td>
                                <td className="px-4 py-3">
                                    <span className={`px-2 py-1 rounded text-xs uppercase tracking-wider font-semibold ${
                                        log.status === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-100 text-red-800'
                                    }`}>
                                        {log.status}
                                    </span>
                                </td>
                                <td className="px-4 py-3 text-xs text-gray-400 font-mono">
                                    <div title="Previous Hash for Tamper-Proofing">
                                        {log.previousHash ? log.previousHash.substring(0, 12) + '...' : '-'}
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                {logs.length === 0 && (
                    <p className="text-center text-gray-500 py-4">No audit logs found.</p>
                )}
            </div>
        </div>
    );
};

export default AuditTrail;