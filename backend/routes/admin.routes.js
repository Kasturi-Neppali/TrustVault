
const express = require('express');
const { AuditLog } = require('../models');
const { authenticateUser } = require('../middleware/auth');

const router = express.Router();

// Middleware: Strictly require 'admin' role
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Admin access required.' });
    }
    next();
};

// [GET] /api/admin/audit-logs
// Returns the audit trail, sorted newest first, populated with user and document details
router.get('/audit-logs', authenticateUser, requireAdmin, async (req, res) => {
    try {
        const logs = await AuditLog.find()
            .sort({ timestamp: -1 })
            .populate('actorId', 'email role') // Get the email of who did it
            .populate('documentId', 'title')   // Get the name of the document
            .lean(); // Faster query since we don't need Mongoose documents here

        res.json({ logs });
    } catch (error) {
        console.error("Audit Log Fetch Error:", error);
        res.status(500).json({ error: 'Server error fetching audit logs.' });
    }
});

module.exports = router;