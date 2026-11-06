/**
 * TrustVault - Administrative & Audit Trail Management Routes
 * Protected endpoints for system administrators: audit log inspection & cryptographic verification
 */

const express = require('express');
const { AuditLog } = require('../models');
const { authenticateUser, requireRole } = require('../middleware/auth');
const { verifyAuditChain } = require('../utils/auditIntegrity');

const router = express.Router();

/**
 * [GET] /api/admin/audit-logs/verify
 * Cryptographically verifies the unbroken SHA-256 hash chain across all audit logs
 */
router.get('/audit-logs/verify', authenticateUser, requireRole(['admin']), async (req, res) => {
  try {
    const report = await verifyAuditChain(AuditLog);
    res.json({ report });
  } catch (error) {
    console.error('Audit Verification Route Error:', error);
    res.status(500).json({ error: 'Server error during cryptographic audit verification.' });
  }
});

/**
 * [GET] /api/admin/audit-logs
 * Retrieves paginated and filtered audit trail records. Admin only.
 */
router.get('/audit-logs', authenticateUser, requireRole(['admin']), async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));
    const skip = (page - 1) * limit;

    const query = {};

    if (req.query.action) {
      query.action = req.query.action;
    }
    if (req.query.status) {
      query.status = req.query.status;
    }
    if (req.query.actorEmail) {
      query.actorEmail = new RegExp(req.query.actorEmail.trim(), 'i');
    }

    const [logs, total] = await Promise.all([
      AuditLog.find(query)
        .sort({ timestamp: -1, _id: -1 })
        .skip(skip)
        .limit(limit)
        .populate('actorId', 'email name role')
        .populate('targetUserId', 'email name')
        .populate('documentId', 'title')
        .lean(),
      AuditLog.countDocuments(query)
    ]);

    res.json({
      logs,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Audit Log Fetch Error:', error);
    res.status(500).json({ error: 'Server error while fetching audit logs.' });
  }
});

module.exports = router;
