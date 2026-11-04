
const { AuditLog } = require('../models');
const crypto = require('crypto');

async function logAction({ actorId, documentId, action, status, ipAddress }) {
  try {
    // Basic tamper-proofing: link to the previous log entry
    const lastLog = await AuditLog.findOne().sort({ timestamp: -1 });
    let previousHash = 'genesis';
    
    if (lastLog) {
      const dataToHash = `${lastLog._id}${lastLog.timestamp}${lastLog.actorId}${lastLog.action}`;
      previousHash = crypto.createHash('sha256').update(dataToHash).digest('hex');
    }

    const logEntry = new AuditLog({
      actorId,
      documentId,
      action,
      status,
      ipAddress,
      previousHash
    });

    await logEntry.save();
  } catch (error) {
    console.error("CRITICAL: Failed to write to audit log", error);
  }
}

module.exports = { logAction };