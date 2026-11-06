/**
 * TrustVault - Tamper-Evident Audit Logging Engine
 * Uses deterministic serialization, SHA-256 hash chaining, and sequential write locking
 */

const crypto = require('crypto');
const uuidv4 = () => crypto.randomUUID();
const { AuditLog } = require('../models');
const {
  GENESIS_HASH,
  canonicalizeEvent,
  computeRecordHash
} = require('./auditIntegrity');

// Serialized concurrency queue to prevent race conditions during hash-chain append
let writeQueue = Promise.resolve();

/**
 * Strips sensitive keys (passwords, tokens, secrets) before persisting to audit trail
 */
function sanitizeMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object') return {};
  const cleaned = { ...metadata };
  const sensitiveKeys = ['password', 'passwordHash', 'token', 'jwt', 'secret', 'authorization', 'cookie', 'fileContent'];
  
  for (const key of Object.keys(cleaned)) {
    if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
      cleaned[key] = '[REDACTED_BY_AUDIT_SECURITY]';
    } else if (typeof cleaned[key] === 'object' && cleaned[key] !== null) {
      cleaned[key] = sanitizeMetadata(cleaned[key]);
    }
  }
  return cleaned;
}

/**
 * Internal append operation executed sequentially
 */
async function appendAuditRecord({
  actorId = null,
  actorEmail = null,
  action,
  status,
  documentId = null,
  targetUserId = null,
  ipAddress = 'unknown',
  metadata = {}
}) {
  const eventId = uuidv4();
  const timestamp = new Date();
  const cleanMetadata = sanitizeMetadata(metadata);

  // Retrieve the most recent log entry to chain hashes
  const lastLog = await AuditLog.findOne().sort({ timestamp: -1, _id: -1 });
  const previousHash = lastLog ? lastLog.currentHash : GENESIS_HASH;

  const rawRecord = {
    eventId,
    timestamp,
    actorId,
    actorEmail,
    action,
    status,
    documentId,
    targetUserId,
    ipAddress: ipAddress || 'unknown',
    metadata: cleanMetadata
  };

  const canonicalPayload = canonicalizeEvent(rawRecord);
  const currentHash = computeRecordHash(canonicalPayload, previousHash);

  const newLogEntry = new AuditLog({
    ...rawRecord,
    previousHash,
    currentHash
  });

  return newLogEntry.save();
}

/**
 * Public audit logger wrapped in promise serialization to handle concurrency safely
 */
async function logAction(entryData) {
  return new Promise((resolve, reject) => {
    writeQueue = writeQueue
      .then(async () => {
        try {
          const saved = await appendAuditRecord(entryData);
          resolve(saved);
        } catch (err) {
          console.error('CRITICAL AUDIT LOG FAILURE:', err);
          // If security critical, caller can choose to fail-closed
          reject(err);
        }
      })
      .catch((err) => {
        console.error('AUDIT QUEUE ERROR:', err);
        reject(err);
      });
  });
}

module.exports = {
  logAction,
  sanitizeMetadata
};
