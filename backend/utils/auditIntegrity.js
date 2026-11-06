/**
 * TrustVault - Cryptographic Audit Integrity Utilities
 * Implements deterministic canonicalization & SHA-256 hash-chain verification
 */

const crypto = require('crypto');

const GENESIS_HASH = '0'.repeat(64);

function normalizeMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return null;
  }
  const keys = Object.keys(metadata);
  if (keys.length === 0) {
    return null;
  }
  return sortObjectKeys(metadata);
}

/**
 * Deterministically canonicalizes audit record attributes to guarantee consistent hashing
 */
function canonicalizeEvent(data) {
  const normalized = {
    action: String(data.action || ''),
    actorEmail: data.actorEmail ? String(data.actorEmail).toLowerCase().trim() : '',
    actorId: data.actorId ? String(data.actorId) : '',
    documentId: data.documentId ? String(data.documentId) : '',
    eventId: String(data.eventId || ''),
    ipAddress: String(data.ipAddress || 'unknown'),
    metadata: normalizeMetadata(data.metadata),
    status: String(data.status || ''),
    targetUserId: data.targetUserId ? String(data.targetUserId) : '',
    timestamp: new Date(data.timestamp).toISOString()
  };

  return JSON.stringify(normalized);
}

/**
 * Recursively sorts object keys for deterministic serialization
 */
function sortObjectKeys(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return obj;
  }
  const sorted = {};
  Object.keys(obj).sort().forEach(key => {
    sorted[key] = sortObjectKeys(obj[key]);
  });
  return sorted;
}

/**
 * Calculates SHA-256 hash of canonical event data combined with previous hash
 */
function computeRecordHash(canonicalPayload, previousHash) {
  const input = `${canonicalPayload}|${previousHash}`;
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Validates the entire cryptographic hash chain in the database
 * Returns an integrity report with details on valid records or detected tampering
 */
async function verifyAuditChain(AuditLogModel) {
  const records = await AuditLogModel.find().sort({ timestamp: 1, _id: 1 }).lean();

  if (records.length === 0) {
    return {
      isValid: true,
      totalRecords: 0,
      message: 'Audit chain is empty. Genesis state intact.',
      latestHash: GENESIS_HASH
    };
  }

  let expectedPreviousHash = GENESIS_HASH;

  for (let i = 0; i < records.length; i++) {
    const record = records[i];

    // 1. Verify that the previousHash pointer matches the actual preceding hash
    if (record.previousHash !== expectedPreviousHash) {
      return {
        isValid: false,
        totalRecords: records.length,
        verifiedRecords: i,
        tamperedIndex: i,
        recordId: record._id,
        eventId: record.eventId,
        reason: 'Broken previousHash linkage (record insertion, deletion, or reordering detected)',
        expectedPreviousHash,
        actualPreviousHash: record.previousHash
      };
    }

    // 2. Recalculate canonical payload and hash
    const canonicalPayload = canonicalizeEvent(record);
    const recomputedHash = computeRecordHash(canonicalPayload, record.previousHash);

    // 3. Verify that the stored currentHash matches the recomputed cryptographic hash
    if (record.currentHash !== recomputedHash) {
      return {
        isValid: false,
        totalRecords: records.length,
        verifiedRecords: i,
        tamperedIndex: i,
        recordId: record._id,
        eventId: record.eventId,
        reason: 'Hash mismatch: record contents have been tampered with or altered in database',
        expectedHash: recomputedHash,
        storedHash: record.currentHash
      };
    }

    expectedPreviousHash = record.currentHash;
  }

  return {
    isValid: true,
    totalRecords: records.length,
    verifiedRecords: records.length,
    latestHash: records[records.length - 1].currentHash,
    message: 'Cryptographic audit chain fully verified. Zero tampering detected.'
  };
}

module.exports = {
  GENESIS_HASH,
  canonicalizeEvent,
  computeRecordHash,
  verifyAuditChain
};

