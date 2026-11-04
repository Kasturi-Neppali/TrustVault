
const mongoose = require('mongoose');

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' }
});

// Document Schema
const documentSchema = new mongoose.Schema({
  title: { type: String, required: true },
  category: { type: String, required: true },
  originalFilename: { type: String, required: true },
  mimeType: { type: String, required: true },
  size: { type: Number, required: true },
  storagePath: { type: String, required: true }, // NEVER a public folder
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  uploadDate: { type: Date, default: Date.now }
});

// Permission Schema - This is the core of the security model
const permissionSchema = new mongoose.Schema({
  documentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Document', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  accessLevel: { type: String, enum: ['read', 'edit'], required: true },
  grantedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  grantedAt: { type: Date, default: Date.now }
});

// Audit Log Schema - Immutable record of everything
const auditLogSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  documentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Document' }, // Optional, not all actions have a doc
  action: { type: String, enum: ['upload', 'download', 'edit', 'delete', 'permission_granted', 'permission_revoked', 'access_denied', 'login'], required: true },
  status: { type: String, enum: ['success', 'blocked'], required: true },
  ipAddress: { type: String },
  previousHash: { type: String } // For tamper-proofing the log
});

module.exports = {
  User: mongoose.model('User', userSchema),
  Document: mongoose.model('Document', documentSchema),
  Permission: mongoose.model('Permission', permissionSchema),
  AuditLog: mongoose.model('AuditLog', auditLogSchema)
};