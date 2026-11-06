const mongoose = require('mongoose');

// ==========================================
// User Schema
// ==========================================
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address.']
  },
  name: {
    type: String,
    required: true,
    trim: true,
    default: 'User'
  },
  passwordHash: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'user'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update timestamp hook
userSchema.pre('save', function () {
  this.updatedAt = new Date();
});

// ==========================================
// Document Schema
// ==========================================
const documentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 255
  },
  category: {
    type: String,
    required: true,
    trim: true,
    default: 'General',
    maxlength: 100
  },
  originalFilename: {
    type: String,
    required: true
  },
  mimeType: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true,
    max: 10 * 1024 * 1024 // 10MB absolute model maximum
  },
  storagePath: {
    type: String,
    required: true,
    unique: true
  },
  ownerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  uploadDate: {
    type: Date,
    default: Date.now
  }
});

// ==========================================
// Permission Schema (Document-Specific Access)
// ==========================================
const permissionSchema = new mongoose.Schema({
  documentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Document',
    required: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  accessLevel: {
    type: String,
    enum: ['read', 'edit', 'viewer', 'editor'],
    required: true
  },
  grantedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  grantedAt: {
    type: Date,
    default: Date.now
  }
});

// Critical Constraint: Prevent duplicate permissions for the same document and user
permissionSchema.index({ documentId: 1, userId: 1 }, { unique: true });

// ==========================================
// Audit Log Schema (Tamper-Evident Hash Chain)
// ==========================================
const auditLogSchema = new mongoose.Schema({
  eventId: {
    type: String,
    required: true,
    unique: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    required: true,
    index: true
  },
  actorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  actorEmail: {
    type: String,
    default: null
  },
  action: {
    type: String,
    enum: [
      'register',
      'login',
      'logout',
      'upload',
      'download',
      'edit',
      'delete',
      'permission_granted',
      'permission_revoked',
      'access_denied',
      'admin_action',
      'security_alert'
    ],
    required: true
  },
  status: {
    type: String,
    enum: ['success', 'blocked', 'failure'],
    required: true
  },
  documentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Document',
    default: null
  },
  targetUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  ipAddress: {
    type: String,
    default: 'unknown'
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  previousHash: {
    type: String,
    required: true
  },
  currentHash: {
    type: String,
    required: true,
    index: true
  }
});

// Enforce chronological indexing
auditLogSchema.index({ timestamp: -1, _id: -1 });

module.exports = {
  User: mongoose.model('User', userSchema),
  Document: mongoose.model('Document', documentSchema),
  Permission: mongoose.model('Permission', permissionSchema),
  AuditLog: mongoose.model('AuditLog', auditLogSchema)
};
