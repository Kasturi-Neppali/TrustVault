/**
 * TrustVault - Secure Document Lifecycle & Access Control Routes
 * Implements upload with magic-byte verification, secure downloads, metadata editing,
 * granular sharing by verified email, and immediate revocation.
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');

const { Document, Permission, User } = require('../models');
const { authenticateUser, requireDocumentAccess } = require('../middleware/auth');
const {
  ALLOWED_EXTENSIONS,
  ALLOWED_MIME_TYPES,
  verifyFileSignature,
  sanitizeOriginalFilename,
  generateStorageFilename,
  isPathWithinRoot
} = require('../utils/fileValidation');
const { normalizeEmail } = require('../middleware/validate');
const { logAction } = require('../utils/audit');

const router = express.Router();

// 1. Configure Storage Root (Decoupled from web root, configurable via env)
const storageDir = process.env.STORAGE_DIR
  ? path.resolve(process.env.STORAGE_DIR)
  : path.join(__dirname, '..', 'storage');

if (!fs.existsSync(storageDir)) {
  fs.mkdirSync(storageDir, { recursive: true });
}

// 2. Configure Multer with Memory Storage for in-memory signature validation before disk persistence
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB strict limit
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext) || !ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return cb(new Error('Invalid file type or extension. Only PDF, PNG, JPG, and TXT files are permitted.'));
    }
    cb(null, true);
  }
});

/**
 * [POST] /api/documents/upload
 * Requires authentication. Verifies magic bytes, generates UUID storage filename, saves metadata & logs event.
 */
router.post('/upload', authenticateUser, (req, res, next) => {
  upload.single('document')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File size exceeds maximum allowed limit of 5MB.' });
      }
      return res.status(400).json({ error: `Upload error: ${err.message}` });
    } else if (err) {
      return res.status(400).json({ error: err.message });
    }
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ error: 'No file uploaded or file payload was empty.' });
    }

    const { title, category } = req.body;

    // 1. Verify actual file signature (magic bytes) against reported MIME type
    const signatureCheck = verifyFileSignature(req.file.buffer, req.file.mimetype);
    if (!signatureCheck.isValid) {
      return res.status(400).json({ error: signatureCheck.error });
    }

    // 2. Generate safe identifiers
    const sanitizedOriginal = sanitizeOriginalFilename(req.file.originalname);
    const storageFilename = generateStorageFilename(sanitizedOriginal);
    const destinationPath = path.join(storageDir, storageFilename);

    // Verify destination remains strictly within storage root
    if (!isPathWithinRoot(destinationPath, storageDir)) {
      return res.status(400).json({ error: 'Invalid storage destination path.' });
    }

    // 3. Persist validated file buffer to private storage directory
    await fs.promises.writeFile(destinationPath, req.file.buffer);

    // 4. Save Document metadata in database
    const newDocument = new Document({
      title: (typeof title === 'string' && title.trim()) ? title.trim().slice(0, 255) : sanitizedOriginal,
      category: (typeof category === 'string' && category.trim()) ? category.trim().slice(0, 100) : 'General',
      originalFilename: sanitizedOriginal,
      mimeType: signatureCheck.detectedType || req.file.mimetype,
      size: req.file.size,
      storagePath: storageFilename,
      ownerId: req.user.userId
    });

    await newDocument.save();

    // 5. Append upload event to cryptographic audit ledger
    await logAction({
      actorId: req.user.userId,
      actorEmail: req.user.email,
      documentId: newDocument._id,
      action: 'upload',
      status: 'success',
      ipAddress: req.ip,
      metadata: {
        filename: sanitizedOriginal,
        fileSize: req.file.size,
        mimeType: newDocument.mimeType
      }
    });

    res.status(201).json({
      message: 'Document uploaded and secured successfully.',
      documentId: newDocument._id,
      document: {
        id: newDocument._id,
        title: newDocument.title,
        category: newDocument.category,
        originalFilename: newDocument.originalFilename,
        mimeType: newDocument.mimeType,
        size: newDocument.size,
        uploadDate: newDocument.uploadDate
      }
    });
  } catch (error) {
    console.error('Upload Error:', error);
    res.status(500).json({ error: 'Internal server error during document upload.' });
  }
});

/**
 * [GET] /api/documents
 * Fetches all documents owned by or explicitly granted to the authenticated user
 */
router.get('/', authenticateUser, async (req, res) => {
  try {
    const ownedDocs = await Document.find({ ownerId: req.user.userId })
      .sort({ uploadDate: -1 })
      .lean();

    const permissions = await Permission.find({ userId: req.user.userId })
      .populate('documentId')
      .populate('grantedBy', 'email name')
      .lean();

    // Format granted documents with access level and granter info
    const grantedDocs = permissions
      .filter(p => p.documentId !== null && typeof p.documentId === 'object')
      .map(p => ({
        ...p.documentId,
        accessLevel: p.accessLevel,
        grantedBy: p.grantedBy,
        grantedAt: p.grantedAt
      }));

    res.json({
      owned: ownedDocs,
      granted: grantedDocs
    });
  } catch (error) {
    console.error('Fetch Documents Error:', error);
    res.status(500).json({ error: 'Internal server error while fetching documents.' });
  }
});

/**
 * [GET] /api/documents/:id
 * Fetches document metadata if user has read permission or ownership
 */
router.get('/:id', authenticateUser, requireDocumentAccess('read'), async (req, res) => {
  res.json({
    document: {
      id: req.document._id,
      title: req.document.title,
      category: req.document.category,
      originalFilename: req.document.originalFilename,
      mimeType: req.document.mimeType,
      size: req.document.size,
      ownerId: req.document.ownerId,
      uploadDate: req.document.uploadDate
    },
    userAccessLevel: req.userAccessLevel
  });
});

/**
 * [GET] /api/documents/:id/download
 * Secure document download with real-time authorization, path traversal check, and safe headers
 */
router.get('/:id/download', authenticateUser, requireDocumentAccess('read'), async (req, res) => {
  try {
    const document = req.document;
    const filePath = path.join(storageDir, document.storagePath);

    // Defense-in-depth: Verify path containment
    if (!isPathWithinRoot(filePath, storageDir)) {
      await logAction({
        actorId: req.user.userId,
        actorEmail: req.user.email,
        documentId: document._id,
        action: 'security_alert',
        status: 'blocked',
        ipAddress: req.ip,
        metadata: { threat: 'Path traversal attempted during file download', attemptedPath: document.storagePath }
      });
      return res.status(403).json({ error: 'Security violation: Invalid storage boundary.' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Storage file is missing on server.' });
    }

    // Append successful download to audit trail
    await logAction({
      actorId: req.user.userId,
      actorEmail: req.user.email,
      documentId: document._id,
      action: 'download',
      status: 'success',
      ipAddress: req.ip,
      metadata: {
        accessLevel: req.userAccessLevel,
        filename: document.originalFilename
      }
    });

    // Set secure download headers
    res.setHeader('Content-Type', document.mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(document.originalFilename)}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  } catch (error) {
    console.error('Download Error:', error);
    res.status(500).json({ error: 'Internal server error during download streaming.' });
  }
});

/**
 * [PATCH] /api/documents/:id
 * Allows document owner or users with 'edit' access to update document metadata (title, category)
 */
router.patch('/:id', authenticateUser, requireDocumentAccess('edit'), async (req, res) => {
  try {
    const { title, category } = req.body;
    const document = req.document;

    if (title && typeof title === 'string') {
      document.title = title.trim().slice(0, 255);
    }
    if (category && typeof category === 'string') {
      document.category = category.trim().slice(0, 100);
    }

    await document.save();

    await logAction({
      actorId: req.user.userId,
      actorEmail: req.user.email,
      documentId: document._id,
      action: 'edit',
      status: 'success',
      ipAddress: req.ip,
      metadata: { updatedTitle: document.title, updatedCategory: document.category }
    });

    res.json({
      message: 'Document metadata updated successfully.',
      document
    });
  } catch (error) {
    console.error('Metadata Update Error:', error);
    res.status(500).json({ error: 'Internal server error updating document metadata.' });
  }
});

/**
 * [DELETE] /api/documents/:id
 * Permanently deletes a document, physical file, and all associated permissions. Owner only.
 */
router.delete('/:id', authenticateUser, requireDocumentAccess('owner'), async (req, res) => {
  try {
    const document = req.document;
    const filePath = path.join(storageDir, document.storagePath);

    // 1. Remove physical file from disk if present
    if (fs.existsSync(filePath) && isPathWithinRoot(filePath, storageDir)) {
      try {
        await fs.promises.unlink(filePath);
      } catch (fsErr) {
        console.warn('Warning: Could not delete physical file on disk:', fsErr.message);
      }
    }

    // 2. Cascade delete all permission grants
    await Permission.deleteMany({ documentId: document._id });

    // 3. Delete Document record
    await Document.findByIdAndDelete(document._id);

    // 4. Log deletion in audit ledger
    await logAction({
      actorId: req.user.userId,
      actorEmail: req.user.email,
      documentId: document._id,
      action: 'delete',
      status: 'success',
      ipAddress: req.ip,
      metadata: { deletedFilename: document.originalFilename, deletedTitle: document.title }
    });

    res.json({ message: 'Document and all associated permissions deleted permanently.' });
  } catch (error) {
    console.error('Delete Document Error:', error);
    res.status(500).json({ error: 'Internal server error deleting document.' });
  }
});

// ==========================================
// DOCUMENT SHARING & PERMISSION MANAGEMENT
// ==========================================

/**
 * [GET] /api/documents/:id/permissions
 * Retrieves active sharing permissions for a document. Owner only.
 */
router.get('/:id/permissions', authenticateUser, requireDocumentAccess('owner'), async (req, res) => {
  try {
    const permissions = await Permission.find({ documentId: req.document._id })
      .populate('userId', 'email name')
      .populate('grantedBy', 'email name')
      .sort({ grantedAt: -1 })
      .lean();

    res.json({ permissions });
  } catch (error) {
    console.error('Fetch Permissions Error:', error);
    res.status(500).json({ error: 'Internal server error fetching permissions.' });
  }
});

/**
 * Shared helper for granting access to a user
 */
async function handleShareDocument(req, res) {
  try {
    const { targetUserId, targetEmail, accessLevel } = req.body;
    const document = req.document;
    const ownerId = req.user.userId;

    // Validate access level
    const normalizedLevel = String(accessLevel || '').toLowerCase();
    const validLevels = ['read', 'viewer', 'edit', 'editor'];
    if (!validLevels.includes(normalizedLevel)) {
      return res.status(400).json({ error: 'Invalid access level. Must be "viewer" (or "read") or "editor" (or "edit").' });
    }

    // Normalize access level internally to 'read' or 'edit'
    const canonicalAccessLevel = (normalizedLevel === 'editor' || normalizedLevel === 'edit') ? 'edit' : 'read';

    // Resolve target recipient by email or ID
    let targetUser = null;
    if (targetEmail) {
      targetUser = await User.findOne({ email: normalizeEmail(targetEmail) });
    } else if (targetUserId) {
      if (mongoose.Types.ObjectId.isValid(targetUserId)) {
        targetUser = await User.findById(targetUserId);
      }
    }

    if (!targetUser) {
      return res.status(404).json({ error: 'Recipient user account does not exist. Please check the email address or user ID.' });
    }

    // Prevent owner from sharing with self
    if (targetUser._id.toString() === ownerId) {
      return res.status(400).json({ error: 'You are already the owner of this document.' });
    }

    // Upsert permission in database
    const permission = await Permission.findOneAndUpdate(
      { documentId: document._id, userId: targetUser._id },
      {
        accessLevel: canonicalAccessLevel,
        grantedBy: ownerId,
        grantedAt: new Date()
      },
      { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
    );

    // Append sharing event to audit ledger
    await logAction({
      actorId: ownerId,
      actorEmail: req.user.email,
      documentId: document._id,
      targetUserId: targetUser._id,
      action: 'permission_granted',
      status: 'success',
      ipAddress: req.ip,
      metadata: {
        recipientEmail: targetUser.email,
        accessLevel: canonicalAccessLevel
      }
    });

    res.json({
      message: `Access (${canonicalAccessLevel}) granted to ${targetUser.email} successfully.`,
      permission
    });
  } catch (error) {
    console.error('Grant Access Error:', error);
    res.status(500).json({ error: 'Internal server error while granting access.' });
  }
}

/**
 * [POST] /api/documents/:id/share
 * Preferred RESTful sharing endpoint
 */
router.post('/:id/share', authenticateUser, requireDocumentAccess('owner'), handleShareDocument);

/**
 * [POST] /api/documents/:documentId/grant
 * Preserved for backward compatibility
 */
router.post('/:documentId/grant', authenticateUser, requireDocumentAccess('owner'), handleShareDocument);

/**
 * Shared helper for revoking access
 */
async function handleRevokeDocument(req, res) {
  try {
    const { targetUserId } = req.body || {};
    const permissionId = req.params.permissionId;
    const document = req.document;
    const ownerId = req.user.userId;

    let query = { documentId: document._id };

    if (permissionId) {
      if (!mongoose.Types.ObjectId.isValid(permissionId)) {
        return res.status(400).json({ error: 'Invalid permission ID format.' });
      }
      query._id = permissionId;
    } else if (targetUserId) {
      if (!mongoose.Types.ObjectId.isValid(targetUserId)) {
        return res.status(400).json({ error: 'Invalid user ID format.' });
      }
      query.userId = targetUserId;
    } else {
      return res.status(400).json({ error: 'Target user ID or permission ID is required to revoke access.' });
    }

    const deleted = await Permission.findOneAndDelete(query);
    if (!deleted) {
      return res.status(404).json({ error: 'Permission entry not found or already revoked.' });
    }

    // Append revocation to audit ledger
    await logAction({
      actorId: ownerId,
      actorEmail: req.user.email,
      documentId: document._id,
      targetUserId: deleted.userId,
      action: 'permission_revoked',
      status: 'success',
      ipAddress: req.ip,
      metadata: { revokedAccessLevel: deleted.accessLevel }
    });

    res.json({ message: 'Document access revoked immediately.' });
  } catch (error) {
    console.error('Revoke Access Error:', error);
    res.status(500).json({ error: 'Internal server error while revoking access.' });
  }
}

/**
 * [DELETE] /api/documents/:id/permissions/:permissionId
 * Preferred RESTful revocation endpoint
 */
router.delete('/:id/permissions/:permissionId', authenticateUser, requireDocumentAccess('owner'), handleRevokeDocument);

/**
 * [POST] /api/documents/:documentId/revoke
 * Preserved for backward compatibility
 */
router.post('/:documentId/revoke', authenticateUser, requireDocumentAccess('owner'), handleRevokeDocument);

module.exports = router;
