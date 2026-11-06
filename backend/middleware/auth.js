/**
 * TrustVault - Authentication & Authorization Middleware
 * Enforces JWT verification, active user validation, and real-time database permission checks
 */

const mongoose = require('mongoose');
const { verifyToken } = require('../utils/token');
const { User, Document, Permission } = require('../models');
const { logAction } = require('../utils/audit');

/**
 * Authenticates user via HttpOnly cookie or Authorization Bearer header
 */
const authenticateUser = async (req, res, next) => {
  let token = null;

  // 1. Check HttpOnly cookie
  if (req.cookies && req.cookies.trustvault_token) {
    token = req.cookies.trustvault_token;
  }

  // 2. Fallback to Authorization: Bearer <token>
  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    }
  }

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No authentication token provided.' });
  }

  try {
    const decoded = verifyToken(token);

    // Verify user still exists in the database (account not deleted/revoked)
    const user = await User.findById(decoded.userId).select('-passwordHash').lean();
    if (!user) {
      return res.status(401).json({ error: 'Authentication failed. User account does not exist.' });
    }

    req.user = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      name: user.name
    };

    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired authentication token.' });
  }
};

/**
 * Enforces system-level role requirements (e.g. ['admin'])
 */
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: You do not possess the required system role.' });
    }
    next();
  };
};

/**
 * Enforces document-level permissions (owner, editor, viewer/read)
 * Performs real-time database queries to ensure immediate revocation
 */
const requireDocumentAccess = (requiredLevel = 'read') => {
  return async (req, res, next) => {
    try {
      const documentId = req.params.id || req.params.documentId;

      if (!documentId || !mongoose.Types.ObjectId.isValid(documentId)) {
        return res.status(400).json({ error: 'Invalid document ID format.' });
      }

      const document = await Document.findById(documentId);
      if (!document) {
        return res.status(404).json({ error: 'Document not found.' });
      }

      const currentUserId = req.user.userId;

      // 1. Is the requester the Document Owner?
      if (document.ownerId.toString() === currentUserId) {
        req.document = document;
        req.userAccessLevel = 'owner';
        return next();
      }

      // If the route strictly requires Owner authority (e.g. delete, share, revoke)
      if (requiredLevel === 'owner') {
        await logAction({
          actorId: currentUserId,
          actorEmail: req.user.email,
          documentId: document._id,
          action: 'access_denied',
          status: 'blocked',
          ipAddress: req.ip,
          metadata: { reason: 'Non-owner attempted owner-restricted action', requiredLevel }
        });
        return res.status(403).json({ error: 'Forbidden: Only the document owner can perform this operation.' });
      }

      // 2. Check real-time Permission collection for granted access
      const permission = await Permission.findOne({
        documentId: document._id,
        userId: currentUserId
      });

      let isAllowed = false;
      if (permission) {
        const level = permission.accessLevel;
        if (requiredLevel === 'read' && ['read', 'viewer', 'edit', 'editor'].includes(level)) {
          isAllowed = true;
        } else if (requiredLevel === 'edit' && ['edit', 'editor'].includes(level)) {
          isAllowed = true;
        }
      }

      if (!isAllowed) {
        await logAction({
          actorId: currentUserId,
          actorEmail: req.user.email,
          documentId: document._id,
          action: 'access_denied',
          status: 'blocked',
          ipAddress: req.ip,
          metadata: {
            reason: permission ? 'Insufficient document permissions' : 'No document permission record found',
            requiredLevel,
            grantedLevel: permission?.accessLevel || null
          }
        });
        return res.status(403).json({ error: 'Forbidden: You do not have access to this document.' });
      }

      req.document = document;
      req.permission = permission;
      req.userAccessLevel = permission.accessLevel;
      next();
    } catch (error) {
      console.error('Authorization Middleware Error:', error);
      res.status(500).json({ error: 'Internal server error during authorization check.' });
    }
  };
};

module.exports = {
  authenticateUser,
  requireRole,
  requireDocumentAccess
};
