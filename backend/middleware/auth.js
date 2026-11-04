
const jwt = require('jsonwebtoken');
const { Permission, Document } = require('../models');
const { logAction } = require('../utils/audit');

// 1. Authenticate the User
const authenticateUser = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // The token ONLY contains the userId, nothing else.
    next();
  } catch (ex) {
    res.status(400).json({ error: 'Invalid token.' });
  }
};

// 2. Authorize Document Access (The "Immediate Revocation" Check)
const requireDocumentAccess = (requiredLevel) => {
  return async (req, res, next) => {
    try {
      const documentId = req.params.documentId;
      const userId = req.user.userId;

      // First check: Is the user the actual owner of the document?
      const document = await Document.findById(documentId);
      if (!document) return res.status(404).json({ error: 'Document not found.' });

      if (document.ownerId.toString() === userId) {
        return next(); // Owner has full access
      }

      // Second check: If not the owner, check the real-time database permissions
      const permission = await Permission.findOne({
        documentId: documentId,
        userId: userId
      });

      let isAllowed = false;
      if (permission) {
        if (requiredLevel === 'read' && (permission.accessLevel === 'read' || permission.accessLevel === 'edit')) {
          isAllowed = true;
        } else if (requiredLevel === 'edit' && permission.accessLevel === 'edit') {
          isAllowed = true;
        }
      }

      // If the database row is gone (revoked), this fails immediately.
      if (!isAllowed) {
        // MUST log the failed attempt as per requirements
        await logAction({
          actorId: userId,
          documentId: documentId,
          action: 'access_denied',
          status: 'blocked',
          ipAddress: req.ip
        });
        return res.status(403).json({ error: 'Forbidden: You do not have access to this document.' });
      }

      next();
    } catch (error) {
      res.status(500).json({ error: 'Server error during authorization.' });
    }
  };
};

module.exports = { authenticateUser, requireDocumentAccess };