
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { Document, Permission } = require('../models');
const { authenticateUser, requireDocumentAccess } = require('../middleware/auth');
const { logAction } = require('../utils/audit');

const router = express.Router();

// 1. Configure Secure Storage (Files go to backend/storage, NEVER public)
const storageDir = path.join(__dirname, '..', 'storage');
if (!fs.existsSync(storageDir)) {
    fs.mkdirSync(storageDir); // Create the folder if it doesn't exist
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, storageDir);
    },
    filename: (req, file, cb) => {
        // Obfuscate the filename on disk so it can't be guessed
        const uniqueName = `${uuidv4()}-${file.originalname}`;
        cb(null, uniqueName);
    }
});

// File validation - only allow specific types
const fileFilter = (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'text/plain'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only PDF, JPG, PNG, and TXT are allowed.'));
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// [POST] /api/documents/upload (Requires Authentication)
router.post('/upload', authenticateUser, upload.single('document'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded or invalid file type.' });
        }

        const { title, category } = req.body;

        // 1. Save document metadata to DB
        const newDocument = new Document({
            title: title || req.file.originalname,
            category: category || 'Uncategorized',
            originalFilename: req.file.originalname,
            mimeType: req.file.mimetype,
            size: req.file.size,
            storagePath: req.file.filename, // Only the obfuscated name is saved
            ownerId: req.user.userId
        });
        await newDocument.save();

        // 2. The Uploader becomes the Owner (full access implicitly granted in our middleware, 
        // but we can explicitly log it)
        await logAction({
            actorId: req.user.userId,
            documentId: newDocument._id,
            action: 'upload',
            status: 'success',
            ipAddress: req.ip
        });

        res.status(201).json({
            message: 'Document uploaded successfully.',
            documentId: newDocument._id
        });

    } catch (error) {
        console.error("Upload Error:", error);
        res.status(500).json({ error: 'Server error during upload.' });
    }
});

// [GET] /api/documents
// Fetch documents the user owns AND documents they have been granted access to
router.get('/', authenticateUser, async (req, res) => {
    try {
        const ownedDocs = await Document.find({ ownerId: req.user.userId }).lean();
        
        const permissions = await Permission.find({ userId: req.user.userId }).lean();
        const grantedDocIds = permissions.map(p => p.documentId);
        const grantedDocs = await Document.find({ _id: { $in: grantedDocIds } }).lean();

        res.json({ owned: ownedDocs, granted: grantedDocs });
    } catch (error) {
        console.error("Fetch Documents Error:", error);
        res.status(500).json({ error: 'Server error while fetching documents.' });
    }
});

// [GET] /api/documents/:documentId/download 
// The most important route: Requires auth AND document access permission
router.get('/:documentId/download', authenticateUser, requireDocumentAccess('read'), async (req, res) => {
    try {
        const document = await Document.findById(req.params.documentId);
        
        if (!document) {
            return res.status(404).json({ error: 'Document not found.' });
        }

        const filePath = path.join(storageDir, document.storagePath);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File physically missing on server.' });
        }

        // Audit Log: Record successful download
        await logAction({
            actorId: req.user.userId,
            documentId: document._id,
            action: 'download',
            status: 'success',
            ipAddress: req.ip
        });

        // Stream the file back securely
        res.download(filePath, document.originalFilename);

    } catch (error) {
        console.error("Download Error:", error);
        res.status(500).json({ error: 'Server error during download.' });
    }
});

// --- PERMISSION MANAGEMENT ENDPOINTS ---

// [POST] /api/documents/:documentId/grant
// Only the Owner can grant access to another user
router.post('/:documentId/grant', authenticateUser, async (req, res) => {
    try {
        const { targetUserId, accessLevel } = req.body;
        const documentId = req.params.documentId;
        const ownerId = req.user.userId;

        // 1. Verify the requester actually owns the document
        const document = await Document.findById(documentId);
        if (!document) {
            return res.status(404).json({ error: 'Document not found.' });
        }
        if (document.ownerId.toString() !== ownerId) {
            return res.status(403).json({ error: 'Only the owner can grant access.' });
        }

        // 2. Validate inputs
        if (!['read', 'edit'].includes(accessLevel)) {
            return res.status(400).json({ error: 'Invalid access level. Must be read or edit.' });
        }

        // 3. Upsert the permission (Create if new, update if it exists)
        await Permission.findOneAndUpdate(
            { documentId, userId: targetUserId },
            { accessLevel, grantedBy: ownerId, grantedAt: Date.now() },
            { upsert: true, new: true }
        );

        // 4. Audit Log
        await logAction({
            actorId: ownerId,
            documentId: documentId,
            action: 'permission_granted',
            status: 'success',
            ipAddress: req.ip
        });

        res.json({ message: `Access (${accessLevel}) granted to user successfully.` });

    } catch (error) {
        console.error("Grant Permission Error:", error);
        res.status(500).json({ error: 'Server error while granting permission.' });
    }
});


// [POST] /api/documents/:documentId/revoke
// Only the Owner can revoke access
router.post('/:documentId/revoke', authenticateUser, async (req, res) => {
    try {
        const { targetUserId } = req.body;
        const documentId = req.params.documentId;
        const ownerId = req.user.userId;

        // 1. Verify the requester actually owns the document
        const document = await Document.findById(documentId);
        if (!document) {
            return res.status(404).json({ error: 'Document not found.' });
        }
        if (document.ownerId.toString() !== ownerId) {
            return res.status(403).json({ error: 'Only the owner can revoke access.' });
        }

        // 2. Delete the permission record (This triggers the "Immediate Revocation")
        const result = await Permission.findOneAndDelete({
            documentId: documentId,
            userId: targetUserId
        });

        if (!result) {
            return res.status(400).json({ error: 'User did not have access to this document.' });
        }

        // 3. Audit Log
        await logAction({
            actorId: ownerId,
            documentId: documentId,
            action: 'permission_revoked',
            status: 'success',
            ipAddress: req.ip
        });

        res.json({ message: 'Access revoked immediately.' });

    } catch (error) {
        console.error("Revoke Permission Error:", error);
        res.status(500).json({ error: 'Server error while revoking permission.' });
    }
});



module.exports = router;