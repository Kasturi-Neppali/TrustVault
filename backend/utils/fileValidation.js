/**
 * TrustVault - Secure File Validation & Storage Engine
 * Verifies file magic bytes, sanitizes filenames, and prevents path traversal
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const uuidv4 = () => crypto.randomUUID();

const ALLOWED_EXTENSIONS = ['.pdf', '.png', '.jpg', '.jpeg', '.txt'];

const ALLOWED_MIME_TYPES = [
  'application/pdf',
  'image/png',
  'image/jpeg',
  'text/plain'
];

/**
 * Inspects binary buffer for actual file signatures (magic bytes)
 */
function verifyFileSignature(buffer, reportedMimeType) {
  if (!buffer || buffer.length < 4) {
    return { isValid: false, error: 'File is empty or corrupted.' };
  }

  // 1. PDF Signature: %PDF (0x25 0x50 0x44 0x46)
  const isPdf = buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46;

  // 2. PNG Signature: 89 50 4E 47 0D 0A 1A 0A
  const isPng = buffer.length >= 8 &&
    buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47 &&
    buffer[4] === 0x0d && buffer[5] === 0x0a && buffer[6] === 0x1a && buffer[7] === 0x0a;

  // 3. JPEG Signature: FF D8 FF
  const isJpeg = buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;

  // 4. TXT Signature: Must be valid text without null bytes or binary executable headers
  const isExecutableHeader = (buffer[0] === 0x4d && buffer[1] === 0x5a) || // MZ (Windows EXE/DLL)
                             (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46); // ELF (Linux binary)

  let isCleanText = false;
  if (!isExecutableHeader && !isPdf && !isPng && !isJpeg) {
    // Check first 1024 bytes for null bytes or control characters
    const sampleSize = Math.min(buffer.length, 1024);
    let containsNullByte = false;
    for (let i = 0; i < sampleSize; i++) {
      if (buffer[i] === 0x00) {
        containsNullByte = true;
        break;
      }
    }
    if (!containsNullByte) {
      isCleanText = true;
    }
  }

  // Verify match with declared MIME type
  if (reportedMimeType === 'application/pdf') {
    if (!isPdf) return { isValid: false, error: 'File content does not match PDF signature (magic byte mismatch).' };
    return { isValid: true, detectedType: 'application/pdf' };
  }

  if (reportedMimeType === 'image/png') {
    if (!isPng) return { isValid: false, error: 'File content does not match PNG signature (magic byte mismatch).' };
    return { isValid: true, detectedType: 'image/png' };
  }

  if (reportedMimeType === 'image/jpeg') {
    if (!isJpeg) return { isValid: false, error: 'File content does not match JPEG signature (magic byte mismatch).' };
    return { isValid: true, detectedType: 'image/jpeg' };
  }

  if (reportedMimeType === 'text/plain') {
    if (isExecutableHeader || !isCleanText) {
      return { isValid: false, error: 'File contains binary or executable content disguised as text.' };
    }
    return { isValid: true, detectedType: 'text/plain' };
  }

  return { isValid: false, error: 'Unsupported or unverified file signature.' };
}

/**
 * Sanitizes original filename (removes directory traversal, control characters)
 */
function sanitizeOriginalFilename(rawName) {
  if (typeof rawName !== 'string') return 'unnamed_file';
  // Strip path traversal sequences like ../ or ..\
  let safe = path.basename(rawName);
  // Remove control characters, null bytes, backslashes, quotes
  safe = safe.replace(/[\x00-\x1F\x7F<>:"/\\|?*]/g, '_').trim();
  if (!safe || safe === '.' || safe === '..') {
    safe = 'document';
  }
  return safe.slice(0, 200);
}

/**
 * Generates an unpredictable, UUID-based storage filename
 */
function generateStorageFilename(originalFilename) {
  const ext = path.extname(originalFilename).toLowerCase();
  const safeExt = ALLOWED_EXTENSIONS.includes(ext) ? ext : '.bin';
  return `${uuidv4()}${safeExt}`;
}

/**
 * Validates that an absolute target path remains strictly contained inside the storage root
 */
function isPathWithinRoot(targetPath, rootDir) {
  const relative = path.relative(rootDir, targetPath);
  return !relative.startsWith('..') && !path.isAbsolute(relative);
}

module.exports = {
  ALLOWED_EXTENSIONS,
  ALLOWED_MIME_TYPES,
  verifyFileSignature,
  sanitizeOriginalFilename,
  generateStorageFilename,
  isPathWithinRoot
};
