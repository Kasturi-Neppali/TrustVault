/**
 * TrustVault - Input Validation & Sanitization Middleware
 * Defense-in-depth against NoSQL injection, malformed payloads, and invalid characters
 */

/**
 * Strips MongoDB operators ($gt, $where, etc.) and dots from object keys
 */
function sanitizeInput(obj) {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeInput);
  }
  const clean = {};
  for (const key of Object.keys(obj)) {
    // Prohibit keys starting with $ or containing .
    if (key.startsWith('$') || key.includes('.')) {
      continue;
    }
    clean[key] = sanitizeInput(obj[key]);
  }
  return clean;
}

/**
 * Express middleware to sanitize req.body, req.query, and req.params
 */
function noSqlSanitizer(req, res, next) {
  if (req.body) req.body = sanitizeInput(req.body);
  if (req.query) req.query = sanitizeInput(req.query);
  if (req.params) req.params = sanitizeInput(req.params);
  next();
}

/**
 * Validates email format strictly
 */
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim().toLowerCase();
  if (trimmed.length > 254) return false;
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return emailRegex.test(trimmed);
}

/**
 * Sanitizes and normalizes email string
 */
function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

module.exports = {
  noSqlSanitizer,
  isValidEmail,
  normalizeEmail,
  sanitizeInput
};

