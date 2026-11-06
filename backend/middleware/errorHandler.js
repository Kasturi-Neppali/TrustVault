/**
 * TrustVault - Centralized Secure Error Handler
 * Sanitizes error outputs to prevent information disclosure in production
 */

function errorHandler(err, req, res, next) {
  const isProduction = process.env.NODE_ENV === 'production';

  // Always log detailed error internally for server operations
  console.error('[SERVER_ERROR]', {
    message: err.message,
    path: req.originalUrl,
    method: req.method,
    stack: isProduction ? undefined : err.stack
  });

  const statusCode = err.status || err.statusCode || 500;
  
  // Safe user-facing error message
  const safeMessage = (isProduction && statusCode === 500)
    ? 'An unexpected internal error occurred. Please contact security support.'
    : err.message || 'Internal Server Error';

  res.status(statusCode).json({
    error: safeMessage
  });
}

module.exports = errorHandler;

