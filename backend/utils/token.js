/**
 * TrustVault - JWT & Session Cookie Utilities
 */

const jwt = require('jsonwebtoken');

const JWT_DEFAULT_SECRET = 'trustvault_dev_insecure_jwt_secret_change_me_in_production_123456';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '2h';
const COOKIE_NAME = 'trustvault_token';

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('FATAL SECURITY ERROR: JWT_SECRET environment variable is missing in production!');
    }
    return JWT_DEFAULT_SECRET;
  }
  return secret;
}

/**
 * Generates signed JWT for an authenticated user
 */
function generateToken(user) {
  const payload = {
    userId: user._id ? user._id.toString() : user.userId,
    email: user.email,
    role: user.role
  };

  return jwt.sign(payload, getJwtSecret(), {
    expiresIn: JWT_EXPIRES_IN,
    algorithm: 'HS256'
  });
}

/**
 * Verifies JWT token
 */
function verifyToken(token) {
  return jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] });
}

/**
 * Configures secure HttpOnly cookie on Express response
 */
function setAuthCookie(res, token) {
  const isProduction = process.env.NODE_ENV === 'production';
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 2 * 60 * 60 * 1000 // 2 hours
  });
}

/**
 * Clears session cookie on logout
 */
function clearAuthCookie(res) {
  const isProduction = process.env.NODE_ENV === 'production';
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax'
  });
}

module.exports = {
  generateToken,
  verifyToken,
  setAuthCookie,
  clearAuthCookie,
  COOKIE_NAME
};

