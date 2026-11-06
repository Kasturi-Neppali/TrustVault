/**
 * TrustVault - Cryptographic Password Utilities
 * Enforces strong password policy & secure bcrypt hashing
 */

const bcrypt = require('bcrypt');

const BCRYPT_SALT_ROUNDS = process.env.NODE_ENV === 'test' ? 6 : 12;

/**
 * Validates password complexity:
 * - Minimum 8 characters, maximum 128 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one numeric digit
 * - At least one special character
 */
function validatePassword(password) {
  if (typeof password !== 'string') {
    return { isValid: false, error: 'Password must be a string.' };
  }

  if (password.length < 8) {
    return { isValid: false, error: 'Password must be at least 8 characters long.' };
  }

  if (password.length > 128) {
    return { isValid: false, error: 'Password cannot exceed 128 characters.' };
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password);

  if (!hasUppercase) {
    return { isValid: false, error: 'Password must include at least one uppercase letter.' };
  }
  if (!hasLowercase) {
    return { isValid: false, error: 'Password must include at least one lowercase letter.' };
  }
  if (!hasDigit) {
    return { isValid: false, error: 'Password must include at least one number.' };
  }
  if (!hasSpecial) {
    return { isValid: false, error: 'Password must include at least one special character.' };
  }

  return { isValid: true };
}

/**
 * Hashes a plaintext password using bcrypt with 12 salt rounds
 */
async function hashPassword(plainPassword) {
  const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
  return bcrypt.hash(plainPassword, salt);
}

/**
 * Compares plaintext password against stored hash using constant-time comparison
 */
async function comparePassword(plainPassword, passwordHash) {
  if (!plainPassword || !passwordHash) return false;
  return bcrypt.compare(plainPassword, passwordHash);
}

module.exports = {
  validatePassword,
  hashPassword,
  comparePassword,
  BCRYPT_SALT_ROUNDS
};
