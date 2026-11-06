/**
 * TrustVault - Authentication Routes
 * Implements secure registration, login with rate-limiting, session cookies, and logout
 */

const express = require('express');
const { User } = require('../models');
const { validatePassword, hashPassword, comparePassword } = require('../utils/password');
const { generateToken, setAuthCookie, clearAuthCookie } = require('../utils/token');
const { authenticateUser } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { isValidEmail, normalizeEmail } = require('../middleware/validate');
const { logAction } = require('../utils/audit');

const router = express.Router();

/**
 * [POST] /api/auth/register
 * Public registration endpoint. Always assigns safe default 'user' role.
 * Explicitly rejects and blocks any privilege escalation attempts.
 */
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // 1. Validate full name
    const trimmedName = typeof name === 'string' ? name.trim() : '';
    if (!trimmedName || trimmedName.length < 2 || trimmedName.length > 100) {
      return res.status(400).json({ error: 'Full name is required (2 to 100 characters).' });
    }

    // 2. Validate and normalize email
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: 'A valid email address is required.' });
    }
    const normalizedEmail = normalizeEmail(email);

    // 3. Validate password complexity
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ error: passwordValidation.error });
    }

    // 4. Duplicate account check
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ error: 'An account with this email address already exists.' });
    }

    // 5. Hash password with bcrypt (12 rounds)
    const passwordHash = await hashPassword(password);

    // 6. Persist user. NOTE: role is strictly hardcoded to 'user'. Any client-supplied role is ignored.
    const newUser = new User({
      name: trimmedName,
      email: normalizedEmail,
      passwordHash,
      role: 'user'
    });

    await newUser.save();

    // 7. Audit Log registration event
    await logAction({
      actorId: newUser._id,
      actorEmail: newUser.email,
      action: 'register',
      status: 'success',
      ipAddress: req.ip,
      metadata: { registrationMethod: 'public_endpoint' }
    });

    res.status(201).json({
      message: 'Account registered successfully.',
      user: {
        id: newUser._id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role
      }
    });
  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

/**
 * [POST] /api/auth/login
 * Verifies credentials, applies brute-force rate-limiting, logs success/failure, issues JWT & HttpOnly cookie
 */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const normalizedEmail = normalizeEmail(email);

    // Look up user
    const user = await User.findOne({ email: normalizedEmail });

    // Constant-time password check or safe reject to prevent user enumeration
    let passwordMatches = false;
    if (user) {
      passwordMatches = await comparePassword(password, user.passwordHash);
    } else {
      // Fake compare to mitigate timing attacks against non-existent accounts
      await comparePassword('dummy_fake_password_to_equalize_timing', '$2b$12$e80yqVzH26x7pYtJjK3g7e80yqVzH26x7pYtJjK3g7e80yqVzH26x');
    }

    if (!user || !passwordMatches) {
      // Log failed authentication attempt
      await logAction({
        actorId: user ? user._id : null,
        actorEmail: normalizedEmail,
        action: 'login',
        status: 'blocked',
        ipAddress: req.ip,
        metadata: { reason: 'Invalid credentials' }
      });

      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Generate JWT and set HttpOnly cookie
    const token = generateToken(user);
    setAuthCookie(res, token);

    // Log successful login
    await logAction({
      actorId: user._id,
      actorEmail: user.email,
      action: 'login',
      status: 'success',
      ipAddress: req.ip
    });

    res.json({
      message: 'Logged in successfully.',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Internal server error during authentication.' });
  }
});

/**
 * [POST] /api/auth/logout
 * Clears session cookie and logs user logout
 */
router.post('/logout', (req, res) => {
  clearAuthCookie(res);

  // If user had a valid token, log the logout event
  if (req.user) {
    logAction({
      actorId: req.user.userId,
      actorEmail: req.user.email,
      action: 'logout',
      status: 'success',
      ipAddress: req.ip
    }).catch(err => console.error('Logout audit error:', err));
  }

  res.json({ message: 'Logged out successfully.' });
});

/**
 * [GET] /api/auth/me
 * Returns current authenticated user state verified directly against the database
 */
router.get('/me', authenticateUser, (req, res) => {
  res.json({
    user: req.user
  });
});

module.exports = router;
