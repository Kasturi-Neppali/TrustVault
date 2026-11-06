/**
 * TrustVault - Rate Limiting Security Middleware
 * Mitigates brute-force attacks, credential stuffing, and API denial-of-service
 */

const rateLimit = require('express-rate-limit');

// When testing, skip rate limiting so automated test suites can run without false positives
const isTest = process.env.NODE_ENV === 'test';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isTest ? 1000 : 10,  // 10 attempts per 15 min in production/dev
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts from this IP. Please try again after 15 minutes.'
  },
  skip: () => isTest
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isTest ? 5000 : 300, // 300 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests from this IP. Please try again later.'
  },
  skip: () => isTest
});

module.exports = {
  authLimiter,
  apiLimiter
};

