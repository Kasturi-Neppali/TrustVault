process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_for_trustvault_auth_tests_strictly_isolated';

const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const app = require('../server');
const { User, AuditLog } = require('../models');

jest.setTimeout(30000);

const os = require('os');
const TEST_DB_URI = 'mongodb://127.0.0.1:27017/trustvault_test_auth?directConnection=true';

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(TEST_DB_URI, {
      runtimeAdapters: { os }
    });
  }
  await User.deleteMany({});
  await AuditLog.deleteMany({});
}, 30000);

afterAll(async () => {
  await User.deleteMany({});
  await AuditLog.deleteMany({});
  await mongoose.connection.close();
}, 30000);

describe('TrustVault Authentication & Session Suite', () => {
  it('1. Successfully registers a standard user with safe default role', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Alice Springs',
        email: 'alice@example.com',
        password: 'Password@1234'
      });

    expect(res.status).toBe(201);
    expect(res.body.user).toBeDefined();
    expect(res.body.user.email).toBe('alice@example.com');
    expect(res.body.user.role).toBe('user');

    // Confirm database record
    const user = await User.findOne({ email: 'alice@example.com' });
    expect(user).toBeTruthy();
    expect(user.role).toBe('user');
    expect(user.passwordHash).not.toBe('Password@1234');
  });

  it('2. CRITICAL SECURITY: Blocks privilege escalation in registration payload', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Mallory Hacker',
        email: 'mallory@example.com',
        password: 'Password@1234',
        role: 'admin',
        isAdmin: true,
        permissions: ['admin']
      });

    expect(res.status).toBe(201);
    // Role MUST remain strictly 'user'
    expect(res.body.user.role).toBe('user');

    const dbUser = await User.findOne({ email: 'mallory@example.com' });
    expect(dbUser.role).toBe('user');
  });

  it('3. Rejects duplicate registration with generic error', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Duplicate Alice',
        email: 'alice@example.com',
        password: 'Password@1234'
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/already exists/i);
  });

  it('4. Rejects invalid email formats', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Bad Email',
        email: 'not-an-email',
        password: 'Password@1234'
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/valid email/i);
  });

  it('5. Rejects weak passwords violating complexity policy', async () => {
    // Too short
    let res = await request(app).post('/api/auth/register').send({
      name: 'Weak One',
      email: 'weak1@example.com',
      password: 'Pass1'
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/at least 8 characters/i);

    // No uppercase
    res = await request(app).post('/api/auth/register').send({
      name: 'Weak Two',
      email: 'weak2@example.com',
      password: 'password@123'
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/uppercase/i);

    // No special character
    res = await request(app).post('/api/auth/register').send({
      name: 'Weak Three',
      email: 'weak3@example.com',
      password: 'Password123'
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/special character/i);
  });

  it('6. Rejects login with incorrect password with generic error', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'alice@example.com',
        password: 'WrongPassword@999'
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password.');

    // Audit log should capture login failure
    const failedLog = await AuditLog.findOne({
      actorEmail: 'alice@example.com',
      action: 'login',
      status: 'blocked'
    });
    expect(failedLog).toBeTruthy();
  });

  it('7. Rejects login for non-existent email with identical generic error', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'ghost@example.com',
        password: 'Password@1234'
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password.');
  });

  it('8. Successfully logs in with valid credentials, issuing JWT and cookie', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'alice@example.com',
        password: 'Password@1234'
      });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email).toBe('alice@example.com');

    // Confirm Set-Cookie header contains trustvault_token
    const cookies = res.headers['set-cookie'];
    expect(cookies).toBeDefined();
    const tokenCookie = cookies.find(c => c.startsWith('trustvault_token='));
    expect(tokenCookie).toBeDefined();
    expect(tokenCookie).toMatch(/HttpOnly/i);
  });

  it('9. Accessing protected route /api/auth/me without authentication returns 401', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Access denied/i);
  });

  it('10. Accessing /api/auth/me with invalid token returns 401', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer totally_invalid_jwt_token');

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Invalid or expired/i);
  });

  it('11. Accessing /api/auth/me with valid Bearer token succeeds', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'alice@example.com',
        password: 'Password@1234'
      });

    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${loginRes.body.token}`);

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('alice@example.com');
  });

  it('12. Accessing /api/auth/me with expired token returns 401', async () => {
    const user = await User.findOne({ email: 'alice@example.com' });
    const expiredToken = jwt.sign(
      { userId: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '-1s' }
    );

    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Invalid or expired/i);
  });

  it('13. Logout clears the active session cookie', async () => {
    const res = await request(app).post('/api/auth/logout');
    expect(res.status).toBe(200);
    const cookies = res.headers['set-cookie'];
    expect(cookies).toBeDefined();
    const clearedCookie = cookies.find(c => c.startsWith('trustvault_token='));
    expect(clearedCookie).toMatch(/Expires=Thu, 01 Jan 1970/i);
  });
});
