process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_for_trustvault_audit_tests';

const request = require('supertest');
const mongoose = require('mongoose');
const os = require('os');
const app = require('../server');
const { User, AuditLog } = require('../models');
const { logAction, sanitizeMetadata } = require('../utils/audit');
const { verifyAuditChain, GENESIS_HASH } = require('../utils/auditIntegrity');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/trustvault_test_audit?directConnection=true';

let adminToken, userToken;
let adminId, userId;

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(TEST_DB_URI, {
      runtimeAdapters: { os }
    });
  }
  await User.deleteMany({});
  await AuditLog.deleteMany({});

  // 1. Create standard user
  const uRes = await request(app).post('/api/auth/register').send({
    name: 'Normal User',
    email: 'normal@example.com',
    password: 'Password@1234'
  });
  userId = uRes.body.user.id;

  const uLogin = await request(app).post('/api/auth/login').send({
    email: 'normal@example.com',
    password: 'Password@1234'
  });
  userToken = uLogin.body.token;

  // 2. Create system admin directly in DB for testing
  const { hashPassword } = require('../utils/password');
  const adminUser = new User({
    name: 'Admin Test',
    email: 'admintest@trustvault.com',
    passwordHash: await hashPassword('AdminPass@1234'),
    role: 'admin'
  });
  await adminUser.save();
  adminId = adminUser._id;

  const aLogin = await request(app).post('/api/auth/login').send({
    email: 'admintest@trustvault.com',
    password: 'AdminPass@1234'
  });
  adminToken = aLogin.body.token;
}, 30000);

afterAll(async () => {
  await User.deleteMany({});
  await AuditLog.deleteMany({});
  await mongoose.connection.close();
}, 30000);

describe('TrustVault Tamper-Evident Audit Logging Suite', () => {
  it('1. Confirms genesis record previousHash equals 64 zeros', async () => {
    // Clear logs to test genesis behavior from clean state
    await AuditLog.deleteMany({});

    const entry1 = await logAction({
      actorId: userId,
      actorEmail: 'normal@example.com',
      action: 'login',
      status: 'success',
      ipAddress: '127.0.0.1'
    });

    expect(entry1.previousHash).toBe(GENESIS_HASH);
    expect(entry1.currentHash).toHaveLength(64);
  });

  it('2. Chains subsequent records: record[N].previousHash === record[N-1].currentHash', async () => {
    const entry2 = await logAction({
      actorId: userId,
      actorEmail: 'normal@example.com',
      action: 'upload',
      status: 'success',
      ipAddress: '127.0.0.1',
      metadata: { filename: 'doc1.pdf' }
    });

    const lastLogs = await AuditLog.find().sort({ timestamp: 1, _id: 1 });
    expect(lastLogs.length).toBe(2);
    expect(entry2.previousHash).toBe(lastLogs[0].currentHash);
  });

  it('3. Sanitizes sensitive keys (passwords, tokens) before logging', () => {
    const dirtyMetadata = {
      user: 'alice',
      password: 'PlainSecretPassword123!',
      jwt: 'eyJhbGciOi...',
      nested: {
        token: 'secret_token_value',
        allowedNote: 'Audit note'
      }
    };

    const clean = sanitizeMetadata(dirtyMetadata);
    expect(clean.password).toBe('[REDACTED_BY_AUDIT_SECURITY]');
    expect(clean.jwt).toBe('[REDACTED_BY_AUDIT_SECURITY]');
    expect(clean.nested.token).toBe('[REDACTED_BY_AUDIT_SECURITY]');
    expect(clean.nested.allowedNote).toBe('Audit note');
  });

  it('4. Handles high-concurrency writes sequentially without chain bifurcation', async () => {
    // Fire 10 concurrent audit writes simultaneously
    const promises = [];
    for (let i = 0; i < 10; i++) {
      promises.push(
        logAction({
          actorId: userId,
          actorEmail: 'normal@example.com',
          action: 'download',
          status: 'success',
          ipAddress: '127.0.0.1',
          metadata: { concurrentIndex: i }
        })
      );
    }

    await Promise.all(promises);

    // Verify chain integrity after concurrent writes
    const report = await verifyAuditChain(AuditLog);
    expect(report.isValid).toBe(true);
    expect(report.totalRecords).toBe(12); // 2 previous + 10 concurrent
    expect(report.verifiedRecords).toBe(12);
  });

  it('5. Cryptographic verification succeeds on uncorrupted ledger', async () => {
    const report = await verifyAuditChain(AuditLog);
    expect(report.isValid).toBe(true);
    expect(report.message).toMatch(/verified|zero tampering/i);
  });

  it('6. CRITICAL SECURITY: Detects tampered record content in database', async () => {
    // Tamper with record #3 directly in MongoDB collection (bypassing app logic)
    const records = await AuditLog.find().sort({ timestamp: 1, _id: 1 });
    const victimRecord = records[2];

    await AuditLog.updateOne(
      { _id: victimRecord._id },
      { $set: { action: 'delete', status: 'failure' } }
    );

    const report = await verifyAuditChain(AuditLog);
    expect(report.isValid).toBe(false);
    expect(report.recordId.toString()).toBe(victimRecord._id.toString());
    expect(report.reason).toMatch(/Hash mismatch|altered/i);

    // Revert tampering for subsequent test
    await AuditLog.updateOne(
      { _id: victimRecord._id },
      { $set: { action: victimRecord.action, status: victimRecord.status } }
    );
  });

  it('7. CRITICAL SECURITY: Detects deleted / missing audit records in database', async () => {
    // Delete record #4 in the chain
    const records = await AuditLog.find().sort({ timestamp: 1, _id: 1 });
    const targetToDelete = records[3];

    await AuditLog.deleteOne({ _id: targetToDelete._id });

    const report = await verifyAuditChain(AuditLog);
    expect(report.isValid).toBe(false);
    expect(report.reason).toMatch(/Broken previousHash linkage|deletion/i);
  });

  it('8. Non-admin user cannot access admin audit logs endpoint', async () => {
    const res = await request(app)
      .get('/api/admin/audit-logs')
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Forbidden/i);
  });

  it('9. Admin can view paginated audit logs with populated details', async () => {
    const res = await request(app)
      .get('/api/admin/audit-logs?page=1&limit=5')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.logs).toBeInstanceOf(Array);
    expect(res.body.pagination).toBeDefined();
    expect(res.body.pagination.total).toBeGreaterThanOrEqual(1);
  });

  it('10. Admin can run on-demand cryptographic verification via API', async () => {
    const res = await request(app)
      .get('/api/admin/audit-logs/verify')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.report).toBeDefined();
  });
});
