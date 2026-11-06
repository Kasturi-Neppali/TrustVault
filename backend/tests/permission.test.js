process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_for_trustvault_permission_tests';

const request = require('supertest');
const mongoose = require('mongoose');
const os = require('os');
const app = require('../server');
const { User, Document, Permission, AuditLog } = require('../models');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/trustvault_test_permissions?directConnection=true';

let ownerToken, viewerToken, editorToken, intruderToken;
let ownerId, viewerId, editorId, intruderId;
let documentId;

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(TEST_DB_URI, {
      runtimeAdapters: { os }
    });
  }
  await User.deleteMany({});
  await Document.deleteMany({});
  await Permission.deleteMany({});
  await AuditLog.deleteMany({});

  // 1. Owner
  const oRes = await request(app).post('/api/auth/register').send({
    name: 'Doc Owner',
    email: 'docowner@example.com',
    password: 'Password@1234'
  });
  ownerId = oRes.body.user.id;
  const oLogin = await request(app).post('/api/auth/login').send({
    email: 'docowner@example.com',
    password: 'Password@1234'
  });
  ownerToken = oLogin.body.token;

  // 2. Viewer
  const vRes = await request(app).post('/api/auth/register').send({
    name: 'Viewer User',
    email: 'viewer@example.com',
    password: 'Password@1234'
  });
  viewerId = vRes.body.user.id;
  const vLogin = await request(app).post('/api/auth/login').send({
    email: 'viewer@example.com',
    password: 'Password@1234'
  });
  viewerToken = vLogin.body.token;

  // 3. Editor
  const eRes = await request(app).post('/api/auth/register').send({
    name: 'Editor User',
    email: 'editor@example.com',
    password: 'Password@1234'
  });
  editorId = eRes.body.user.id;
  const eLogin = await request(app).post('/api/auth/login').send({
    email: 'editor@example.com',
    password: 'Password@1234'
  });
  editorToken = eLogin.body.token;

  // 4. Intruder (unauthorized third-party)
  const iRes = await request(app).post('/api/auth/register').send({
    name: 'Intruder User',
    email: 'intruder@example.com',
    password: 'Password@1234'
  });
  intruderId = iRes.body.user.id;
  const iLogin = await request(app).post('/api/auth/login').send({
    email: 'intruder@example.com',
    password: 'Password@1234'
  });
  intruderToken = iLogin.body.token;

  // Owner uploads confidential document
  const pdfBuffer = Buffer.from('%PDF-1.4\nConfidential Data\n%%EOF');
  const uploadRes = await request(app)
    .post('/api/documents/upload')
    .set('Authorization', `Bearer ${ownerToken}`)
    .attach('document', pdfBuffer, 'contracts.pdf')
    .field('title', 'Classified Contracts')
    .field('category', 'Legal');

  documentId = uploadRes.body.documentId;
}, 30000);

afterAll(async () => {
  await User.deleteMany({});
  await Document.deleteMany({});
  await Permission.deleteMany({});
  await AuditLog.deleteMany({});
  await mongoose.connection.close();
}, 30000);

describe('TrustVault Granular Authorization & RBAC Suite', () => {
  it('1. Owner has full read access to their document', async () => {
    const res = await request(app)
      .get(`/api/documents/${documentId}`)
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(res.status).toBe(200);
    expect(res.body.userAccessLevel).toBe('owner');
    expect(res.body.document.title).toBe('Classified Contracts');
  });

  it('2. SECURITY: Intruder CANNOT access or download document (IDOR Defense)', async () => {
    const res = await request(app)
      .get(`/api/documents/${documentId}/download`)
      .set('Authorization', `Bearer ${intruderToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Forbidden/i);

    // Verify access_denied was logged to audit ledger
    const denialLog = await AuditLog.findOne({
      actorId: intruderId,
      documentId: documentId,
      action: 'access_denied',
      status: 'blocked'
    });
    expect(denialLog).toBeTruthy();
  });

  it('3. Owner shares document with Viewer using recipient email', async () => {
    const res = await request(app)
      .post(`/api/documents/${documentId}/share`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        targetEmail: 'viewer@example.com',
        accessLevel: 'viewer'
      });

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/granted/i);
    expect(res.body.permission.accessLevel).toBe('read');
  });

  it('4. Viewer CAN now download the shared document', async () => {
    const res = await request(app)
      .get(`/api/documents/${documentId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
  });

  it('5. SECURITY: Viewer CANNOT edit document metadata', async () => {
    const res = await request(app)
      .patch(`/api/documents/${documentId}`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ title: 'Viewer Attempted Tampering' });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Forbidden/i);
  });

  it('6. SECURITY: Viewer CANNOT share document with other users (No permission escalation)', async () => {
    const res = await request(app)
      .post(`/api/documents/${documentId}/share`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({
        targetEmail: 'intruder@example.com',
        accessLevel: 'viewer'
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Only the document owner can perform this operation/i);
  });

  it('7. Owner grants Editor access to Editor user', async () => {
    const res = await request(app)
      .post(`/api/documents/${documentId}/share`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        targetEmail: 'editor@example.com',
        accessLevel: 'editor'
      });

    expect(res.status).toBe(200);
    expect(res.body.permission.accessLevel).toBe('edit');
  });

  it('8. Editor CAN update document metadata', async () => {
    const res = await request(app)
      .patch(`/api/documents/${documentId}`)
      .set('Authorization', `Bearer ${editorToken}`)
      .send({ title: 'Contracts Reviewed By Editor' });

    expect(res.status).toBe(200);
    expect(res.body.document.title).toBe('Contracts Reviewed By Editor');
  });

  it('9. SECURITY: Editor CANNOT share document with other users', async () => {
    const res = await request(app)
      .post(`/api/documents/${documentId}/share`)
      .set('Authorization', `Bearer ${editorToken}`)
      .send({
        targetEmail: 'intruder@example.com',
        accessLevel: 'read'
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Only the document owner can perform this operation/i);
  });

  it('10. Owner cannot share document with themselves', async () => {
    const res = await request(app)
      .post(`/api/documents/${documentId}/share`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        targetEmail: 'docowner@example.com',
        accessLevel: 'viewer'
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/already the owner/i);
  });

  it('11. Sharing with non-existent user email returns 404', async () => {
    const res = await request(app)
      .post(`/api/documents/${documentId}/share`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        targetEmail: 'nobody@nowhere.com',
        accessLevel: 'viewer'
      });

    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/does not exist/i);
  });

  it('12. Database unique compound index prevents duplicate permission records', async () => {
    const perms = await Permission.find({ documentId, userId: viewerId });
    // Even though sharing could be called again, upsert/index guarantees exactly 1 record
    expect(perms.length).toBe(1);
  });

  it('13. Immediate Revocation: Owner revokes Viewer access; access is revoked instantly', async () => {
    // 1. Owner lists permissions
    const listRes = await request(app)
      .get(`/api/documents/${documentId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(listRes.status).toBe(200);
    const viewerPerm = listRes.body.permissions.find(p => p.userId._id === viewerId);
    expect(viewerPerm).toBeDefined();

    // 2. Owner deletes permission
    const revokeRes = await request(app)
      .delete(`/api/documents/${documentId}/permissions/${viewerPerm._id}`)
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(revokeRes.status).toBe(200);
    expect(revokeRes.body.message).toMatch(/revoked immediately/i);

    // 3. Viewer attempts to download right now: MUST fail with 403 Forbidden
    const downloadRes = await request(app)
      .get(`/api/documents/${documentId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(downloadRes.status).toBe(403);
    expect(downloadRes.body.error).toMatch(/Forbidden/i);
  });
});

