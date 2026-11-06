process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_for_trustvault_doc_tests_isolated';

const request = require('supertest');
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const os = require('os');
const app = require('../server');
const { User, Document, Permission, AuditLog } = require('../models');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/trustvault_test_docs?directConnection=true';

let ownerToken, nonOwnerToken;
let ownerId, nonOwnerId;
let uploadedDocId;

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

  // 1. Register Owner
  const ownerRes = await request(app).post('/api/auth/register').send({
    name: 'Doc Owner',
    email: 'owner@example.com',
    password: 'Password@1234'
  });
  ownerId = ownerRes.body.user.id;

  const ownerLogin = await request(app).post('/api/auth/login').send({
    email: 'owner@example.com',
    password: 'Password@1234'
  });
  ownerToken = ownerLogin.body.token;

  // 2. Register Non-Owner
  const nonOwnerRes = await request(app).post('/api/auth/register').send({
    name: 'Other User',
    email: 'other@example.com',
    password: 'Password@1234'
  });
  nonOwnerId = nonOwnerRes.body.user.id;

  const nonOwnerLogin = await request(app).post('/api/auth/login').send({
    email: 'other@example.com',
    password: 'Password@1234'
  });
  nonOwnerToken = nonOwnerLogin.body.token;
}, 30000);

afterAll(async () => {
  await User.deleteMany({});
  await Document.deleteMany({});
  await Permission.deleteMany({});
  await AuditLog.deleteMany({});
  await mongoose.connection.close();
}, 30000);

describe('TrustVault Secure Document Lifecycle Suite', () => {
  it('1. Uploads valid PDF file with genuine magic bytes', async () => {
    // Valid PDF header: %PDF-1.4
    const validPdfBuffer = Buffer.from('%PDF-1.4\n%âãÏÓ\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF');

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .attach('document', validPdfBuffer, 'financial_report.pdf')
      .field('title', 'Q3 Financial Audit')
      .field('category', 'Finance');

    expect(res.status).toBe(201);
    expect(res.body.documentId).toBeDefined();
    expect(res.body.document.title).toBe('Q3 Financial Audit');
    uploadedDocId = res.body.documentId;

    // Verify storage filename is UUID and not originalFilename
    const docInDb = await Document.findById(uploadedDocId);
    expect(docInDb).toBeTruthy();
    expect(docInDb.storagePath).toMatch(/^[0-9a-f-]+\.pdf$/i);
    expect(docInDb.originalFilename).toBe('financial_report.pdf');
  });

  it('2. Uploads valid PNG image with genuine magic bytes', async () => {
    // Valid PNG header: 89 50 4E 47 0D 0A 1A 0A
    const validPngBuffer = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d]);

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .attach('document', validPngBuffer, 'diagram.png')
      .field('title', 'Architecture Diagram');

    expect(res.status).toBe(201);
    expect(res.body.document.mimeType).toBe('image/png');
  });

  it('3. Uploads valid TXT text document', async () => {
    const validTxtBuffer = Buffer.from('Confidential strategic plan for 2027.\nAuthorized access only.');

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .attach('document', validTxtBuffer, 'strategy.txt')
      .field('title', 'Strategy Document');

    expect(res.status).toBe(201);
  });

  it('4. CRITICAL SECURITY: Blocks executable disguised as PDF (MIME spoofing prevention)', async () => {
    // Windows PE executable header: 'MZ' (0x4D 0x5A) disguised with PDF filename and application/pdf MIME
    const fakePdfBuffer = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff');

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .attach('document', fakePdfBuffer, 'trojan.pdf');

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/magic byte mismatch|signature/i);
  });

  it('5. Blocks disallowed file extension (.exe)', async () => {
    const exeBuffer = Buffer.from('MZThisIsAnExecutableFile');

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .attach('document', exeBuffer, 'malware.exe');

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Invalid file type or extension/i);
  });

  it('6. Blocks oversized file exceeding 5MB limit', async () => {
    // 6MB buffer
    const largeBuffer = Buffer.alloc(6 * 1024 * 1024, 0x20);

    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', `Bearer ${ownerToken}`)
      .attach('document', largeBuffer, 'huge.txt');

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/exceeds maximum allowed limit of 5MB/i);
  });

  it('7. Fetches owned documents list', async () => {
    const res = await request(app)
      .get('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(res.status).toBe(200);
    expect(res.body.owned).toBeInstanceOf(Array);
    expect(res.body.owned.length).toBeGreaterThanOrEqual(1);
    expect(res.body.owned.some(d => d._id === uploadedDocId)).toBe(true);
  });

  it('8. Downloads document securely with safe headers', async () => {
    const res = await request(app)
      .get(`/api/documents/${uploadedDocId}/download`)
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['content-disposition']).toMatch(/attachment; filename=/i);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.body).toBeInstanceOf(Buffer);
  });

  it('9. Updates document metadata (PATCH)', async () => {
    const res = await request(app)
      .patch(`/api/documents/${uploadedDocId}`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        title: 'Updated Financial Audit Title',
        category: 'Confidential Finance'
      });

    expect(res.status).toBe(200);
    expect(res.body.document.title).toBe('Updated Financial Audit Title');
    expect(res.body.document.category).toBe('Confidential Finance');
  });

  it('10. Non-owner cannot update document metadata without edit permission', async () => {
    const res = await request(app)
      .patch(`/api/documents/${uploadedDocId}`)
      .set('Authorization', `Bearer ${nonOwnerToken}`)
      .send({ title: 'Hacked Title' });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Forbidden/i);
  });

  it('11. Non-owner cannot delete document', async () => {
    const res = await request(app)
      .delete(`/api/documents/${uploadedDocId}`)
      .set('Authorization', `Bearer ${nonOwnerToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/Forbidden/i);
  });

  it('12. Owner successfully deletes document and cleans disk', async () => {
    const docBefore = await Document.findById(uploadedDocId);
    const storageFilePath = path.join(__dirname, '..', 'storage', docBefore.storagePath);

    const res = await request(app)
      .delete(`/api/documents/${uploadedDocId}`)
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/deleted permanently/i);

    // Verify removed from database
    const docAfter = await Document.findById(uploadedDocId);
    expect(docAfter).toBeNull();

    // Verify physical file removed
    expect(fs.existsSync(storageFilePath)).toBe(false);
  });
});

