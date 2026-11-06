process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_key_for_jest_only';

const request = require('supertest');
const mongoose = require('mongoose');
const os = require('os');
const app = require('../server');

beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
        await mongoose.connect('mongodb://127.0.0.1:27017/trustvault_test?directConnection=true', {
            runtimeAdapters: { os }
        });
    }
    // Clear collections before testing
    await mongoose.connection.db.dropDatabase();
}, 30000);

afterAll(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.connection.close();
}, 30000);

describe('TrustVault Security & Isolation Tests', () => {
    let userAToken, userBToken;
    let userAId, userBId;
    let documentId;

    it('1. Should register User A and User B', async () => {
        const resA = await request(app).post('/api/auth/register').send({
            name: 'User A',
            email: 'usera@test.com',
            password: 'Password@1234'
        });
        userAId = resA.body.user.id;

        const resB = await request(app).post('/api/auth/register').send({
            name: 'User B',
            email: 'userb@test.com',
            password: 'Password@1234'
        });
        userBId = resB.body.user.id;

        expect(resA.statusCode).toEqual(201);
        expect(resB.statusCode).toEqual(201);
    });

    it('2. Should log in both users to get tokens', async () => {
        const resA = await request(app).post('/api/auth/login').send({
            email: 'usera@test.com',
            password: 'Password@1234'
        });
        userAToken = resA.body.token;

        const resB = await request(app).post('/api/auth/login').send({
            email: 'userb@test.com',
            password: 'Password@1234'
        });
        userBToken = resB.body.token;

        expect(userAToken).toBeDefined();
        expect(userBToken).toBeDefined();
    });

    it('3. User A should be able to upload a document', async () => {
        // Create a valid text file buffer
        const buffer = Buffer.from('Confidential Data for User A');
        
        const res = await request(app)
            .post('/api/documents/upload')
            .set('Authorization', `Bearer ${userAToken}`)
            .attach('document', buffer, 'secret.txt')
            .field('title', 'User A Secret')
            .field('category', 'Test');

        expect(res.statusCode).toEqual(201);
        documentId = res.body.documentId;
        expect(documentId).toBeDefined();
    });

    it('4. SECURITY: User B CANNOT download User A\'s document', async () => {
        const res = await request(app)
            .get(`/api/documents/${documentId}/download`)
            .set('Authorization', `Bearer ${userBToken}`);

        expect(res.statusCode).toEqual(403);
        expect(res.body.error).toContain('Forbidden');
    });

    it('5. User A grants read access to User B', async () => {
        const res = await request(app)
            .post(`/api/documents/${documentId}/grant`)
            .set('Authorization', `Bearer ${userAToken}`)
            .send({ targetUserId: userBId, accessLevel: 'read' });

        expect(res.statusCode).toEqual(200);
    });

    it('6. User B CAN download the document now', async () => {
        const res = await request(app)
            .get(`/api/documents/${documentId}/download`)
            .set('Authorization', `Bearer ${userBToken}`);

        expect(res.statusCode).toEqual(200);
    });
});
