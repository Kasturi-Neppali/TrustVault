
const request = require('supertest');
const mongoose = require('mongoose');
const express = require('express');
const authRoutes = require('../routes/auth.routes');
const documentRoutes = require('../routes/document.routes');

process.env.JWT_SECRET = 'test_secret_key_for_jest_only';

// Setup a mock app for testing
const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);

// We will use a separate test database
beforeAll(async () => {
    await mongoose.connect('mongodb://localhost:27017/trustvault_test');
    // Clear collections before testing
    await mongoose.connection.db.dropDatabase();
});

afterAll(async () => {
    await mongoose.connection.close();
});

describe('TrustVault Security & Isolation Tests', () => {
    let userAToken, userBToken;
    let userAId, userBId;
    let documentId;

    it('1. Should register User A and User B', async () => {
        const resA = await request(app).post('/api/auth/register').send({
            email: 'usera@test.com', password: 'password123'
        });
        userAId = resA.body.userId;

        const resB = await request(app).post('/api/auth/register').send({
            email: 'userb@test.com', password: 'password123'
        });
        userBId = resB.body.userId;

        expect(resA.statusCode).toEqual(201);
        expect(resB.statusCode).toEqual(201);
    });

    it('2. Should log in both users to get tokens', async () => {
        const resA = await request(app).post('/api/auth/login').send({
            email: 'usera@test.com', password: 'password123'
        });
        userAToken = resA.body.token;

        const resB = await request(app).post('/api/auth/login').send({
            email: 'userb@test.com', password: 'password123'
        });
        userBToken = resB.body.token;

        expect(userAToken).toBeDefined();
        expect(userBToken).toBeDefined();
    });

    it('3. User A should be able to upload a document', async () => {
        // Create a dummy file buffer
        const buffer = Buffer.from('Confidential Data');
        
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

        // This is the most critical test. If the judges remove the DB check 
        // in your middleware, this test will fail because it will return 200 instead of 403.
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