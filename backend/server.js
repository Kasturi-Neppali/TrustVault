
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

// Global Middleware
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:3000'], // We will restrict this to your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

// Database Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB (TrustVault)'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Route Placeholders (We will create these files in the next steps)
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/documents', require('./routes/document.routes'));
app.use('/api/admin', require('./routes/admin.routes'));

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 TrustVault Security Server running on port ${PORT}`);
});