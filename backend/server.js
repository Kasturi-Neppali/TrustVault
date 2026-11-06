require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

const { apiLimiter } = require('./middleware/rateLimiter');
const { noSqlSanitizer } = require('./middleware/validate');
const errorHandler = require('./middleware/errorHandler');

const app = express();

// 1. Security Headers (Helmet)
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// 2. Cookie Parser for HttpOnly session tokens
app.use(cookieParser());

// 3. Strict Payload Limits to mitigate DoS
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 4. NoSQL Query Injection Sanitizer
app.use(noSqlSanitizer);

// 5. Configurable CORS Allowlisting
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
  : [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'https://trustvault-app-five.vercel.app'
    ];

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser agents (Supertest, curl) or allowlisted web origins
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy violation: Origin ${origin} not permitted.`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// 6. Global API Rate Limiter
app.use('/api', apiLimiter);

// 7. Route Mounting
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/documents', require('./routes/document.routes'));
app.use('/api/admin', require('./routes/admin.routes'));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'TrustVault Security Engine'
  });
});

// 8. 404 Route Fallback
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

// 9. Centralized Error Handler
app.use(errorHandler);

// Database Connection & Server Initialization
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/trustvault';

if (require.main === module) {
  mongoose.connect(MONGO_URI)
    .then(() => {
      console.log(' Connected to MongoDB (TrustVault)');
      app.listen(PORT, () => {
        console.log(` TrustVault Security Server running on port ${PORT}`);
      });
    })
    .catch(err => {
      console.error('❌ MongoDB Connection Error:', err);
      process.exit(1);
    });
}

module.exports = app;
