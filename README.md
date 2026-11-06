# TrustVault — Enterprise Confidential Document Storage & Tamper-Evident Audit Platform

TrustVault is a production-quality, security-hardened MERN application designed for confidential document storage, controlled document sharing, and tamper-evident audit logging. Engineered to withstand malicious users, unauthorized access attempts, privilege escalation, IDOR attacks, and common OWASP vulnerabilities.

---

## Table of Contents
1. [Architectural Overview](#architectural-overview)
2. [Core Security Features](#core-security-features)
   - [Authentication & Session Security](#authentication--session-security)
   - [Authorization & Granular RBAC](#authorization--granular-rbac)
   - [Secure File Storage & Lifecycle](#secure-file-storage--lifecycle)
   - [Tamper-Evident Cryptographic Audit Logging](#tamper-evident-cryptographic-audit-logging)
   - [Defensive Middleware & Injection Protection](#defensive-middleware--injection-protection)
3. [Project Directory Structure](#project-directory-structure)
4. [Environment Configuration](#environment-configuration)
5. [Local Development Setup](#local-development-setup)
6. [Administrator Provisioning](#administrator-provisioning)
7. [Cryptographic Audit Verification Tool](#cryptographic-audit-verification-tool)
8. [Automated Test Suite](#automated-test-suite)
9. [Production Deployment Hardening](#production-deployment-hardening)
10. [Secret Rotation & Repository Exposure Guide](#secret-rotation--repository-exposure-guide)
11. [Academic Demonstration Script](#academic-demonstration-script)

---

## Architectural Overview

TrustVault follows a zero-trust, defense-in-depth architecture across all tiers:
- **Backend**: Express.js REST API with Helmet security headers, NoSQL query sanitization, IP rate limiting, and centralized error redaction.
- **Database**: MongoDB with strict Mongoose schemas, compound unique indexes preventing duplicate permissions, and chronological indexing.
- **Frontend**: React client with Tailwind CSS, Lucide icons, backend-verified session restoration via `/api/auth/me`, and live cryptographic verification interfaces.
- **Storage Engine**: Private filesystem storage decoupled from web server public paths, utilizing UUID-based identifiers and magic-byte inspection.
- **Audit Engine**: Sequential SHA-256 hash-chained ledger ensuring forensic integrity and detection of altered, inserted, or deleted logs.

```
       +-------------------------------------------------------+
       |                  React Frontend (UI)                  |
       |  (Session verification via /api/auth/me, cookie/JWT)  |
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |              Security Middleware Layer                |
       |  (Helmet, CORS Allowlist, Rate Limiting, NoSQL Strip) |
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |             Authentication & RBAC Engine              |
       | (Real-time DB permission check, Immediate Revocation) |
       +-------------------------------------------------------+
            /                                        \
           v                                          v
+-----------------------+              +-------------------------------+
|  Private File Storage |              |   MongoDB Cluster (Datastore) |
|  - Magic-Byte Check   |              |   - Users (Bcrypt cost 12)    |
|  - UUID File Mapping  |              |   - Documents & Permissions   |
|  - Traversal Boundary |              |   - Tamper-Evident AuditLog   |
+-----------------------+              +-------------------------------+
```

---

## Core Security Features

### Authentication & Session Security
- **Safe Public Registration**: Public registration assigns the safe default role `'user'`. Any client-supplied privilege fields (`role: "admin"`, `isAdmin: true`, `permissions: ["admin"]`) are strictly discarded.
- **Admin Gated Provisioning**: Administrator accounts can only be provisioned via the secure bootstrap utility (`scripts/seedAdmin.js`).
- **Credential Protection**: Passwords require at least 8 characters, with uppercase, lowercase, numbers, and special symbols, hashed using `bcrypt` (12 salt rounds).
- **Brute-Force & Credential Stuffing Defense**: Authentication routes are protected by rate limiters (10 attempts per 15 minutes). Authentication failures return uniform generic messages (`Invalid email or password`) to prevent email enumeration.
- **Session Management**: Dual support for secure `HttpOnly`, `SameSite=Lax` cookies and `Authorization: Bearer` tokens. Client applications do not rely on untrusted `localStorage` state for access control.
- **Active Session Endpoints**: Full lifecycle support including `POST /api/auth/login`, `POST /api/auth/logout` (cookie invalidation), and `GET /api/auth/me` (real-time server verification).

### Authorization & Granular RBAC
- **System Roles vs Document Permissions**: Distinct separation between global system roles (`admin`, `user`) and document-level permissions (`owner`, `editor`, `viewer`).
- **Real-Time Database Verification**: Document permissions are checked directly against the database on every request. Mutable permissions are never stored inside static JWTs.
- **Immediate Revocation**: Revoking a permission in the database immediately blocks access on the very next download or update attempt.
- **IDOR Defense**: All document IDs are validated and checked for explicit ownership or granted permissions. Unauthorized requests return HTTP 403 Forbidden and generate an immutable `access_denied` audit entry.
- **Privilege Containment**: Viewers and Editors are strictly prohibited from sharing or delegating permissions to other users. Only the Document Owner can grant or revoke access.

### Secure File Storage & Lifecycle
- **Magic-Byte Signature Inspection**: Files are inspected at the binary buffer level to verify authentic magic numbers before accepting them:
  - PDF: `%PDF-` (`0x25 0x50 0x44 0x46`)
  - PNG: `\x89PNG\r\n\x1a\n` (`0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A`)
  - JPEG: `\xFF\xD8\xFF`
  - TXT: Validated text without null bytes or binary executable headers (`MZ`, `ELF`).
- **In-Memory Validation**: Multer uses memory storage during inspection; unverified or malicious files are never written to disk.
- **Path Traversal Defense**: Files on disk are named using random UUIDs (`<uuid>.<sanitizedExt>`). The user's original filename is stored strictly as metadata. On retrieval, paths are verified to ensure they resolve within the configured `STORAGE_DIR`.
- **Download Headers**: Safe streaming with `Content-Disposition: attachment`, explicit MIME type headers, and `X-Content-Type-Options: nosniff`.

### Tamper-Evident Cryptographic Audit Logging
- **SHA-256 Hash Chaining**: Every audit entry computes a cryptographic hash based on:
  $$\text{currentHash} = \text{SHA-256}(\text{canonicalPayload} \parallel \text{previousHash})$$
- **Deterministic Canonicalization**: Event fields (`action`, `actorEmail`, `actorId`, `documentId`, `eventId`, `ipAddress`, `metadata`, `status`, `targetUserId`, `timestamp`) are normalized and serialized with alphabetically sorted keys.
- **Genesis State**: The initial log entry anchors to a genesis hash of 64 zeros (`0000...0000`).
- **Concurrency Serialization**: An in-memory promise mutex sequences concurrent audit log writes within the Node.js server, preventing race conditions and branched chains.
- **Automated Verification**: Standalone script (`scripts/verifyAuditChain.js`) and admin API endpoint (`/api/admin/audit-logs/verify`) verify the unbroken hash chain and detect any altered, deleted, or inserted records.
- **Credential Redaction**: Passwords, JWTs, authorization headers, and raw file buffers are sanitized before entering the audit stream.

### Defensive Middleware & Injection Protection
- **Helmet**: Sets secure HTTP response headers (Content-Security-Policy, X-Frame-Options, Strict-Transport-Security).
- **CORS Allowlisting**: Strictly permits requests from allowlisted origins with credentials.
- **NoSQL Injection Sanitizer**: Recursively strips keys containing MongoDB operators (`$`) or dots (`.`) from request bodies, queries, and parameters.
- **Payload Limits**: JSON bodies capped at 1MB, file uploads capped at 5MB.
- **Centralized Error Handler**: Redacts stack traces and database internal error messages in production.

---

## Project Directory Structure

```
TrustVault/
├── backend/
│   ├── middleware/
│   │   ├── auth.js            # JWT auth & real-time document RBAC
│   │   ├── errorHandler.js    # Production-safe centralized error handler
│   │   ├── rateLimiter.js     # Express rate limiters for auth and API
│   │   └── validate.js        # NoSQL injection cleaner and input validators
│   ├── models/
│   │   └── index.js           # Mongoose schemas: User, Document, Permission, AuditLog
│   ├── routes/
│   │   ├── admin.routes.js    # Admin audit trail and verification routes
│   │   ├── auth.routes.js     # Register, login, logout, /me
│   │   └── document.routes.js # Upload, download, patch, delete, share, revoke
│   ├── scripts/
│   │   ├── seedAdmin.js       # Admin bootstrap provisioner
│   │   └── verifyAuditChain.js# Standalone cryptographic audit verification
│   ├── storage/               # Private document storage (excluded from git)
│   ├── tests/
│   │   ├── auth.test.js       # 13 automated authentication tests
│   │   ├── document.test.js   # 12 automated document lifecycle tests
│   │   ├── permission.test.js # 13 automated RBAC & revocation tests
│   │   ├── audit.test.js      # 10 automated hash-chain integrity tests
│   │   └── security.test.js   # 6 isolation and download authorization tests
│   ├── utils/
│   │   ├── audit.js           # Serialized audit logger with credential redaction
│   │   ├── auditIntegrity.js  # Canonicalization & hash chain verification engine
│   │   ├── fileValidation.js  # Magic-byte inspector & path traversal validator
│   │   ├── password.js        # Bcrypt utilities & password complexity policy
│   │   └── token.js           # JWT signing, verification, and HttpOnly cookies
│   └── server.js              # Express app with Helmet, CORS, and middleware
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AuditTrail.js  # Admin audit view with live cryptographic verification
│   │   │   ├── Dashboard.js   # Document vault, upload, download, share, revoke
│   │   │   └── Login.js       # Sign in & registration with password validator
│   │   ├── services/
│   │   │   └── api.js         # Axios client with credentials & error interceptors
│   │   ├── App.js             # Verified session restoration & navigation
│   │   └── App.test.js        # Frontend UI rendering test
│   └── package.json
├── scripts/
│   ├── seedAdmin.js           # Root CLI wrapper for admin provisioner
│   └── verifyAuditChain.js    # Root CLI wrapper for audit verification tool
├── .env.example               # Complete environment variable documentation
├── .gitignore                 # Exclusion rules for secrets, storage, and build artifacts
├── CHANGELOG.md               # Detailed history of changes
├── IMPLEMENTATION_PLAN.md     # Prioritized engineering roadmap
├── SECURITY_REVIEW.md         # Complete vulnerability assessment (SEC-01 to SEC-17)
├── THREATS.md                 # Formal threat model (19 attack scenarios)
└── package.json               # Root scripts and dependencies
```

---

## Environment Configuration

Create a `.env` file in the project root (and in `backend/.env` for backend standalone runs):

```env
NODE_ENV=development
PORT=5000
MONGO_URI=mongodb://localhost:27017/trustvault
JWT_SECRET=replace_with_a_super_strong_cryptographic_jwt_secret_key_minimum_64_characters
JWT_EXPIRES_IN=2h
STORAGE_DIR=./backend/storage
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,https://trustvault-app-five.vercel.app
ADMIN_NAME=TrustVault Administrator
ADMIN_EMAIL=admin@trustvault.com
ADMIN_PASSWORD=TrustVault@Admin2026!
```

---

## Local Development Setup

### Prerequisites
- Node.js v18+ (tested on Node v24)
- Local MongoDB running on port 27017

### 1. Install Dependencies
```bash
# Install root and backend dependencies
npm install

# Install frontend dependencies
npm --prefix frontend install
```

### 2. Seed Administrator Account
```bash
npm run seed-admin
```

### 3. Run Backend Server
```bash
npm start
# Server starts on http://localhost:5000
```

### 4. Run Frontend Client
In a separate terminal:
```bash
cd frontend
npm start
# Client launches on http://localhost:3000
```

---

## Administrator Provisioning

Administrator accounts cannot be created through the public registration API. Use the secure provisioning script:

```bash
npm run seed-admin
```

This reads `ADMIN_NAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` from `.env`, hashes the credentials using bcrypt, persists the user with role `'admin'`, and writes an initial event to the audit ledger.

---

## Cryptographic Audit Verification Tool

To independently verify the integrity of the audit ledger from the command line:

```bash
npm run verify-audit
```

**Expected output on an intact ledger:**
```
=====================================================
   TRUSTVAULT CRYPTOGRAPHIC AUDIT VERIFICATION TOOL   
=====================================================

Connecting to database: mongodb://localhost:27017/trustvault
Connected to MongoDB.
Analyzing audit log records...

[PASS] AUDIT INTEGRITY STATUS: VALID
Total Audit Records Inspected: 14
Verified Continuous Records : 14
Latest Cryptographic Hash  : a4f8e...

All audit events maintain an unbroken SHA-256 hash chain.
No deletion, insertion, or in-place tampering detected.
```

If any database administrator or attacker alters a single character in an audit record or removes a record from MongoDB, the tool detects the corruption, identifies the exact tampered index, displays the expected vs actual hash, and exits with code 1.

---

## Automated Test Suite

TrustVault includes 54 automated test cases covering authentication, authorization, document lifecycle, file signatures, and cryptographic audit integrity.

### Run All Backend Tests
```bash
npm test
```

### Individual Test Suites
```bash
# Authentication & session tests (13 tests)
npx jest backend/tests/auth.test.js --forceExit

# Document lifecycle & magic byte tests (12 tests)
npx jest backend/tests/document.test.js --forceExit

# Granular RBAC, IDOR & immediate revocation tests (13 tests)
npx jest backend/tests/permission.test.js --forceExit

# Cryptographic hash-chain & tamper detection tests (10 tests)
npx jest backend/tests/audit.test.js --forceExit

# Isolation & download security tests (6 tests)
npx jest backend/tests/security.test.js --forceExit
```

### Run Frontend Tests
```bash
npm --prefix frontend test -- --watchAll=false
```

---

## Production Deployment Hardening

1. **Enforce Production Environment**: Set `NODE_ENV=production`.
2. **Cryptographic Secrets**: Generate a 64+ character random string for `JWT_SECRET` (`openssl rand -base64 48`).
3. **Database Authentication**: Use a dedicated non-root MongoDB user with least-privilege credentials and TLS encryption (`mongodb+srv://...`).
4. **Isolated Storage**: Mount `STORAGE_DIR` onto an encrypted EBS/persistent volume outside the application code directory.
5. **Reverse Proxy & TLS**: Terminate HTTPS at an upstream reverse proxy (Nginx or Cloudflare) with `Strict-Transport-Security` headers enabled.
6. **CORS Allowlist**: Set `ALLOWED_ORIGINS` strictly to your production domain (e.g. `https://trustvault.yourdomain.com`).

---

## Secret Rotation & Repository Exposure Guide

### Historical File Exposure Notice
During the initial project setup, test files containing user certificates were committed to the repository history under `backend/storage/`. 

To remediate this:
1. **Repository Untracking**: `git rm --cached` was executed on all files under `backend/storage/` while preserving physical files on disk.
2. **Gitignore Hardening**: Added rules to `.gitignore`:
   ```gitignore
   backend/storage/*
   !backend/storage/.gitkeep
   storage/*
   !storage/.gitkeep
   .env
   .env.*
   ```
3. **History Purge (Production Recommendation)**: If deploying to a public repository, use `git filter-repo` or BFG Repo-Cleaner to completely rewrite history and erase any previous blob references:
   ```bash
   git filter-repo --path backend/storage/ --invert-paths
   ```
4. **Secret Rotation**: Rotate all JWT secrets and database credentials across all staging and production environments.

---

## Academic Demonstration Script

Follow this script to demonstrate TrustVault's security features:

1. **Privilege Escalation Defense**:
   - Register a user through the UI or via curl with `role: "admin"`.
   - Observe that the backend ignores the role parameter and assigns `'user'`.
2. **Owner Document Upload & Magic-Byte Verification**:
   - Log in as `alice@example.com`.
   - Upload a genuine PDF document.
   - Attempt to upload an `.exe` file renamed to `.pdf` — verify that the backend rejects it with HTTP 400.
3. **IDOR Prevention**:
   - Copy Alice's document ID.
   - Log in as `bob@example.com` in an incognito window.
   - Attempt to download Alice's document using the ID — observe HTTP 403 Forbidden.
   - Confirm that an `access_denied` entry was written to the audit log.
4. **Controlled Sharing**:
   - Alice shares the document with `bob@example.com` as Viewer.
   - Bob refreshes his dashboard and downloads the file successfully.
   - Bob attempts to edit or share the document — observe that access is denied.
5. **Immediate Revocation**:
   - Alice clicks "Access" and revokes Bob's permission.
   - Bob immediately attempts to download the document again — access is instantly blocked (HTTP 403).
6. **Tamper-Evident Audit Ledger**:
   - Log in as `admin@trustvault.com` (`TrustVault@Admin2026!`).
   - Navigate to the "Audit Ledger" tab.
   - Click "Verify Hash Chain Integrity" — observe the green verified badge.
   - (Optional) Modify an action in MongoDB using Compass — re-run verification and observe the immediate tamper alert detailing the corrupted record.
