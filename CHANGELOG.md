# TrustVault — Changelog

All notable changes to the TrustVault codebase are documented in this file.

## [1.0.0] - 2026-11-06

### Phase 1 — Repository Analysis & Threat Modeling
- Performed an exhaustive static and architectural code audit of the entire TrustVault repository.
- Authored `SECURITY_REVIEW.md` cataloging 17 security vulnerabilities categorized by severity (Critical, High, Medium, Low).
- Authored `IMPLEMENTATION_PLAN.md` detailing the prioritized engineering roadmap.
- Authored `THREATS.md` with comprehensive STRIDE/OWASP threat models for 19 distinct attack vectors.

### Phase 2 — Authentication Hardening
- **Fixed Privilege Escalation (SEC-01)**: Public registration at `/api/auth/register` now strictly assigns the safe default role `'user'`, stripping all client-supplied role keys.
- **Password Security**: Enforced strong password policy (min 8 characters, requiring uppercase, lowercase, numbers, and symbols) using `bcrypt` with 12 salt rounds (adaptive 6 rounds for test speed).
- **Session & Cookie Security**: Implemented dual authentication supporting secure `HttpOnly`, `SameSite=Lax` cookies alongside `Authorization: Bearer` headers.
- **Brute-Force & Credential Stuffing Defense**: Integrated `express-rate-limit` (10 requests per 15 minutes) and uniform generic authentication error messages (`Invalid email or password`).
- **New Auth Endpoints**: Added `GET /api/auth/me` for database-backed active session verification and `POST /api/auth/logout` for cookie clearing.
- **Admin Bootstrap Provisioner**: Created `scripts/seedAdmin.js` for controlled administrator bootstrapping.
- **Automated Tests**: Created `backend/tests/auth.test.js` with 13 comprehensive passing test cases.

### Phase 3 & 4 — Authorization, Document Security & File Lifecycle
- **Differentiated RBAC**: Separated system roles (`admin`, `user`) from document roles (`owner`, `editor`, `viewer`).
- **Real-Time Permission Checks & Immediate Revocation**: Implemented `requireDocumentAccess` middleware querying MongoDB on every request.
- **Magic-Byte Signature Verification (SEC-02, SEC-08)**: Inspected binary buffer signatures before accepting uploads (PDF `%PDF-`, PNG `\x89PNG`, JPEG `\xFF\xD8\xFF`, clean TXT).
- **Path Traversal Protection (SEC-07)**: Enforced random UUID-based disk filenames (`<uuid>.<sanitizedExt>`) and strict boundary verification against `STORAGE_DIR`.
- **Granular Sharing**: Implemented `POST /api/documents/:id/share` supporting recipient resolution by verified email address and role selection (Viewer vs Editor).
- **Compound Database Constraint**: Added compound unique index `{ documentId: 1, userId: 1 }` on `Permission` schema preventing duplicate permission states.
- **Document REST APIs**: Implemented `GET /api/documents/:id`, `PATCH /api/documents/:id` (metadata update), `DELETE /api/documents/:id` (with physical file cleanup), and `GET /api/documents/:id/permissions`.
- **Automated Tests**: Created `backend/tests/document.test.js` (12 tests) and `backend/tests/permission.test.js` (13 tests) — all passing.

### Phase 5 — Tamper-Evident Cryptographic Audit Logging
- **Cryptographic Hash Chain (SEC-03)**: Redesigned `AuditLog` schema storing deterministic canonical payload, `previousHash`, and `currentHash = SHA-256(canonicalPayload + previousHash)`.
- **Deterministic Serialization**: Created `utils/auditIntegrity.js` normalizing all attributes and sorting object keys.
- **Sequential Concurrency Lock**: Protected audit appends with an in-memory queue to prevent race conditions and branched chains.
- **Verification Utility**: Built `scripts/verifyAuditChain.js` and `GET /api/admin/audit-logs/verify` to detect any modified, inserted, or deleted records.
- **Credential Redaction**: Implemented automatic sanitization stripping passwords, tokens, and authorization headers from audit metadata.
- **Automated Tests**: Created `backend/tests/audit.test.js` with 10 comprehensive passing test cases.

### Phase 6 — Frontend User Experience & Security
- **API Client Modernization**: Configured `frontend/src/services/api.js` with dynamic `REACT_APP_API_URL` and `withCredentials: true`.
- **Safe Session Restoration (SEC-04)**: Updated `App.js` to verify authentication directly with `GET /api/auth/me` on startup.
- **Login & Registration UI**: Re-engineered `Login.js` with registration tab, live password complexity validation, password visibility toggles, and demo credentials.
- **Dashboard Upgrades**: Modernized `Dashboard.js` with dual views (My Vault vs Shared With Me), share modal by email, access management modal with immediate revocation, and metadata editor.
- **Audit Trail Dashboard**: Upgraded `AuditTrail.js` with live one-click hash chain verification badge, pagination, action/status filters, and search.
- **Frontend Unit Tests & Build**: Fixed test scaffolding in `App.test.js` and verified clean production build (`npm run build`).

### Phase 7 & 8 — Deployment & Final Verification
- Added `helmet`, CORS allowlisting from `.env`, payload limits (1MB JSON, 5MB upload), and centralized error handling.
- Configured `.env.example`, `.env`, and hardened `.gitignore` against accidental file leakage.
- Untracked committed storage files from git while preserving user data on disk.
- Completed full test execution: 54/54 automated backend tests passed, frontend unit tests passed, production build passed.
