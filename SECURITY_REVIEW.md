# TrustVault — Comprehensive Security Assessment & Vulnerability Review

**Date:** November 2026  
**Auditor:** Senior Full-Stack & Application Security Engineering Team  
**Scope:** TrustVault MERN Architecture (Backend REST APIs, Database Models, Storage Engine, Middleware, Audit Trail, and Frontend React Client)

---

## Executive Summary

TrustVault was conceptualized as a secure confidential document storage, controlled sharing, and tamper-evident audit logging platform. An exhaustive manual code audit and static analysis of the existing codebase revealed severe vulnerabilities across all major security domains:

1. **Authentication:** Privilege escalation via mass assignment on public registration, absence of rate limiting, lack of credential complexity enforcement, and unmonitored authentication failures.
2. **Authorization & Access Control:** Missing RESTful document lifecycle endpoints (view metadata, edit metadata, delete), lack of recipient validation during document sharing, and absent compound database constraints to prevent duplicate permission states.
3. **File Handling & Storage:** Blind trust in client-provided MIME headers without file magic-byte validation, vulnerable filename generation permitting directory traversal artifacts, missing path verification upon retrieval, and committed sensitive user data in the storage directory.
4. **Audit Integrity:** Flawed hash chain implementation lacking stored current entry hashes, vulnerable to silent split-brain race conditions during concurrent writes, without integrity verification tooling or tamper detection.
5. **Frontend Security:** Untrusted local storage persistence leading to client-side privilege spoofing, hardcoded production API targets, absence of session verification via `/api/auth/me`, and missing registration UI.

Below is the prioritized catalog of all identified vulnerabilities.

---

## Vulnerability Inventory by Severity

| ID | Title | Severity | OWASP Category | Component | Status |
|---|---|---|---|---|---|
| **SEC-01** | Privilege Escalation via Mass Assignment in Public Registration | **CRITICAL** | A01:2021-Broken Access Control | `routes/auth.routes.js` | Identified |
| **SEC-02** | Unrestricted File Upload via Unverified Client MIME Header | **CRITICAL** | A04:2021-Insecure Design | `routes/document.routes.js` | Identified |
| **SEC-03** | Broken Audit Hash Chain & Concurrency Race Condition | **CRITICAL** | A08:2021-Software & Data Integrity Failures | `utils/audit.js`, `models/index.js` | Identified |
| **SEC-04** | Client-Side Privilege Spoofing via Untrusted LocalStorage State | **HIGH** | A07:2021-Identification & Auth Failures | `frontend/src/App.js` | Identified |
| **SEC-05** | Credential Stuffing & Brute Force Vulnerability (Missing Rate Limiting) | **HIGH** | A07:2021-Identification & Auth Failures | `server.js`, `routes/auth.routes.js` | Identified |
| **SEC-06** | Missing Authentication Endpoints (`/api/auth/me`, `/api/auth/logout`) | **HIGH** | A07:2021-Identification & Auth Failures | `routes/auth.routes.js` | Identified |
| **SEC-07** | Insecure Filename Concatenation & Path Traversal Risk | **HIGH** | A01:2021-Broken Access Control | `routes/document.routes.js` | Identified |
| **SEC-08** | Missing File Signature (Magic Byte) Verification | **HIGH** | A04:2021-Insecure Design | `routes/document.routes.js` | Identified |
| **SEC-09** | Missing Security HTTP Headers (Helmet, CSRF, NoSQL Injection) | **HIGH** | A05:2021-Security Misconfiguration | `backend/server.js` | Identified |
| **SEC-10** | Unrestricted Document Sharing to Non-Existent Users & Missing Compound Index | **HIGH** | A01:2021-Broken Access Control | `routes/document.routes.js`, `models/index.js` | Identified |
| **SEC-11** | Absence of Input Validation & Normalization Framework | **MEDIUM** | A03:2021-Injection | `routes/auth.routes.js`, `routes/document.routes.js` | Identified |
| **SEC-12** | Information Disclosure via Detailed Database Errors in Production | **MEDIUM** | A05:2021-Security Misconfiguration | `backend/server.js` | Identified |
| **SEC-13** | Hardcoded Third-Party API URL & Inflexible CORS Policy | **MEDIUM** | A05:2021-Security Misconfiguration | `backend/server.js`, `frontend/src/services/api.js` | Identified |
| **SEC-14** | Committed User Files & Inadequate `.gitignore` Rules | **MEDIUM** | A05:2021-Security Misconfiguration | `.gitignore`, `backend/storage/` | Identified |
| **SEC-15** | Incomplete RESTful Document Management Endpoints (Delete, Patch, Details) | **MEDIUM** | A04:2021-Insecure Design | `routes/document.routes.js` | Identified |
| **SEC-16** | Absence of Password Visibility & Form Usability in UI | **LOW** | Usability / Security UI | `frontend/src/components/Login.js` | Identified |
| **SEC-17** | Incomplete Testing Suite & Flawed Frontend Test Scaffolding | **LOW** | Quality Assurance | `tests/`, `frontend/src/App.test.js` | Identified |

---

## Detailed Vulnerability Analysis

### [CRITICAL] SEC-01: Privilege Escalation via Mass Assignment in Public Registration
- **Location:** `backend/routes/auth.routes.js:14-31`
- **Code Snippet:**
  ```javascript
  const { email, password, role } = req.body;
  ...
  const newUser = new User({
      email,
      passwordHash,
      role: role || 'user'
  });
  ```
- **Description:** The registration handler extracts `role` directly from `req.body` without filtering or restriction. Any unauthenticated caller can send `{"email": "attacker@evil.com", "password": "...", "role": "admin"}` to instantly attain full system administrative rights.
- **Impact:** Complete system compromise, unauthorized access to all system audit logs, and elevation of privilege.
- **Remediation:** Remove `role` from accepted registration payload. Hardcode newly registered accounts to `'user'`. Implement an administrative bootstrap CLI tool (`scripts/seedAdmin.js`) with strong environment variable gating.

---

### [CRITICAL] SEC-02: Unrestricted File Upload via Unverified Client MIME Header
- **Location:** `backend/routes/document.routes.js:31-38`
- **Code Snippet:**
  ```javascript
  const fileFilter = (req, file, cb) => {
      const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'text/plain'];
      if (allowedTypes.includes(file.mimetype)) {
          cb(null, true);
      } else {
          cb(new Error('Invalid file type...'));
      }
  };
  ```
- **Description:** Validation checks `file.mimetype`, which is fully controlled by the HTTP client (`Content-Type` header in multipart payload). An attacker can upload executable binaries, web shells, or scripts disguised with `Content-Type: application/pdf`.
- **Impact:** Malicious file execution, storage corruption, and malware hosting.
- **Remediation:** Implement true file signature / magic-byte verification (e.g., checking PDF header `%PDF`, PNG header `\x89PNG`, JPEG `\xFF\xD8\xFF`, UTF-8 text validation) before persisting or accepting files.

---

### [CRITICAL] SEC-03: Broken Audit Hash Chain & Concurrency Race Condition
- **Location:** `backend/utils/audit.js:8-25`, `backend/models/index.js:33-41`
- **Description:**
  1. The existing schema only records `previousHash`, but never records the entry's own cryptographic hash (`currentHash`).
  2. The `previousHash` is calculated dynamically by hashing fields of the previous record at insertion time, but if any record in the chain is modified later, there is no ledger of what its valid hash was supposed to be.
  3. `AuditLog.findOne().sort({ timestamp: -1 })` is subject to race conditions under concurrent operations, resulting in bifurcated chains.
  4. Failure to write an audit entry is silently caught and swallowed with `console.error()`.
- **Impact:** Audit logs can be modified or deleted without automated tamper detection; security guarantees cannot be proven.
- **Remediation:**
  1. Canonicalize event fields (actor, action, document, timestamp, metadata) into a deterministic payload.
  2. Compute `currentHash = SHA-256(canonicalPayload + previousHash)`.
  3. Enforce write serialization / concurrency locking for audit chain appends.
  4. Implement `utils/auditIntegrity.js` and `scripts/verifyAuditChain.js` to cryptographically verify chain integrity.

---

### [HIGH] SEC-04: Client-Side Privilege Spoofing via Untrusted LocalStorage State
- **Location:** `frontend/src/App.js:11-16`
- **Code Snippet:**
  ```javascript
  const savedUser = localStorage.getItem('trustvault_user');
  if (savedUser && token) {
      setUser(JSON.parse(savedUser));
  }
  ```
- **Description:** The client assumes whatever is in `localStorage.trustvault_user` is authoritative. Any user can open DevTools and set `role: "admin"`. The UI immediately renders the admin Audit Trail tab and administrative tools.
- **Impact:** Unauthorized interface exposure and reliance on untrusted client state.
- **Remediation:** Introduce a backend verification route `GET /api/auth/me`. On application load, validate the active token and pull authoritative profile data directly from the server.

---

### [HIGH] SEC-05: Missing Rate Limiting & Protection Against Brute Force
- **Location:** `backend/server.js`, `backend/routes/auth.routes.js`
- **Description:** No rate limiting or throttling exists on `/api/auth/login` or `/api/auth/register`. An attacker can launch brute-force password guessing or credential stuffing attacks with millions of requests.
- **Impact:** Account takeover, denial of service.
- **Remediation:** Integrate `express-rate-limit` configuring dedicated limiters for authentication endpoints and general API endpoints.

---

### [HIGH] SEC-06: Missing Authentication Lifecycle Endpoints (`/me`, `/logout`, Cookies)
- **Location:** `backend/routes/auth.routes.js`
- **Description:** Missing session validation and logout endpoints. Tokens stored purely in `localStorage` without option for secure `HttpOnly` cookie handling leaves users vulnerable to persistent session leakage and XSS credential exfiltration.
- **Remediation:** Implement `GET /api/auth/me`, `POST /api/auth/logout`, support both `Authorization: Bearer` and secure `HttpOnly`, `SameSite=lax` cookie sessions, and clear cookies upon logout.

---

### [HIGH] SEC-07: Insecure Filename Generation & Path Traversal Vulnerability
- **Location:** `backend/routes/document.routes.js:25`
- **Code Snippet:**
  ```javascript
  const uniqueName = `${uuidv4()}-${file.originalname}`;
  ```
- **Description:** `file.originalname` is directly appended to the disk filename without sanitization. Filenames containing `../`, null bytes, or illegal characters can escape the storage directory or trigger filesystem errors. In download handling, `path.join(storageDir, document.storagePath)` does not verify that the resolved path is strictly contained within `storageDir`.
- **Impact:** Local file inclusion / path traversal, arbitrary file overwrite.
- **Remediation:** Generate storage identifiers strictly as `<uuidv4>.<sanitizedExt>`, store `originalFilename` separately in MongoDB, and strictly validate `path.resolve(storageDir, storagePath).startsWith(path.resolve(storageDir))` upon file access.

---

### [HIGH] SEC-08: Missing File Signature (Magic Byte) Verification
- **Location:** `backend/routes/document.routes.js:31-38`
- **Description:** Files are accepted solely based on caller-specified MIME headers.
- **Remediation:** Implement buffer inspection reading magic bytes for PDF (`%PDF`), JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), and UTF-8 verification for TXT.

---

### [HIGH] SEC-09: Missing Security Middleware
- **Location:** `backend/server.js`
- **Description:** The server lacks HTTP security header protections (e.g., `helmet`), payload size caps, and NoSQL query injection sanitization (`express-mongo-sanitize`).
- **Remediation:** Add `helmet`, sanitize request bodies, configure payload limits, and establish strict CORS policies.

---

### [HIGH] SEC-10: Insecure Document Sharing & Missing Unique Compound Index
- **Location:** `backend/models/index.js:24-30`, `backend/routes/document.routes.js:143-185`
- **Description:**
  1. `POST /api/documents/:documentId/grant` accepts any `targetUserId` without verifying that the target exists in the `User` database.
  2. Users must provide raw MongoDB `_id` rather than recipient email.
  3. `Permission` schema lacks `{ documentId: 1, userId: 1 }` unique index constraint.
  4. Owners can grant permissions to themselves, and editors might grant permissions beyond their scope.
- **Remediation:** Resolve target users by verified email, enforce unique compound database indexing on `(documentId, userId)`, prevent self-sharing, and strictly enforce Owner-only sharing.

---

### [MEDIUM & LOW] SEC-11 through SEC-17
- Input validation missing structured schemas (Zod / Joi / express-validator).
- Stack traces leaked to API consumers in error responses.
- Backend CORS fixed to single Vercel origin, breaking local tests and environments.
- Committed personal documents (`backend/storage/*.pdf`) in git history requiring rotation instructions and `.gitignore` hardening.
- Frontend missing registration form, document deletion, and audit trail pagination/filtering.
- Frontend unit tests failing out of the box.

---

## Action Plan

All Critical and High vulnerabilities will be resolved first during Phases 2, 3, 4, and 5, followed by frontend hardening in Phase 6, deployment configurations in Phase 7, and end-to-end automated testing in Phase 8.

