# TrustVault — Prioritized Engineering & Security Implementation Plan

## Architectural Principles
1. **Zero-Trust Input Model:** Never trust client-supplied identity, roles, permissions, MIME types, or filenames.
2. **Fail-Closed Access Control:** Deny access by default at every layer (system roles vs document-level permissions).
3. **Defense in Depth:** Combine application validation, ORM/database constraints, secure OS filesystem abstraction, and cryptographic tamper-evidence.
4. **Immediate Revocation:** Authorization must verify real-time database state on every operation, never caching mutable rights in long-lived tokens.
5. **Audit Integrity:** Tamper-evident SHA-256 hash chaining with deterministic canonical serialization and concurrency serialization.

---

## Roadmap Phases

```
Phase 1: Repository Analysis & Vulnerability Review [COMPLETED]
   ├── Inspect entire backend and frontend codebase
   ├── Write SECURITY_REVIEW.md
   ├── Write IMPLEMENTATION_PLAN.md
   ├── Write CHANGELOG.md
   └── Write THREATS.md

Phase 2: Robust Authentication & Session Architecture
   ├── Fix privilege escalation in registration (hardcode safe 'user' role)
   ├── Add full name, normalized email, and password complexity validation
   ├── Implement rate limiting on auth routes
   ├── Add safe generic authentication messages (prevent email enumeration)
   ├── Implement GET /api/auth/me (current user verification)
   ├── Implement POST /api/auth/logout (session invalidation)
   ├── Implement dual token support (Bearer auth + secure HttpOnly cookies)
   ├── Add admin bootstrap script: scripts/seedAdmin.js
   └── Backend unit/integration tests for auth in tests/auth.test.js

Phase 3: Robust Authorization & Role-Based Access Control
   ├── Differentiate system-level roles ('admin', 'user') from document roles ('owner', 'editor', 'viewer')
   ├── Enforce backend authorization on all routes: requireDocumentAccess('read' | 'edit' | 'owner')
   ├── Ensure Admin access to audit logs without bypassing document privacy unless documented
   ├── Protect against IDOR on all document metadata, download, and permission routes
   └── Automated authorization tests in tests/permission.test.js

Phase 4: Secure Document Lifecycle & Sharing
   ├── Re-architect Multer storage: UUID identifiers (<uuid>.<ext>), isolated from original filenames
   ├── Implement true magic-byte / file signature validation (PDF, PNG, JPG, TXT)
   ├── Prevent path traversal with absolute path verification against STORAGE_DIR
   ├── Implement RESTful document endpoints:
   │     POST   /api/documents/upload
   │     GET    /api/documents
   │     GET    /api/documents/:id
   │     GET    /api/documents/:id/download
   │     PATCH  /api/documents/:id (metadata update: title, category)
   │     DELETE /api/documents/:id (owner only, cleans disk and permissions)
   │     GET    /api/documents/:id/permissions
   │     POST   /api/documents/:id/share (by verified email, Viewer/Editor)
   │     DELETE /api/documents/:id/permissions/:permissionId
   ├── Compound unique index on Permission schema: { documentId: 1, userId: 1 }
   └── Document security tests in tests/document.test.js

Phase 5: Tamper-Evident Cryptographic Audit Logging
   ├── Redesign AuditLog schema: eventId, actorId, action, documentId, targetUserId, timestamp, metadata, previousHash, currentHash
   ├── Implement canonical JSON serialization for deterministic hashing
   ├── Implement SHA-256 cryptographic chaining (currentHash = SHA256(canonicalData + previousHash))
   ├── Enforce sequential write serialization / lock to prevent concurrency race conditions
   ├── Record critical security events (login success/failure, register, upload, download, denied access, share, revoke, delete)
   ├── Implement scripts/verifyAuditChain.js and utils/auditIntegrity.js
   └── Cryptographic audit chain integrity tests in tests/audit.test.js

Phase 6: Frontend Security & Modern User Experience
   ├── Modernize API service (configurable REACT_APP_API_URL, cookie credentials)
   ├── Secure session restoration (verify with GET /api/auth/me, do not trust localStorage role)
   ├── Upgrade Login component to include User Registration tab with client validation and password visibility toggle
   ├── Modernize Dashboard:
   │     - Documents table (owned & shared)
   │     - Share modal with user email search and Viewer/Editor selector
   │     - Active permissions list with one-click revocation
   │     - Document metadata editor and deletion modal
   │     - Secure download trigger
   ├── Upgrade Audit Trail view:
   │     - Pagination and action/actor/date filtering
   │     - Cryptographic verification badge / integrity status check
   └── Polish responsive UI with Tailwind CSS

Phase 7: Deployment Hardening & Documentation
   ├── Add Helmet, CORS allowlisting from environment, NoSQL injection filtering
   ├── Configure .env.example with complete production & development specifications
   ├── Update .gitignore to exclude storage files and sensitive assets
   ├── Document secret rotation for previously committed files in README.md
   └── Complete THREATS.md with threat model analysis

Phase 8: Comprehensive Verification & Final Reporting
   ├── Execute all backend Jest & Supertest test suites
   ├── Execute frontend build and test checks
   ├── Verify all manual security flows
   └── Produce comprehensive final engineering report
```

