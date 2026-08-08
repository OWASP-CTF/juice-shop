# Security Assessment Report: OWASP Juice Shop dc34-ctf

**Date**: 2026-08-08
**Assessor**: Codex, using the OWASP Secure Agent Playbook
**Scope**: Server-side application code, HTTP trust boundaries, focused regression tests, dependency manifests, and current-file secret patterns in `OWASP-CTF/juice-shop` at `dc34-ctf`
**Skills Used**: Codex Security repository scan and finding remediation; Secure Agent Playbook code review, OWASP Top 10 web review, secrets scan, and npm SCA audit

---

## Executive Summary

The assessment confirmed three high-confidence canonical vulnerabilities and a set of related web-security weaknesses. The remediation removes directly reachable SQL injection, cross-account basket access, ZIP traversal, unsafe evaluation/deserialization, weak credential and token handling, several authorization gaps, stored/reflected injection paths, SSRF to private networks, and input-validation flaws. Focused and full native regression suites exercise both expected behavior and adversarial inputs; dependency risk, public training artifacts, CSRF coverage, and generic error disclosure remain explicitly tracked below.

## Findings Summary

| # | Severity | Title | CWE | OpenCRE | OWASP Ref | Status |
|---|----------|-------|-----|---------|-----------|--------|
| 1 | CRITICAL | ZIP entries escaped the upload directory | CWE-22 | [675-168](https://www.opencre.org/cre/675-168) | A01 Broken Access Control | Fixed |
| 2 | CRITICAL | Login and product search executed attacker-controlled SQL | CWE-89 | [732-873](https://www.opencre.org/cre/732-873) | A03 Injection | Fixed |
| 3 | HIGH | Object and function authorization was incomplete | CWE-639 | — | A01 Broken Access Control | Fixed |
| 4 | CRITICAL | Untrusted expressions and query programs were evaluated | CWE-502 / CWE-94 | [831-563](https://www.opencre.org/cre/831-563) | A03 Injection / A08 Integrity Failures | Fixed |
| 5 | HIGH | Static secrets, weak password hashes, and permissive JWT verification | CWE-287 / CWE-327 | [813-610](https://www.opencre.org/cre/813-610), [742-431](https://www.opencre.org/cre/742-431) | A02 Cryptographic Failures / A07 Authentication Failures | Fixed |
| 6 | HIGH | Profile image retrieval allowed server-side requests to internal hosts | CWE-918 | — | A10 SSRF | Fixed with residual DNS-rebinding gap |
| 7 | HIGH | User-controlled content reached executable or unsafe HTML contexts | CWE-79 / CWE-1336 | [366-835](https://www.opencre.org/cre/366-835) | A03 Injection | Fixed in reviewed server paths |
| 8 | HIGH | Deprecated XML/YAML and weak upload checks enabled XXE and resource abuse | CWE-611 / CWE-400 / CWE-434 | — | A05 Security Misconfiguration | Fixed |
| 9 | HIGH | Business operations accepted forged identities and invalid monetary quantities | CWE-20 / CWE-841 | — | A04 Insecure Design | Fixed in reviewed routes |
| 10 | CRITICAL | Installed dependencies include known vulnerable components | CWE-1104 | — | A06 Vulnerable and Outdated Components | Open |
| 11 | MEDIUM | Cookie-authenticated mutations lack an explicit anti-CSRF mechanism | CWE-352 | [464-084](https://www.opencre.org/cre/464-084) | A01 Broken Access Control | Open; CORS constrained |
| 12 | LOW | Generic error handling and public training artifacts disclose implementation data | CWE-200 | — | A05 Security Misconfiguration | Open / partially mitigated |

## Findings Detail

### CRITICAL — ZIP entries escaped the upload directory

- **ID**: JS-2026-001
- **CWE**: CWE-22
- **OpenCRE**: [675-168](https://www.opencre.org/cre/675-168) — sanitize filename metadata from an untrusted origin
- **OWASP Ref**: A01:2021 Broken Access Control
- **Location**: `routes/fileUpload.ts`
- **Impact**: A crafted archive could overwrite repository-relative files outside `uploads/complaints`, potentially changing application content or executable code.
- **Evidence**: The baseline handler concatenated `entry.path` into `createWriteStream`; the regression suite submitted traversal ZIP entries and demonstrated that the hardened handler returns 400 and does not write outside the destination.
- **Remediation**: The handler now resolves every entry beneath a fixed root, verifies `path.relative` containment before any write, limits total uncompressed size, rejects invalid archives, and uses exclusive file creation.
- **Confidence**: HIGH

### CRITICAL — Login and product search executed attacker-controlled SQL

- **ID**: JS-2026-002
- **CWE**: CWE-89
- **OpenCRE**: [732-873](https://www.opencre.org/cre/732-873) — lock/precompile queries through parameterization
- **OWASP Ref**: A03:2021 Injection; ASVS V5.3.4; WSTG-INPV-05
- **Location**: `routes/login.ts`, `routes/search.ts`
- **Impact**: Unauthenticated callers could bypass login, impersonate privileged users, read credentials, and enumerate the database schema.
- **Evidence**: Baseline API tests confirmed quote/UNION payloads changed query meaning. Hardened tests confirm login payloads return 401 and search payloads are treated as literal data without exposing users or `sqlite_master`.
- **Remediation**: Login uses an exact ORM lookup followed by password verification; search uses a bound `$criteria` parameter.
- **Confidence**: HIGH

### HIGH — Object and function authorization was incomplete

- **ID**: JS-2026-003
- **CWE**: CWE-639
- **OWASP Ref**: A01:2021 Broken Access Control; ASVS V4
- **Location**: `server.ts`, `routes/basketItems.ts`, review routes
- **Impact**: A customer could select another basket or basket item, forge review authorship, and invoke endpoints intended for administrators.
- **Evidence**: The baseline accepted a victim basket identifier. Hardened API regressions verify foreign basket/item identifiers return 403, collection reads are scoped to the token basket, review authorship is server-bound, and users, complaints, authentication details, support logs, feedback records, and product mutations enforce role policy.
- **Remediation**: Central route guards now authenticate and authorize roles, basket paths compare object ownership with token-bound `bid`, and review update predicates include the authenticated author.
- **Confidence**: HIGH

### CRITICAL — Untrusted expressions and query programs were evaluated

- **ID**: JS-2026-004
- **CWE**: CWE-502 / CWE-94
- **OpenCRE**: [831-563](https://www.opencre.org/cre/831-563) — avoid deserialization logic
- **OWASP Ref**: A03:2021 Injection; A08:2021 Software and Data Integrity Failures
- **Location**: `routes/b2bOrder.ts`, `routes/showProductReviews.ts`, `routes/trackOrder.ts`, `routes/captcha.ts`, `routes/userProfile.ts`
- **Impact**: Attackers could execute or stall expression evaluators and submit executable Mongo-style predicates.
- **Evidence**: Regressions submit infinite-loop and sandbox-breakout expressions, Mongo sleep/selector payloads, and injected order identifiers. The requests are rejected or handled as inert data.
- **Remediation**: B2B data is parsed only as JSON, database lookups use typed direct equality predicates, CAPTCHA arithmetic uses explicit operators, and profile rendering no longer calls `eval`.
- **Confidence**: HIGH

### HIGH — Static secrets, weak password hashes, and permissive JWT verification

- **ID**: JS-2026-005
- **CWE**: CWE-287 / CWE-327
- **OpenCRE**: [813-610](https://www.opencre.org/cre/813-610) — do not use static secrets; [742-431](https://www.opencre.org/cre/742-431) — use approved cryptographic algorithms
- **OWASP Ref**: A02:2021 Cryptographic Failures; A07:2021 Identification and Authentication Failures
- **Location**: `lib/insecurity.ts`, `models/user.ts`, authentication routes
- **Impact**: Repository readers could forge tokens and coupons, crack unsalted MD5 passwords cheaply, and exploit JWT algorithm confusion.
- **Evidence**: Current-file secret-pattern scanning found zero API-token, private-key, or embedded-URL-credential pattern files. Unit and API tests verify salted password hashes, incorrect passwords, signed coupon bounds, unsigned/wrong-algorithm JWT rejection, and complete 2FA setup/disable flows.
- **Remediation**: Private JWT and application HMAC keys are environment-backed with per-process safe fallbacks, RSA is at least 2048 bits, accepted JWTs are pinned to RS256, passwords use salted scrypt with constant-time comparison, and coupons carry an HMAC with a bounded discount.
- **Confidence**: HIGH

### HIGH — Profile image retrieval allowed server-side requests to internal hosts

- **ID**: JS-2026-006
- **CWE**: CWE-918
- **OWASP Ref**: A10:2021 Server-Side Request Forgery
- **Location**: `routes/profileImageUrlUpload.ts`
- **Impact**: An authenticated user could make the server access loopback, link-local, private, or otherwise internal HTTP services.
- **Evidence**: Regression cases for loopback and metadata-style targets now return 400 before a request. Redirects are disabled; only HTTP(S), recognized image extensions, public DNS results, image media types, and bounded response bodies are accepted.
- **Remediation**: URL parsing, protocol checks, private IPv4/IPv6 rejection, redirect denial, timeout, content-type, and byte limits were added.
- **Confidence**: HIGH for direct-address and initial-resolution attacks. A DNS rebinding between validation and connection remains a documented residual risk.

### HIGH — User-controlled content reached executable or unsafe HTML contexts

- **ID**: JS-2026-007
- **CWE**: CWE-79 / CWE-1336
- **OpenCRE**: [366-835](https://www.opencre.org/cre/366-835) — escape output against XSS
- **OWASP Ref**: A03:2021 Injection; ASVS V5.3.3; WSTG-INPV-01
- **Location**: `models/user.ts`, `models/product.ts`, `models/feedback.ts`, `routes/userProfile.ts`, `routes/saveLoginIp.ts`, `routes/trackOrder.ts`
- **Impact**: Stored and reflected payloads could execute in another user's browser or escape the server-side profile template.
- **Evidence**: API regressions submit direct and recursively masked iframe/script payloads and assert sanitized storage/output. Profile usernames are encoded and the profile CSP no longer permits `unsafe-eval`.
- **Remediation**: Secure recursive sanitization is unconditional at model boundaries, dynamic template evaluation was removed, and reflected identifiers are constrained to inert characters.
- **Confidence**: HIGH for reviewed server paths; exhaustive Angular DOM-sink analysis was out of scope.

### HIGH — Deprecated XML/YAML and weak upload checks enabled XXE and resource abuse

- **ID**: JS-2026-008
- **CWE**: CWE-611 / CWE-400 / CWE-434
- **OWASP Ref**: A05:2021 Security Misconfiguration
- **Location**: `routes/fileUpload.ts`, `routes/profileImageFileUpload.ts`
- **Impact**: Crafted documents could read local files or consume excessive CPU/memory, while oversized or disallowed files bypassed browser-only checks.
- **Evidence**: Native API tests cover Linux/Windows XXE, billion-laughs/quadratic XML, YAML bombs, oversized files, illegal types, and malformed archives. They now return 410, 413, 415, or 400 without parsing unsafe formats.
- **Remediation**: Deprecated XML/YAML inputs are rejected without deserialization, and the server independently enforces type and size limits.
- **Confidence**: HIGH

### HIGH — Business operations accepted forged identities and invalid monetary quantities

- **ID**: JS-2026-009
- **CWE**: CWE-20 / CWE-841
- **OWASP Ref**: A04:2021 Insecure Design
- **Location**: `server.ts`, `routes/wallet.ts`, `routes/deluxe.ts`, `routes/order.ts`, `routes/dataErasure.ts`, `routes/captcha.ts`
- **Impact**: Callers could self-register privileged roles, charge invalid wallet amounts, gain deluxe status without a real payment mode, manipulate inventory with negative quantities, forge feedback owners, reuse CAPTCHAs, or submit erasure requests without the account security answer.
- **Evidence**: API regressions verify role fields are ignored, foreign payment cards and invalid amounts are denied, negative item quantities and excessive coupons fail, feedback owner IDs are overwritten, and erasure requires the stored HMAC answer.
- **Remediation**: Server-side identity binding and allowlisted registration fields were added; monetary/rating/quantity ranges are validated; CAPTCHAs are one-use; erasure renders a fixed template and verifies the account answer.
- **Confidence**: HIGH

### CRITICAL — Installed dependencies include known vulnerable components

- **ID**: JS-2026-010
- **CWE**: CWE-1104
- **OWASP Ref**: A06:2021 Vulnerable and Outdated Components
- **Location**: root and `frontend/` npm dependency trees
- **Impact**: Known flaws in reachable dependencies can undermine otherwise-correct application controls.
- **Evidence**: Repository-native `npm audit --json` reports 56 root advisories (7 critical, 27 high, 18 moderate, 4 low) among 1,575 dependencies and 24 frontend advisories (5 high, 7 moderate, 12 low). Several fixes require major upgrades or have no automated fix.
- **Remediation**: Upgrade direct dependencies in compatibility-tested batches, prioritize reachable critical/high advisories, remove unused vulnerable packages, and document accepted residual risk. JWT algorithm pinning supplies a compensating application control for the relevant token path.
- **Confidence**: HIGH for dependency presence; exploitability was not individually proven for every transitive advisory.

### MEDIUM — Cookie-authenticated mutations lack an explicit anti-CSRF mechanism

- **ID**: JS-2026-011
- **CWE**: CWE-352
- **OpenCRE**: [464-084](https://www.opencre.org/cre/464-084) — add CSRF protection for cookie-based REST services
- **OWASP Ref**: A01:2021 Broken Access Control
- **Location**: cookie-authenticated profile routes and token cookie issuance
- **Impact**: Browser behavior or future cookie-policy changes could allow a malicious origin to induce authenticated state changes.
- **Evidence**: CORS was previously unrestricted and no synchronizer/double-submit token is present. CORS is now restricted to `server.baseUrl`, but CORS alone is not a complete CSRF control.
- **Remediation**: Set explicit Secure, HttpOnly, and SameSite cookie attributes and add origin/token validation to every cookie-authenticated mutation.
- **Confidence**: MEDIUM because modern browser defaults reduce the currently demonstrated attack surface.

### LOW — Generic error handling and public training artifacts disclose implementation data

- **ID**: JS-2026-012
- **CWE**: CWE-200
- **OWASP Ref**: A05:2021 Security Misconfiguration
- **Location**: final `errorhandler()` middleware; `/ftp`, `/encryptionkeys`, `/metrics`, and application training assets
- **Impact**: Attackers can learn stack, dependency, operational, or deliberately published challenge information that accelerates follow-on attacks.
- **Evidence**: The final middleware renders detailed errors and several intentionally public CTF endpoints expose listings or operational material. Access logs themselves are now administrator-only.
- **Remediation**: Replace generic development errors with logged correlation IDs and a minimal client message; disable listings and metrics in production or require explicit roles/network policy; remove obsolete backup/key artifacts from deployable images.
- **Confidence**: HIGH for disclosure presence; operational severity depends on deployment intent.

## Verification Evidence

- `PORT=65000 npm run test:api`: 469 tests, 456 passed, 2 failed, 11 skipped. One failure was an external StackOverflow HTTP 403; the only local assertion failure was corrected and its product suite then passed 8/8.
- `test/api/2fa.test.ts`: 13 passed, 0 failed.
- Focused security API batch: 51 tests, 49 passed, 0 failed, 2 pre-existing skips.
- Focused server unit batch: 98 tests, 96 passed, 0 failed, 2 pending; `test/server/insecuritySpec.ts` separately passed 37/37.
- `PORT=65000 npm run test:server`: 253 passed, 2 pending, 3 failed solely because another workspace process already owns the suite's hard-coded port 3000; the first failure confirms the port is occupied and the other two are its setup/teardown consequences.
- `npm run build:server`: passed.
- `npm run rsn:update && npm run rsn`: reviewed deltas locked; all codefix files match the locked state.
- Current-file secret-pattern scan: 0 API-token pattern files, 0 private-key pattern files, 0 embedded URL-credential pattern files (dependencies, build output, Git metadata, and lockfiles excluded).

## Out of Scope

- No competitor fork, branch, commit, diff, patch, pull request, or scorer output was inspected.
- Third-party source under installed dependency directories was not manually audited; SCA results are reported instead.
- The Angular frontend and Web3 paths were not exhaustively reviewed or dynamically attacked.
- External LLM, blockchain, email, cloud metadata, production proxy, and production secret-management infrastructure were unavailable.
- DNS-rebinding-resistant outbound connection pinning and a complete CSRF control were not implemented in this batch.
- Public CTF training artifacts and challenge discovery routes were not broadly removed because doing so would materially change the educational application; they are called out as deployment gaps.

## Standards Coverage

| CRE ID | Requirement | CWE | ASVS / WSTG | Findings |
|--------|-------------|-----|-------------|----------|
| [675-168](https://www.opencre.org/cre/675-168) | Sanitize untrusted filename metadata | CWE-22 | File handling | #1 |
| [732-873](https://www.opencre.org/cre/732-873) | Parameterize queries | CWE-89 | ASVS V5.3.4 / WSTG-INPV-05 | #2 |
| [831-563](https://www.opencre.org/cre/831-563) | Avoid unsafe deserialization logic | CWE-502 | Input processing | #4 |
| [813-610](https://www.opencre.org/cre/813-610) | Do not use static secrets | CWE-287 | Authentication | #5 |
| [742-431](https://www.opencre.org/cre/742-431) | Use approved cryptography | CWE-327 | Cryptography | #5 |
| [366-835](https://www.opencre.org/cre/366-835) | Escape output against XSS | CWE-79 | ASVS V5.3.3 / WSTG-INPV-01 | #7 |
| [464-084](https://www.opencre.org/cre/464-084) | Protect cookie REST services from CSRF | CWE-352 | Session security | #11 |

## Recommendations

1. Merge the verified application fixes and require the same negative security regressions in CI.
2. Set `JWT_PRIVATE_KEY` and `APPLICATION_HMAC_KEY` through production secret management so multiple instances share stable, rotated keys.
3. Triage and upgrade the root critical/high npm advisories, then the frontend high advisories, with compatibility tests.
4. Add connection-level DNS/IP pinning for outbound image retrieval and complete CSRF/cookie hardening.
5. Replace verbose error handling and gate or remove public CTF-only listings, metrics, backups, and key artifacts in production profiles.
