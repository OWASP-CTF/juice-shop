# Security Assessment Report: OWASP Juice Shop dc34-ctf

**Date**: 2026-08-08
**Assessor**: Codex, using the OWASP Secure Agent Playbook
**Scope**: Server-side application code, HTTP trust boundaries, focused regression tests, dependency manifests, and current-file secret patterns in `OWASP-CTF/juice-shop` at `dc34-ctf`
**Skills Used**: Codex Security repository scan and finding remediation; Secure Agent Playbook code review, OWASP Top 10 web review, secrets scan, and npm SCA audit

---

## Executive Summary

The assessment confirmed three high-confidence canonical vulnerabilities and a set of related web-security weaknesses. The remediation removes directly reachable SQL injection, cross-account basket access, ZIP traversal, unsafe evaluation/deserialization, weak credential and token handling, several authorization gaps, stored/reflected injection paths, SSRF to private networks, and input-validation flaws. Later source-derived passes additionally gate operational artifacts and premium/Web3 routes, disable legacy knowledge-based recovery by default, remove embedded production seed credentials (including a preconfigured administrator's second-factor seed) and a Web3 challenge secret, make review likes atomic, reject expired coupons and active SVG profile images, constrain chatbot tools, sign progress codes, remove Angular trust bypasses, and replace verbose error responses. Focused and full native regression suites exercise both expected behavior and adversarial inputs; dependency risk and residual defense-in-depth gaps remain explicitly tracked below.

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
| 11 | MEDIUM | Cookie-authenticated mutations lacked explicit anti-CSRF controls | CWE-352 | [464-084](https://www.opencre.org/cre/464-084) | A01 Broken Access Control | Fixed for reviewed cookie mutation |
| 12 | LOW | Generic error handling and public training artifacts disclosed implementation data | CWE-200 | — | A05 Security Misconfiguration | Fixed in reviewed server paths |

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
- **Evidence**: The baseline accepted a victim basket identifier. Hardened API regressions verify foreign basket/item identifiers return 403, collection reads are scoped to the token basket, review authorship is server-bound, and users, complaints, authentication details, support logs, metrics, premium content, Web3 operations, feedback records, and product mutations enforce role policy.
- **Remediation**: Central route guards now authenticate and authorize roles, basket paths compare object ownership with token-bound `bid`, review update predicates include the authenticated author, and privilege-specific routes require their corresponding role.
- **Confidence**: HIGH

### CRITICAL — Untrusted expressions and query programs were evaluated

- **ID**: JS-2026-004
- **CWE**: CWE-502 / CWE-94
- **OpenCRE**: [831-563](https://www.opencre.org/cre/831-563) — avoid deserialization logic
- **OWASP Ref**: A03:2021 Injection; A08:2021 Software and Data Integrity Failures
- **Location**: `routes/b2bOrder.ts`, `routes/showProductReviews.ts`, `routes/trackOrder.ts`, `routes/captcha.ts`, `routes/userProfile.ts`, `routes/chat.ts`
- **Impact**: Attackers could execute or stall expression evaluators and submit executable Mongo-style predicates.
- **Evidence**: Regressions submit infinite-loop and sandbox-breakout expressions, Mongo sleep/selector payloads, and injected order identifiers. The requests are rejected or handled as inert data.
- **Remediation**: B2B data is parsed only as JSON, database and chatbot review lookups use typed direct equality predicates, CAPTCHA arithmetic uses explicit operators, and profile rendering no longer calls `eval`. Chatbot coupon issuance is bounded and disabled without an explicit support-service opt-in, authentication tokens are verified before tool use, and tool-call internals are returned only to verified administrators.
- **Confidence**: HIGH

### HIGH — Static secrets, weak password hashes, and permissive JWT verification

- **ID**: JS-2026-005
- **CWE**: CWE-287 / CWE-327
- **OpenCRE**: [813-610](https://www.opencre.org/cre/813-610) — do not use static secrets; [742-431](https://www.opencre.org/cre/742-431) — use approved cryptographic algorithms
- **OWASP Ref**: A02:2021 Cryptographic Failures; A07:2021 Identification and Authentication Failures
- **Location**: `lib/insecurity.ts`, `models/user.ts`, `routes/checkKeys.ts`, authentication and recovery routes
- **Impact**: Repository readers could forge tokens and coupons, crack unsalted MD5 passwords cheaply, and exploit JWT algorithm confusion.
- **Evidence**: Current-file secret-pattern scanning found zero API-token, private-key, or embedded-URL-credential pattern files. Unit and API tests verify salted password hashes, incorrect passwords, repeated-password validation, minimum change/reset length, signed coupon and progress-code bounds, forged/unknown progress-code rejection, unsigned/wrong-algorithm JWT rejection, secret-free user tokens, default-disabled security-question recovery, complete 2FA setup/disable flows, rejection of eight formerly repository-known production seed passwords, and replacement of the repository-known 2FA administrator seed.
- **Remediation**: Private JWT and application HMAC keys are environment-backed with per-process safe fallbacks; sensitive seed accounts now use deployment environment variables with cryptographically random fallbacks, including a separately configurable random base32 TOTP seed for the preconfigured 2FA administrator; the embedded Web3 mnemonic/private-key derivation was removed in favor of an environment-backed challenge key; RSA is at least 2048 bits; accepted JWTs are pinned to RS256 and contain only an allowlisted user projection; passwords use salted scrypt with constant-time comparison; and coupons and continue codes carry scoped HMACs. Restore endpoints accept only authenticated codes containing known challenge IDs. Legacy knowledge-based recovery requires an explicit compatibility opt-in.
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
- **Evidence**: API regressions submit direct and recursively masked iframe/script payloads and assert sanitized storage/output. Angular search regressions verify query/product HTML remains untrusted, promotion subtitles are emitted as a native WebVTT track rather than executable script content, profile usernames are encoded, the profile CSP no longer permits `unsafe-eval`, and remotely referenced SVG profile images are rejected before retrieval.
- **Remediation**: Secure recursive sanitization is unconditional at model boundaries, Angular's built-in HTML sanitization is no longer bypassed for product descriptions or search queries, video subtitles use the browser's non-executable WebVTT track mechanism, dynamic template evaluation was removed, reflected identifiers are constrained to inert characters, and remote profile images are restricted to non-active raster extensions.
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
- **Evidence**: API regressions verify role fields are ignored, foreign payment cards and invalid amounts are denied, negative item quantities, expired/forged/excessive coupons fail, concurrent duplicate review likes result in exactly one success, CAPTCHA answers are not returned and concurrent/replayed submissions result in exactly one success, feedback owner IDs are overwritten, and erasure requires the stored HMAC answer.
- **Remediation**: Server-side identity binding and allowlisted registration fields were added; monetary/rating/quantity ranges are validated; obsolete campaign coupons were removed; review likes use an atomic conditional update with per-process duplicate suppression; arithmetic and image CAPTCHAs are atomically one-use and image answers remain server-side; erasure renders a fixed template and verifies the account answer.
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

### MEDIUM — Cookie-authenticated mutations lacked explicit anti-CSRF controls

- **ID**: JS-2026-011
- **CWE**: CWE-352
- **OpenCRE**: [464-084](https://www.opencre.org/cre/464-084) — add CSRF protection for cookie-based REST services
- **OWASP Ref**: A01:2021 Broken Access Control
- **Location**: cookie-authenticated profile routes and token cookie issuance
- **Impact**: Browser behavior or future cookie-policy changes could allow a malicious origin to induce authenticated state changes.
- **Evidence**: CORS was previously unrestricted and no synchronizer/double-submit token was present. CORS is now restricted to `server.baseUrl`; authentication cookies are explicitly HttpOnly and SameSite=Strict (and Secure in production); the cookie-authenticated profile mutation requires a same-origin Origin/Referer. API regressions verify foreign and missing origins receive 403.
- **Remediation**: Explicit cookie attributes and mandatory profile origin validation address the demonstrated path. Extend origin or token validation to any future cookie-authenticated mutation and retain header-based authorization for API clients.
- **Confidence**: MEDIUM because modern browser defaults reduce the currently demonstrated attack surface.

### LOW — Generic error handling and public training artifacts disclosed implementation data

- **ID**: JS-2026-012
- **CWE**: CWE-200
- **OWASP Ref**: A05:2021 Security Misconfiguration
- **Location**: final server error boundary; formerly `/ftp`, `/encryptionkeys`, and `/metrics`
- **Impact**: Attackers could learn stack, dependency, operational, or deliberately published challenge information that accelerates follow-on attacks.
- **Evidence**: The final middleware returns a fixed JSON error while preserving safe 4xx statuses and logs diagnostics server-side. The current-user endpoint always returns JSON and ignores JSONP callbacks. The reviewed operational surfaces no longer expose FTP/quarantine listings or backup artifacts, encryption keys, or unauthenticated metrics; regressions verify 403/404/401 behavior as appropriate.
- **Remediation**: FTP is restricted to the legal document and generated order PDFs, quarantine and key routes are disabled, metrics require an authenticated administrator, legacy JSONP user-data disclosure was removed, and verbose development errors were replaced by a minimal client response.
- **Confidence**: HIGH for disclosure presence; operational severity depends on deployment intent.

## Verification Evidence

- `PORT=37123 npm run test:api`: 459 tests, 446 passed, 2 failed, 11 skipped. One failure is an external StackOverflow HTTP 403; the other is cross-file asynchronous test activity after all 9 chatbot assertions passed. The isolated changed-route batch below is clean.
- Second-pass focused security API batch: 137 tests, 131 passed, 0 failed, 6 pre-existing skips.
- Second-pass focused server unit batch: 58 passed, 0 failed.
- Third-pass focused security API batch: 41 passed, 0 failed; additional affected error-path suites passed apart from an external profile-image fetch timeout.
- Focused Angular search suite: 9 passed, 0 failed.
- Third-pass full API suite: 460 tests, 447 passed, 2 failed, 11 skipped. Both failures were external-resource connection timeouts (Disqus and Stack Overflow); all repository-owned API tests passed.
- Third-pass full frontend suite: 120 files, 938 tests passed, 0 failed.
- Seed-credential and memory-response API regressions: 15 passed, 0 failed; user-token unit regressions: 4 passed, 0 failed.
- Credential-pass full API suite: 467 tests, 452 passed, 4 failed, 11 skipped. All four failures were live-site DNS/timeout/HTTP failures (Pastebin, Stack Overflow, GitHub, and the external profile-image host); all repository-owned API tests passed.
- Final 2FA-seed full API suite: 471 tests, 459 passed, 1 failed, 11 skipped. The sole failure was the external Stack Overflow resource returning HTTP 403 instead of 200; all repository-owned API tests passed.
- Credential-pass full frontend suite: 120 files, 938 tests passed, 0 failed.
- JSONP, video-subtitle, and concurrent-CAPTCHA focused API batch: 50 passed, 0 failed.
- 2FA and production seed-credential focused batch: 22 passed, 0 failed, including normal 2FA setup/verify/disable behavior and replacement of the repository-known administrator password and TOTP seed.
- Focused security API batch: 51 tests, 49 passed, 0 failed, 2 pre-existing skips.
- Focused server unit batch: 98 tests, 96 passed, 0 failed, 2 pending; `test/server/insecuritySpec.ts` separately passed 37/37.
- `PORT=65000 npm run test:server`: 253 passed, 2 pending, 3 failed solely because another workspace process already owns the suite's hard-coded port 3000; the first failure confirms the port is occupied and the other two are its setup/teardown consequences.
- `npm run build:server`: passed.
- `npm run lint`: passed, including frontend TypeScript and SCSS lint.
- `npm run rsn:update && npm run rsn`: reviewed deltas locked; all codefix files match the locked state.
- Official PR scorer after the first signed-off batch: 106/141 points (75%), 28/38 challenges patched. The second signed-off batch improved this to 118/141 points (84%), 32/38 challenges patched. The third and seed-credential signed-off batches remained at 118/141 and 32/38; the JSONP/video/CAPTCHA pass has not yet been scored at the time of this report update.
- Current-file manual secret-pattern scan: 1,166 files examined; 0 API-token pattern files, 0 private-key pattern files, and 0 embedded URL-credential pattern files (dependencies, build output, and Git metadata excluded). Five high-risk-named files were contextually reviewed: npm policy files, test-compose configuration, and static CTF/training key material rather than active service credentials. No trufflehog/gitleaks/detect-secrets binary, CI secret-scanning control, or broad `.env`/`*.key`/`*.pem` ignore coverage was present; these are preventive-control gaps.

## Out of Scope

- No competitor fork, branch, commit, diff, patch, pull request, or scorer output was inspected.
- Third-party source under installed dependency directories was not manually audited; SCA results are reported instead.
- The Angular frontend and external-chain behavior were not exhaustively reviewed or dynamically attacked; Web3 HTTP authorization and repository-embedded key material were reviewed.
- External LLM, blockchain, email, cloud metadata, production proxy, and production secret-management infrastructure were unavailable.
- DNS-rebinding-resistant outbound connection pinning and universal anti-CSRF tokens were not implemented in this batch.
- Public CTF challenge discovery routes were not broadly removed because doing so would materially change the educational application.

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
4. Add connection-level DNS/IP pinning for outbound image retrieval and extend mutation origin/token checks as cookie-authenticated routes evolve.
5. Add a stable multi-instance secret-management policy for JWT, HMAC, coupon, and continue-code signing keys, including rotation and versioning.
