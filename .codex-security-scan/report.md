# Security Review: OWASP-CTF/juice-shop

## Scope

Repository-wide review emphasizing remotely reachable server security boundaries.

- Scan mode: repository
- Target kind: git_worktree
- Target ID: target_juice_shop_dc34
- Revision: bd2611f6cac491bb80c9fe54e954fd945c3ab5ba
- Snapshot digest: codex-security-snapshot/v1:sha256:bd2611f6cac491bb80c9fe54e954fd945c3ab5ba000000000000000000000000
- Inventory strategy: repository
- Included paths: .
- Excluded paths: node_modules/, frontend/node_modules/, build/, dist/
- Runtime or test status: Static review completed; exploit verification is part of remediation.
- Artifacts reviewed: server.ts, lib/insecurity.ts, routes/, models/, test/api/, test/server/

Limitations and exclusions:
- Independent baseline worker unavailable because all four session slots were occupied.
- Frontend and ancillary tooling were not exhaustively reviewed.
- Excluded node_modules/\*\*: Third-party installed source is outside product-source review.
- Excluded frontend/node_modules/\*\*: Third-party installed source is outside product-source review.

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable findings | 3 |
| Severity mix | critical: 2, high: 1 |
| Confidence mix | high: 3 |
| Coverage | partial |
| Validation mode | source-backed static analysis |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

An unauthenticated internet client or ordinary customer controls HTTP parameters, bodies, headers, cookies, and files. Credentials, sessions, customer objects, the filesystem, internal network access, and process integrity must remain isolated.

### Assets

- Credentials and sessions
- Customer baskets and orders
- Server filesystem
- Internal network reachability
- Application integrity

### Trust Boundaries

- Internet to Express
- HTTP input to query engines
- Archive entries to filesystem writes
- User URL to server-side fetch

### Attacker Capabilities

- Send arbitrary public HTTP requests
- Authenticate as a customer
- Submit duplicate JSON keys
- Upload crafted files
- Supply server-fetched URLs

### Security Objectives

- Authenticate sensitive operations
- Enforce object ownership
- Use data-only query parameters
- Contain writes
- Restrict outbound requests

### Assumptions

- The CTF asks to harden scorer-targeted flaws even when modeled as upstream training challenges.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [ZIP entry paths escape the upload directory](#finding-1) | critical | high | inline below |
| [Login input is interpolated into executable SQL](#finding-2) | critical | high | inline below |
| [Basket operations do not enforce ownership](#finding-3) | high | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] ZIP entry paths escape the upload directory

| Field | Value |
| --- | --- |
| Severity | critical |
| Confidence | high |
| Confidence rationale | The original traversal-bearing path reaches createWriteStream after an overbroad includes check. |
| Category | path-traversal |
| CWE | CWE-22 |
| Affected lines | routes/fileUpload.ts:27-46 |

#### Summary

A crafted entry is concatenated into a write path and checked against the whole repository rather than the upload root.

#### Root Cause

Archive paths are not constrained to the upload root.

**Incorrect containment** — `routes/fileUpload.ts:41-45`

Repository containment is broader than the intended extraction root.

```typescript
if (absolutePath.includes(path.resolve('.'))) entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName))
```

#### Validation

The file upload endpoint accepts ZIPs and routes them here.

#### Dataflow

entry.path -\> concatenation -\> createWriteStream

#### Reachability

Remote upload route, gated by challenge configuration.

#### Severity

**Critical** — Repository-relative file overwrite can compromise integrity and potentially execution.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Resolve against a fixed root, reject escaping relative paths, and write only the validated destination.

<a id="finding-2"></a>

### [2] Login input is interpolated into executable SQL

| Field | Value |
| --- | --- |
| Severity | critical |
| Confidence | high |
| Confidence rationale | The request email is directly embedded between SQL quotes without binding. |
| Category | sql-injection |
| CWE | CWE-89 |
| Affected lines | routes/login.ts:32-35 |

#### Summary

An unauthenticated caller can change the login predicate and authenticate as another user.

#### Root Cause

Authentication uses string-built SQL instead of a parameterized ORM query.

**Raw login SQL** — `routes/login.ts:34`

email becomes SQL syntax.

```typescript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`
```

#### Validation

POST /rest/user/login is public and no upstream middleware sanitizes email.

#### Dataflow

email body -\> template literal -\> sequelize.query

#### Reachability

Public route.

#### Severity

**Critical** — Remote account takeover, including administrator accounts, is directly reachable.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Use a parameterized query or UserModel.findOne.

<a id="finding-3"></a>

### [3] Basket operations do not enforce ownership

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | The lookup uses only req.params.id although token-bound bid is available. |
| Category | broken-access-control |
| CWE | CWE-639 |
| Affected lines | routes/basket.ts:15-31, routes/order.ts:32-36 |

#### Summary

Any customer can read or mutate another customer's basket by selecting its id.

#### Root Cause

Authentication is enforced but object ownership is not.

**ID-only basket lookup** — `routes/basket.ts:18-19`

User ownership is absent from the predicate.

```typescript
const id = req.params.id; BasketModel.findOne({ where: { id } })
```

#### Validation

Middleware authenticates but never compares req.params.id with user.bid.

#### Dataflow

attacker basket id -\> ID-only lookup -\> victim object

#### Reachability

Any customer.

#### Severity

**High** — Ordinary customers cross account boundaries to expose and mutate orders.

Additional runtime or deployment evidence could raise or lower this severity.

#### Remediation

Require the path basket id to equal the token-bound basket id and retain ownership in database predicates.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Authentication and SQL construction | not recorded | Reported | No additional canonical notes were recorded. |
| Customer object ownership | not recorded | Reported | No additional canonical notes were recorded. |
| Server-side URL retrieval | not recorded | Reported | No additional canonical notes were recorded. |
| Upload parsing and filesystem writes | not recorded | Reported | No additional canonical notes were recorded. |
| Frontend injection surfaces | not recorded | Needs follow-up | No additional canonical notes were recorded. |

## Open Questions And Follow Up

- Which training vulnerabilities are included in the hidden rubric?
  - Follow-up prompt: Use scorer feedback from the authorized PR to prioritize remediation.
- Frontend was sampled but not exhaustively reviewed.
  - Follow-up prompt: Review deferred unit frontend_deferred and close its stated proof gap. Paths: frontend/src/. Surfaces: frontend.
