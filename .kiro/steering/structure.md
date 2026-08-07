# Project Structure

## Organization Philosophy

Layered-by-type at the top level (routes / models / lib / data / views), not feature-first. The backend is a fairly flat Express app; the Angular frontend (under `frontend/`) is its own self-contained project with standard Angular feature-module organization.

## Directory Patterns

### API Routes
**Location**: `/routes/`
**Purpose**: One file per Express route/endpoint (e.g. `login.ts`, `order.ts`, `2fa.ts`, `resetPassword.ts`). Route handlers call into `lib/insecurity.ts` for auth/crypto helpers and into Sequelize models for persistence.
**Example**: `routes/login.ts` builds a raw SQL-flavored password check via `security.hash(...)` from `lib/insecurity.ts`.

### Data Models
**Location**: `/models/`
**Purpose**: Sequelize model definitions (one file per table/entity: `user.ts`, `card.ts`, `securityAnswer.ts`, `challenge.ts`, etc.) plus `index.ts` wiring associations.
**Example**: `models/user.ts` defines a Sequelize setter that hashes passwords on write.

### Shared Backend Utilities
**Location**: `/lib/`
**Purpose**: Cross-cutting helpers — `insecurity.ts` (auth/crypto — the single most security-relevant file in the repo), `utils.ts` (misc helpers incl. CTF flag signing, random strings), `challengeUtils.ts` (challenge-solved tracking), `logger.ts`, `startup/` (bootstrap sequencing).
**Example**: `lib/insecurity.ts` exports `hash`, `hmac`, `isAuthorized`, `verify`, `denyAll`.

### Seed / Static Data
**Location**: `/data/`
**Purpose**: `datacreator.ts` seeds the SQLite DB on startup; `data/static/*.yml` holds fixture data (users, products, security questions) — including intentionally weak/cleartext seed credentials.
**Example**: `data/static/users.yml` lists seed accounts with cleartext or trivially-encoded passwords.

### Frontend (Angular SPA)
**Location**: `/frontend/src/app/`
**Purpose**: Standard Angular app structure — one directory per component/page (kebab-case dirs, e.g. `two-factor-auth-enter/`), guards (`app.guard.ts`), and services. Builds independently via its own `package.json`/`angular.json` into `frontend/dist`, which the backend serves as static assets.

### Config
**Location**: `/config/`
**Purpose**: YAML environment configs (`default.yml`, plus overrides) validated against `config.schema.yml`. Can contain sensitive-looking but intentionally-fake answers/secrets used by challenges — do not treat as real secrets to redact/rotate.

## Naming Conventions

- **Backend files**: camelCase filenames matching the exported symbol (`insecurity.ts`, `challengeUtils.ts`)
- **Routes**: named after the endpoint/feature they implement, one Express handler factory per file, typically `export function <name> () { return (req, res) => {...} }`
- **Frontend components/dirs**: kebab-case directory + Angular CLI suffix convention (`*.component.ts`, `*.guard.ts`, `*.service.ts`)
- **Challenges**: referenced by camelCase challenge keys ending in `Challenge` (e.g. `weakPasswordChallenge`, `jwtForgedChallenge`) defined in `models/challenge.ts` and checked via `challengeUtils.solve(...)`

## Import Organization

```typescript
// Backend: relative imports, no path aliases
import { challenges } from '../data/datacreator'
import * as security from '../lib/insecurity'
```

**Path Aliases**: None on the backend (plain relative imports). Frontend uses Angular's default project-relative imports.

## Code Organization Principles

- Route handlers are thin: parse request → call a `lib/` helper or Sequelize model → respond. Business/security logic (hashing, token verification, coupon decoding) lives in `lib/insecurity.ts` / `lib/utils.ts`, not scattered across routes.
- Vulnerabilities are traceable: a security-relevant code path almost always has a matching entry in `models/challenge.ts`; when analyzing or modifying such code, check that mapping first to understand intent before assuming it's an accidental defect.

---
_Document patterns, not file trees. New files following patterns shouldn't require updates_
