# Technology Stack

## Architecture

Monolithic Node.js/Express backend serving a separately-built Angular SPA frontend. Backend and frontend are two independent npm projects (`/` and `/frontend`) built and bundled together (`npm run build` builds frontend then compiles the server with `tsc`).

## Core Technologies

- **Language**: TypeScript (backend: CommonJS/ES2020 target, strict mode; frontend: Angular's own TS config)
- **Backend framework**: Express 4
- **Frontend framework**: Angular (standalone, current major version), RxJS
- **ORM / DB**: Sequelize 6 over SQLite3 (models in `models/`)
- **Runtime**: Node.js

## Key Libraries

- `express-jwt` + `jsonwebtoken` / `jws` for auth (note: pinned to very old versions — see `lib/insecurity.ts`, this is intentional, not a dependency to "helpfully" upgrade)
- `sequelize` for all data access (models in `models/`, seed data in `data/datacreator.ts` + `data/static/*.yml`)
- `i18next` for backend i18n, `ngx-translate` on the frontend
- Swagger/OpenAPI-style docs and a CTF scoring GitHub Action (`.github/workflows`)

## Development Standards

### Type Safety
Backend `tsconfig.json` has `strict: true`. Frontend uses Angular's standard strict template checking. Despite strict mode, several files intentionally use loose/`any` casts around auth code (`lib/insecurity.ts`) — this is part of the vulnerability, not an oversight to clean up.

### Code Quality
ESLint via flat config (`eslint.config.mjs`) at the root for backend TS (`data`, `lib`, `models`, `routes`, `test/**/*.ts`, `views`); frontend has its own lint config under `frontend/`.

### Testing
- Backend: unit/API tests under `test/` (Mocha/Chai style, see `npm test` scripts in `package.json`)
- Frontend: Vitest unit tests (`ng test`, Angular's `@angular/build:unit-test` builder), Cypress for E2E (`cypress.config.ts`, `test/cypress/`)

## Development Environment

### Required Tools
Node.js + npm. `postinstall` automatically installs and builds the frontend.

### Common Commands
```bash
# Dev (backend, watch mode via tsx): npm run serve:dev
# Run precompiled build (no live reload): npm start
# Build: npm run build   (build:frontend then build:server)
# Test (backend): npm test
# Lint: npm run lint
```

## Key Technical Decisions

- Vulnerable-by-design: cryptographic primitives, auth logic, and input handling in `lib/insecurity.ts` and `routes/*` intentionally use weak/broken patterns (MD5 password hashing, hard-coded JWT signing key, unrestricted JWT `algorithms`, `Math.random()` for security-sensitive values). Treat these as spec, not bugs, unless the user is explicitly working a "fix this vulnerability" task.
- Each vulnerability is registered as a named entry in `models/challenge.ts` and checked via `lib/challengeUtils.ts` — when touching security-relevant code, check whether a challenge references that code path before changing behavior.

---
_Document standards and patterns, not every dependency_
