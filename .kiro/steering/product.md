# Product Overview

OWASP Juice Shop is an intentionally insecure web application used for security training, awareness demos, CTFs, and as a benchmark target for security tooling (SAST/DAST/IAST). It is a fictional online juice shop (products, cart, checkout, reviews, admin panel) whose business logic is a vehicle for teaching real-world vulnerability classes.

## Core Capabilities

- E-commerce flows (product catalog, basket, checkout, coupons, payment, orders) implemented with realistic but exploitable logic
- A built-in scoreboard/challenge framework (`models/challenge.ts`, `lib/challengeUtils.ts`) that tracks which vulnerabilities a user has found and solved
- Deliberately vulnerable implementations mapped to OWASP Top 10 / CWE categories (auth, crypto, injection, XSS, access control, etc.), each tied to a named challenge
- Multi-language i18n support (`i18n/`) and a CTF export/scoring mode for competitions

## Target Use Cases

- Self-guided or instructor-led security training (finding and exploiting vulnerabilities)
- CTF competitions (this repo includes CTF scoring CI integration)
- Benchmarking security scanners and AI coding/security-review agents against known-vulnerable code

## Value Proposition

Every "bug" is intentional and traceable to a specific challenge and CWE/OWASP category — this is what distinguishes Juice Shop from an accidentally-buggy app. When working in this repo, do not "fix" a vulnerability unless the user explicitly asks for a fix/patch; the default assumption is that vulnerable code is the intended teaching content, not a defect to silently correct.

---
_Focus on patterns and purpose, not exhaustive feature lists_
