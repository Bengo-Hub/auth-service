# Changelog

All notable changes to the Auth Service will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2025-11-14
### Added
- Sprint 2 token service delivering RSA-signed JWT access tokens, opaque refresh tokens with rotation, and `/api/v1/auth/refresh` + `/api/v1/auth/me` endpoints.
- Chi-based auth middleware wiring bearer validation on protected routes.
- Session persistence (Ent `sessions` schema) with client metadata, rotation logic, and audit coverage.

### Changed
- Registration/login handlers now emit token pairs together with user/tenant payloads.

## [0.4.0] - 2025-11-14
### Added
- Sprint 3 Google OAuth integration with signed state tokens, configurable provider metadata, and allowed-domain enforcement.
- Ent `user_identities` schema plus persistence for access/refresh tokens, verified email flag, and profile metadata.
- `/api/v1/auth/oauth/google/start` + `/callback` endpoints with handler/service wiring, plus OAuth helper utilities.

### Changed
- Auth service now auto-links/creates users from provider profiles, ensures tenant membership, and updates README/config docs for social login setup.

## [0.2.0] - 2025-11-14
### Added
- Sprint 1 local auth flows: registration, login, password reset request/confirmation, audit logging, login attempt tracking.
- Argon2id password hashing helper with configurable policy enforcement.
- REST handlers plus request/response envelopes and validation for `/api/v1/auth/*`.

### Changed
- Tenant memberships enforced during login/password reset to prevent cross-tenant leakage.

## [0.1.0] - 2025-11-14
### Added
- Sprint 0 foundations: service bootstrap (`cmd/server` + `internal/app`), typed config loader, zap logging, Chi router with health endpoint.
- Postgres/Redis clients, Ent schema for core identity + audit tables, and automated migrations.
- Token service scaffolding with RSA key loading utilities.

