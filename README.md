# Auth Service (SSO Platform)

The Auth Service provides centralised authentication, authorisation, and session management for the BengoBox ecosystem.  
It exposes standards-compliant OAuth2/OpenID Connect flows to web, mobile, POS, logistics, inventory, treasury, and other platform services.

## Key Features

- Multi-tenant identity store with organisation-aware policies.
- OAuth2/OIDC provider (Authorization Code + PKCE, Device Code, Client Credentials, Refresh Token).
- Social sign-in (Google, Microsoft, Apple, GitHub) with account linking.
- MFA (TOTP, WebAuthn roadmap), adaptive risk-based challenges, device trust.
- Session management, logout propagation, token revocation, JWKS discovery.
- Client registry APIs and admin console for scopes, secrets, and tenant security policies.
- Usage metering and entitlement checks integrated with the treasury service.

## Tech Stack

- Go 1.22+, Ent ORM, PostgreSQL, Redis.
- HTTP transport via `chi`, OAuth/OIDC libraries (`go-oidc`, `golang.org/x/oauth2`).
- OpenAPI/Swagger docs, ConnectRPC (optional) for internal services.
- Observability: zap logging, Prometheus metrics, OpenTelemetry traces.

## Local Development

```shell
# bootstrap dependencies
cp config/example.env .env
make deps

# run postgres/redis
docker compose up -d postgres redis

# generate Ent code & run service
go generate ./internal/ent
go run ./cmd/server
```

Endpoints default to `http://localhost:4101`. Adjust via `AUTH_HTTP_PORT`.

## Project Structure

- `cmd/` – binaries (`server`, `migrate`, `seed`).
- `internal/app` – service bootstrap, configuration, DI.
- `internal/ent` – Ent schema definitions and generated client.
- `internal/http` – handlers and middleware.
- `internal/oauth` – grant flows, token service.
- `internal/services` – domain logic (sessions, MFA, clients).
- `docs/` – architecture notes, ERD, integration playbooks.

## Integrations

- **Food Delivery / POS / Logistics / Inventory:** validate JWTs, consume `userinfo`, introspect tokens when required. Tenant/outlet discovery webhooks emitted here ensure each service hydrates metadata on login (polling not required).
- **Treasury:** receives metering events and returns feature entitlements for subscription plans.
- **Notifications:** delivers OTP and security alerts.

Refer to `docs/erd.md` and `plan.md` for module-level design.

## Status

- Planning phase – schema and integration design underway.
- See `CHANGELOG.md` for milestone history.

