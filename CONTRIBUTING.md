# Contributing Guide

Thanks for your interest in contributing to the Auth Service. This guide outlines how to report issues, propose enhancements, and submit patches.

## Getting Started

1. Read `plan.md` to understand scope and roadmap.
2. Install Go 1.22+, PostgreSQL, and Redis.
3. Copy `config/example.env` (once available) to set local environment variables.
4. Run `go generate ./internal/ent` after any schema changes.

## Development Workflow

1. Fork/branch from `main`.
2. Write clear, focused commits with meaningful messages.
3. Ensure `go fmt`, `golangci-lint`, and `go test ./...` pass.
4. Update documentation (`plan.md`, `docs/erd.md`, README) when behaviour changes.
5. Submit a pull request referencing related issues or product requirements.

## Code Style & Quality

- Follow standard Go conventions (gofmt, gofumpt optional).
- Keep functions small and cohesive; prefer dependency injection over global singletons.
- Provide table-driven tests for business logic and integration tests using Testcontainers when external dependencies are touched.
- Use `context.Context` for request-scoped operations and cancellation.

## Commit Guidelines

- Prefix commits with context where helpful (e.g., `auth:`, `mfa:`).
- Reference Jira/Trello IDs if applicable.
- Avoid squashing unrelated changes into a single commit.

## Issue Reporting

- Include environment details, replication steps, expected vs actual behaviour.
- Attach logs/traces (redacted) when reporting production incidents.
- Tag severity (bug/enhancement/chore/security).

## Security

- Do not share secrets or private keys in pull requests.
- Report vulnerabilities privately via the process in `SECURITY.md`.

## Communication

- Engineering sync channel: `#bengobox-auth`.
- Weekly stand-up: Monday 10:00 EAT.
- Architecture decisions recorded in ADRs (`docs/`).

We appreciate your contributions and collaboration!

