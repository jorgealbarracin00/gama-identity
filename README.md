# gama-identity

`gama-identity` is the GAMA Platform service responsible for the Identity
architecture. This repository currently provides the production-oriented
service foundation: configuration, structured logging, HTTP composition,
health reporting, global error handling, the Human Identity domain, and the
Email Credential domain foundation.

## Technology

- Node.js 22 LTS
- TypeScript
- Fastify
- Zod
- Pino
- dotenv

## Folder structure

```text
src/
├── api/             # Fastify application composition and HTTP error handling
├── authentication/  # Email Credential domain, use cases, and ports
├── config/          # Environment and package metadata configuration
├── health/          # Service health HTTP route
├── identity/        # Human Identity domain, use cases, and ports
├── sessions/        # Session module boundary
├── shared/          # Shared errors and structured logger
└── server.ts        # Process entry point
```

## Local development

Node.js 22 is required.

```bash
npm install
cp .env.example .env
npm run dev
```

The service listens on `PORT` and binds to `0.0.0.0`, making the same startup
configuration suitable for local use and Railway.

## Available scripts

- `npm run dev` — run the service in watch mode
- `npm run build` — compile TypeScript into `dist/`
- `npm start` — run the compiled service
- `npm run typecheck` — validate TypeScript without emitting files
- `npm test` — run the domain and application unit tests

`GET /` returns the service name, package version, and running status.

## Human Identity

A Human Identity is the stable representation of a human principal. It owns
only its opaque identifier, lifecycle state, and lifecycle timestamps.
Credentials, authentication, sessions, authority, tenant membership, product
profiles, and personal profile data are deliberately outside this aggregate.

Lifecycle states are `active`, `suspended`, and `retired`. New identities are
active. Suspension and reactivation are idempotent when already in their target
state. Retirement is terminal.

Application use cases load and save complete aggregates through the
`HumanIdentityRepository` abstraction. The contract is independent of any
database technology.

## Email Credentials

Email Credentials are authentication mechanisms associated with Human
Identities. They contain normalized email credential data, a protected password
hash, independent lifecycle state, and timestamps. They do not modify Human
Identity, grant authority, or create sessions.

Email normalization preserves the local part and lowercases the domain, so
local-part case is significant for uniqueness. No provider-specific dot,
alias, or domain rewriting is performed.

New credentials are `active`; they may be `disabled` or permanently `retired`.
Retired credentials release their normalized email for reuse. Password inputs
must contain 12–128 characters and are validated separately from the
technology-independent hashing and verification ports.

Repository implementations must enforce one non-retired credential per
normalized email. Application operations expose safe metadata and never return
password hashes.
