# gama-identity

`gama-identity` is the operational identity service for the GAMA Platform. An
independent product can register a human, authenticate with email and password,
receive and validate a session, and log out. PostgreSQL is the production
persistence implementation; deterministic in-memory adapters remain available
for tests and lightweight development.

## Architecture

The service keeps four boundaries independent:

```text
Human Identity → Email Credential → Authentication Result → Session
```

- **Human Identity** owns only the stable principal ID and its lifecycle.
- **Email Credential** belongs to a Human Identity and owns normalized email,
  protected password material, and credential lifecycle.
- **Authentication** is an application service. It does not create identities
  or sessions.
- **Session** owns authenticated continuity and its own lifecycle. It does not
  own or repeat authentication.
- **Registration and login** are orchestration use cases that coordinate these
  boundaries without exposing their aggregates.
- **HTTP** parses requests and translates results and errors only.

Ports isolate all repositories, password operations, time, and ID generation.
The composition root selects in-memory or PostgreSQL infrastructure without
changing domain or application code.

## Persistence architecture

```text
Domain → Application → Repository contracts → Infrastructure
                                             ├── In-memory
                                             └── PostgreSQL
```

PostgreSQL uses one shared connection pool and one transaction context. SQL is
confined to `src/infrastructure/postgres`. Repository rows are reconstituted
into full aggregates before crossing the infrastructure boundary.

The relational schema preserves aggregate boundaries:

- `human_identities` stores Human Identity lifecycle state and timestamps.
- `credentials` stores the owning identity reference, normalized email,
  password hash, credential lifecycle, and timestamps.
- `sessions` stores the owning identity reference, lifecycle, access time, and
  fixed expiry.
- `schema_migrations` records applied migration versions and checksums.

A partial unique index permits only one non-retired credential to claim a
normalized email. Foreign keys preserve identity references without merging the
aggregates into a users table. Identifier columns remain opaque text at the
storage boundary; production generates UUIDs, while repository contracts do not
depend on UUID semantics.

## Authentication flow

Authentication normalizes the email, looks up the active credential, verifies
the password through the hashing port, then loads and checks the Human Identity.
Its explicit internal results are `success`, `invalid_credentials`,
`credential_unavailable`, and `identity_unavailable`.

Login deliberately maps all unsuccessful authentication outcomes to the same
public `INVALID_CREDENTIALS` response so callers cannot discover whether an
email, credential, or identity exists.

Passwords are hashed in production with Argon2id. Tests use deterministic
password doubles and never weaken the production adapter.

## Session flow

A successful registration or login creates a fixed-duration active session.
The session records:

- opaque session ID
- Human Identity ID
- creation and last-access timestamps
- expiry
- `active`, `expired`, or `revoked` status

Successful validation updates `lastAccessedAt` but does not extend expiry.
Validation distinguishes authenticated, expired, revoked, and invalid sessions.
Logout is idempotent and revokes the supplied session.

Sessions are bearer credentials. Clients must store and transmit their session
IDs securely.

## HTTP API

JSON requests use `Content-Type: application/json`. Session endpoints use:

```http
Authorization: Bearer <sessionId>
```

### `POST /register`

Request:

```json
{
  "email": "person@example.com",
  "password": "a-password-of-at-least-12-characters"
}
```

Returns `201` with the new `humanIdentityId` and session metadata. In PostgreSQL
mode the complete identity, credential, authentication, and session sequence
runs in one database transaction. Any failure rolls back every write.

### `POST /login`

Accepts the same request shape. Returns `200` with session metadata, or `401`
with the uniform `INVALID_CREDENTIALS` error.

### `GET /session`

Validates the bearer session and touches its last-access time. Returns `200`
with authenticated session metadata. Invalid, expired, and revoked sessions
return `401` with an explicit session error code.

### `POST /logout`

Revokes the bearer session and returns `204`. Repeated logout is successful.

### `GET /health`

Returns service name, version, running status, and a non-sensitive database
status: `connected`, `not_configured`, or `unavailable`. A database failure
returns `503` with `status: "degraded"`. `GET /` remains equivalent.

Errors have a stable envelope:

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password"
  }
}
```

## Local development

Node.js 22 LTS is required.

```bash
npm install
cp .env.example .env
npm run dev
```

Useful commands:

```bash
npm run typecheck
npm run build
npm test
npm run test:integration
npm start
```

### Local PostgreSQL

Create an empty PostgreSQL database, then configure:

```dotenv
REPOSITORY_MODE=postgres
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/gama_identity
DATABASE_SSL=disable
```

Apply migrations explicitly with:

```bash
npm run migrate
```

Migrations also run during PostgreSQL-mode startup before the HTTP listener is
opened. They are ordered by numeric filename, recorded with SHA-256 checksums,
protected by a PostgreSQL advisory lock, and safe to run repeatedly. Never edit
an applied migration; add a new versioned migration instead.

PostgreSQL integration tests are isolated from the runtime connection variable:

```bash
POSTGRES_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/gama_identity_test npm run test:integration
```

The test database is truncated. Never point `POSTGRES_TEST_DATABASE_URL` at a
development or production database.

## Configuration

Configuration is validated with Zod at startup and fails fast when invalid.

| Variable | Default | Purpose |
| --- | ---: | --- |
| `PORT` | `3000` | HTTP listener port |
| `NODE_ENV` | `development` | Runtime environment |
| `LOG_LEVEL` | `info` | Structured log level |
| `PASSWORD_HASH_MEMORY_KIB` | `19456` | Argon2id memory cost |
| `PASSWORD_HASH_ITERATIONS` | `2` | Argon2id time cost |
| `PASSWORD_HASH_PARALLELISM` | `1` | Argon2id parallelism |
| `SESSION_DURATION_SECONDS` | `86400` | Fixed session duration |
| `REPOSITORY_MODE` | `memory` | `memory` or `postgres` infrastructure |
| `DATABASE_URL` | — | Required in PostgreSQL mode |
| `DATABASE_SSL` | `disable` | `disable` or `require` |

Memory mode loses accounts and sessions when the process restarts. PostgreSQL
mode fails startup if `DATABASE_URL` is absent, the connection cannot be
established, or migrations fail.

## Railway deployment

1. Add a PostgreSQL service to the Railway project.
2. Add `DATABASE_URL` to the identity service as a reference to the PostgreSQL
   service variable, normally `${{Postgres.DATABASE_URL}}`.
3. Set `REPOSITORY_MODE=postgres`, `NODE_ENV=production`, and the appropriate
   `DATABASE_SSL` mode for the selected Railway connection.
4. Build with `npm run build`.
5. Start the process directly with `node dist/server.js` so it receives
   `SIGTERM` and can close HTTP and database connections gracefully.
6. Configure `/health` as the deployment health endpoint.

The service continues to bind to `0.0.0.0` and Railway's `PORT`. Startup checks
the database and applies pending migrations before accepting traffic.

## Security decisions

- Passwords use a mature Argon2id implementation behind the existing port.
- Passwords, password hashes, and secrets are never returned or deliberately
  logged.
- Authentication failures have one public response to resist enumeration.
- Session and entity IDs are cryptographically random UUIDs in production.
- Request configuration is validated at the boundary; domain rules remain in
  their owning domains.
- Repository reads return copies so callers cannot mutate persisted state
  outside repository operations.
- All SQL uses parameterized values.
- Database URLs and connection errors are not returned by health endpoints.

## Release process

No release tags are created automatically.

The historical Milestone 1 deployment should be marked as the first public
operational deployment of GAMA Identity:

```bash
git tag v1.0.0
git push origin v1.0.0
```

After Milestone 1.1 has passed production verification, finalize the
`CHANGELOG.md` release date and publish:

```bash
git tag v1.1.0
git push origin v1.1.0
```

Version `v1.1.0` adds interchangeable PostgreSQL persistence without changing
the public identity API.
