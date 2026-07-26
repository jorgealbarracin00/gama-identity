# gama-identity

`gama-identity` is the operational identity service for the GAMA Platform. An
independent product can register a human, authenticate with email and password,
receive and validate a session, and log out. Persistence is deliberately
in-memory in this milestone.

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
Replacing the in-memory repositories does not require changes to domain or
application code.

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

Returns `201` with the new `humanIdentityId` and session metadata. Registration
uses compensating cleanup with the in-memory adapters so it cannot leave a
partially registered account.

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

Returns service name, version, and running status. `GET /` remains an equivalent
health endpoint.

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
npm start
```

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

The server binds to `0.0.0.0` and reads Railway's `PORT`. No database variables
are required. Because storage is in-memory, accounts and sessions are local to
one running process and are lost when that process restarts.

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
