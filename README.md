# gama-identity

`gama-identity` is the initial single-runtime GAMA Platform control plane. It
provides Human Identity, authentication, sessions, and the minimum Product,
Tenant, workforce-entitlement and Product Workload control-plane capabilities.
It does not contain Product business-domain logic. PostgreSQL is the production
persistence implementation; deterministic in-memory adapters remain available
for tests and lightweight development.

## Architecture

The service keeps four boundaries independent:

```text
Human Identity ─┬→ Email Credential ───────┐
                └→ Federated Identity ─────┴→ Authentication Result → Session
                                                                      ↓
                                            Product / Tenant / Workload Control Plane
```

- **Human Identity** owns only the stable principal ID and its lifecycle.
- **Email Credential** belongs to a Human Identity and owns normalized email,
  protected password material, and credential lifecycle.
- **Federated Identity** belongs to a Human Identity and is uniquely identified
  by provider plus verified provider subject. Optional provider email is metadata,
  never identity or password authority.
- **Authentication** is an application service. It does not create identities
  or sessions.
- **Session** owns authenticated continuity and its own lifecycle. It does not
  own or repeat authentication.
- **Registration and login** are orchestration use cases that coordinate these
  boundaries without exposing their aggregates.
- **HTTP** parses requests and translates results and errors only.
- **Control Plane** owns registered Products, Tenants, workforce membership,
  canonical Tenant Workforce Role assignment, Product Participation, Product
  Entitlement, Product Workloads and Platform-security audit. Products remain
  responsible for mapping validated Tenant roles to Product-specific capabilities.

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
- `federated_identities` stores provider-neutral authentication relationships;
  `federated_authentication_nonces` stores only consumed nonce hashes for replay
  protection.
- `sessions` stores the owning identity reference, lifecycle, access time, and
  fixed expiry.
- `registered_products`, `tenants`, `tenant_memberships`,
  `product_participations` and `product_entitlements` store the minimum
  workforce control plane.
- `tenant_provisioning_requests` binds administrative request UUIDs to one
  stable Tenant and initial Owner, making ambiguous retries safe.
- `product_workloads` stores a Product Workload identity and only a protected
  workload-secret hash.
- `platform_audit_events` stores Platform-security and administrative events.
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

Sign in with Apple is the first federated provider. GAMA verifies Apple's signed
identity token, issuer, configured audience, expiration and nonce against Apple's
rotating public keys, then resolves `(provider, providerSubject)`. Unknown Apple
subjects create a new canonical Human transactionally; matching email never
silently links an existing account. An authenticated Human may explicitly connect
Apple by proving both its ordinary GAMA session and a fresh verified Apple
credential. A separate resolve-only boundary can verify a provider credential
and disclose only whether its exact provider/subject relationship already
exists, without creating a Human, relationship, or session. See
[`docs/FEDERATED_AUTHENTICATION.md`](docs/FEDERATED_AUTHENTICATION.md).

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

### `POST /authentication/federated/apple`

Accepts only an Apple identity token and its raw one-time nonce. The server
cryptographically verifies Apple and returns the same ordinary opaque GAMA
session contract. It does not accept a subject, email, Human Identity ID, or any
authorization relationship from the caller.

### `POST /authentication/federated/:provider/resolve`

Accepts the same strict provider credential body and consumes its verified nonce
once. Returns only `{ "outcome": "EXISTING" }` when the exact provider/subject
relationship exists (including disabled or retired history), or
`{ "outcome": "UNLINKED" }` otherwise. It never creates a Human, relationship,
or session and never returns identity, provider-subject, email, or authority
data.

### `GET /authentication/methods`

Requires an ordinary GAMA bearer session and returns that Human's safe,
provider-neutral sign-in-method projection. Provider subjects, tokens and nonce
material are never returned.

### `POST /authentication/federated/:provider/link`

Requires an ordinary GAMA bearer session plus the same strict verified-provider
credential body used by federated sign-in. The session selects the target Human;
the verified token selects the provider identity. The request cannot select a
Human, subject, email, Tenant, Product, role or grant. Outcomes are `linked`,
`already_linked`, or the deliberately narrow `reconciled` result described in
the federated-authentication design document.

### `DELETE /authentication/federated/:provider/link`

Disables the active provider relationship without deleting its Human or changing
authorization. The operation is idempotent and rejects removal of the last usable
authentication method. Coco currently exposes Connect Apple but defers the
reauthentication-sensitive disconnect action.

### `GET /session`

Validates the bearer session and touches its last-access time. Returns `200`
with authenticated session metadata. Invalid, expired, and revoked sessions
return `401` with an explicit session error code.

### `POST /logout`

Revokes the bearer session and returns `204`. Repeated logout is successful.

### `GET /control/workforce-context`

Requires a valid Human bearer session plus `tenantId` and `productId` query
parameters. It succeeds only when the authenticated Human has active Tenant
Membership, Product Participation and Product Entitlement for the requested
workforce context. A `403 WORKFORCE_CONTEXT_REQUIRED` response does not revoke
or otherwise invalidate the Human's GAMA authentication.

A successful context includes `membershipStatus` and the canonical `tenantRole`
(`owner`, `admin` or `staff`) read from the server-owned Tenant Membership.
Existing consumers may ignore these additive fields. Products decide what the
validated role permits for Product-owned capabilities.

## Workforce administration boundaries

`WorkforceAdministration` is the authoritative application service for Human
lookup, Tenant workforce listing, Product workforce grants, Tenant role changes,
Product-only revocation and Tenant membership revocation. A grant is idempotent
and establishes the independent Tenant Membership, Product Participation and
Product Entitlement required by workforce context. Role mutation preserves the
membership key `(tenantId, humanIdentityId)`.

Final-owner demotion and revocation execute in the same PostgreSQL transaction
as a lock over the Tenant's memberships. Tenant removal suspends that person's
Tenant Membership and Tenant-scoped Product Entitlements; it does not delete the
Human Identity, another Tenant relationship or customer data. Security-relevant
changes append Platform audit events, including role transition data.

`WorkforceAdministration` remains internal business logic. It is callable over
HTTP only through two explicit authenticated adapters; `actorReference` remains
audit attribution and is never accepted as authentication.

### Platform administration

A Platform administrator authenticates with an ordinary opaque GAMA Human
session. The service checks both the active Human Identity and the current
`platform_administration_memberships` row on every request. The only MVP
Platform role is the explicitly named `administrator`; Tenant `owner`, `admin`
and `staff` never imply it. The Platform boundary supports:

- `GET /administration/platform/tenants`
- `POST /administration/platform/tenants`
- `GET /administration/platform/products`
- `GET /administration/platform/tenants/:tenantId/products`
- `PUT /administration/platform/tenants/:tenantId/products/:productId`
- `GET /administration/platform/identities/resolve?email=...`
- `GET /administration/platform/tenants/:tenantId/team`
- `GET /administration/platform/tenants/:tenantId/team/:humanIdentityId`
- `POST /administration/platform/tenants/:tenantId/team`
- `PATCH /administration/platform/tenants/:tenantId/team/:humanIdentityId/role`
- `DELETE /administration/platform/tenants/:tenantId/team/:humanIdentityId/products/:productId`
- `DELETE /administration/platform/tenants/:tenantId/team/:humanIdentityId`

Platform administrators have all-Tenant scope in this initial model. Requested
Tenants and Products are still checked against authoritative GAMA records.

Tenant provisioning requires a client-generated UUID `idempotencyKey`, a
`displayName`, and an existing active `initialOwnerHumanIdentityId`. GAMA
generates the opaque Tenant ID and atomically creates the Tenant and canonical
Owner Membership. An identical retry returns the original resource without a
duplicate audit event; different input under the same request key is rejected.
Display name is presentation data and never becomes the stable Tenant key.

The Product directory exposes only ID, display name and lifecycle status. The
Tenant Product routes project and manage the existing Product Participation,
which is the Human-independent `(tenantId, productId)` relationship. Team
projections add safe account email, nullable display name, Human lifecycle,
Membership role/status and per-Product Participation/Entitlement status. Human
Identity ID remains authoritative; email remains lookup/display only.

### Tenant Team administration

The Team boundary requires both a Human bearer session and an authenticated
Product Workload (`x-gama-workload-id` and `x-gama-workload-secret`). The Product
comes from the authenticated workload. `x-gama-tenant-id` is trusted only as a
server-to-server context established by the Product backend; it must never be
copied from a mobile/public client request. GAMA derives the acting Tenant
Workforce Principal from current Human Identity, Membership, role,
Participation and Entitlement state.

The Team routes are:

- `GET /administration/team`
- `POST /administration/team` with only `email` and `tenantRole`
- `PATCH /administration/team/:humanIdentityId/role`
- `PUT /administration/team/:humanIdentityId/product-access`
- `DELETE /administration/team/:humanIdentityId/product-access`
- `DELETE /administration/team/:humanIdentityId`

No Team request accepts a Tenant ID or Product ID in its public payload. Owner
may manage Admin and Staff. Admin may add/remove Staff and manage Staff access.
Staff cannot administer Team. Self-mutation and all Tenant-side Owner creation,
demotion or removal are rejected; additional Owner and ownership transfer are
Platform-administration operations for the MVP.

### `GET /control/workload-context`

Requires `x-gama-workload-id` and `x-gama-workload-secret` request headers.
It authenticates an active Product Workload and returns its stable workload and
Product identifiers. It is the minimum server-to-server identity validation
contract for a future Product backend. It never grants Product-domain authority.

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

Migration `003_tenant_workforce_roles.sql` adds constrained Tenant roles,
membership timestamps and structured audit event data. Existing memberships
receive `staff`, preserving their workforce eligibility without granting
ownership. Deploy the migration-capable runtime before any Console integration,
establish at least one canonical owner through controlled Platform
administration, verify role-bearing workforce context, and only then allow
Product backends to rely on `tenantRole`.

Migration `004_administration_principals.sql` adds the distinct, GAMA-owned
Platform administration membership. Apply migrations before enabling either
administration adapter. Provisioning the first administrator remains an
explicit operator action; no login, email, Firebase role or Tenant role can
bootstrap Platform authority.

Migration `005_platform_tenant_provisioning.sql` adds the durable idempotency
ledger for atomic Tenant and initial-Owner provisioning. It requires no Product
backfill: existing `product_participations` already represent the canonical
Tenant/Product association. Applying this migration to an environment is a
separate deployment operation.

Migration `006_federated_identities.sql` additively creates the provider-neutral
FederatedIdentity and consumed-nonce tables. It requires no backfill and changes
no existing identity, credential, session, workforce, Platform Administration,
or Coco relationship. Applying it to any environment is a separate deployment
operation.

Migration `007_federated_account_linking.sql` adds the partial unique index that
permits at most one active relationship for each `(humanIdentityId, provider)`.
It does not reassign relationships or mutate any Human, credential, session,
workforce, Platform Administration or Product-domain record. Applying it to an
environment is a separate deployment operation.

Migration `008_federated_email_discovery.sql` adds a partial, case-insensitive
index over verified email metadata on active federated relationships. It changes
no identity ownership and grants no authority. Platform/Tenant administrators may
use that metadata to discover a safe canonical Human projection; ambiguous email
evidence fails closed and canonical Human ID remains the unambiguous fallback.
Applying it is a separate deployment operation and must precede a runtime that
depends on the indexed discovery path.

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
| `SESSION_DURATION_SECONDS` | `86400` | Short-lived bearer session duration |
| `SESSION_RENEWAL_DURATION_SECONDS` | `2592000` | Rotating renewable-session duration; must exceed bearer duration |
| `REPOSITORY_MODE` | `memory` | `memory` or `postgres` infrastructure |
| `DATABASE_URL` | — | Required in PostgreSQL mode |
| `DATABASE_SSL` | `disable` | `disable` or `require` |
| `APPLE_CLIENT_IDS` | — | Comma-separated public native App ID and web Services ID audience allowlist; Apple exchange fails closed when absent |
| `APPLE_WEB_CLIENT_ID` | — | Services ID used for the Apple web authorization-code flow; configure with all Apple web values |
| `APPLE_WEB_REDIRECT_URI` | — | Exact registered HTTPS return URL for the Apple web flow |
| `APPLE_TEAM_ID` | — | Apple Developer Team ID used only to sign the server-side client secret |
| `APPLE_KEY_ID` | — | Sign in with Apple key identifier used only by GAMA |
| `APPLE_PRIVATE_KEY` | — | Sign in with Apple private key stored only in the runtime secret environment |

The following inputs are used only by the operator-only Coco bootstrap command
and have no defaults: `COCO_OWNER_HUMAN_IDENTITY_ID`, `COCO_WORKLOAD_SECRET`,
and `COCO_BOOTSTRAP_ACTOR_REFERENCE`.

`PLATFORM_ADMIN_HUMAN_IDENTITY_ID` and
`PLATFORM_ADMIN_BOOTSTRAP_ACTOR_REFERENCE` are used only by the explicit
Platform-administrator bootstrap command described below.

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

## Coco development bootstrap

After an active owner Human Identity has been created in the PostgreSQL-backed
GAMA runtime, an operator establishes the Phase 1 Coco control plane using:

```bash
REPOSITORY_MODE=postgres \
COCO_OWNER_HUMAN_IDENTITY_ID=<active-human-identity-id> \
COCO_WORKLOAD_SECRET=<new-secret-of-at-least-24-characters> \
COCO_BOOTSTRAP_ACTOR_REFERENCE=<platform-operator-reference> \
npm run bootstrap:coco
```

The bootstrap is transactional and creates or refreshes the stable records
`coco-the-llama`, `coco-backend`, and `coco-development`, together with the
owner's workforce relationships. It records Product registration, workload
identity establishment, Tenant Membership, Product Participation and Product
Entitlement in Platform audit only when the corresponding state changes;
repeating the same bootstrap is an audit-clean no-op. The workload secret is
stored only as a hash and
must be placed into the future Coco backend's secret configuration manually.
Customers are never created as Tenant members by this command.
The explicitly supplied bootstrap owner receives Tenant role `owner`; this does
not elevate other existing memberships.

## Platform administrator bootstrap

After migration `004` and after the intended administrator already has an
active GAMA Human Identity, an authorized deployment operator runs:

```bash
REPOSITORY_MODE=postgres \
PLATFORM_ADMIN_HUMAN_IDENTITY_ID=<active-human-identity-id> \
PLATFORM_ADMIN_BOOTSTRAP_ACTOR_REFERENCE=<accountable-operator-reference> \
npm run bootstrap:platform-admin
```

The command is transactional, idempotent and audited. It is not an HTTP route,
does not accept email as authority, does not promote the first login, and does
not depend on Console Firebase state. Suspension or retirement of the stored
membership removes Platform authority on the next request even if the Human's
GAMA session remains active.

## Security decisions

- Passwords use a mature Argon2id implementation behind the existing port.
- Passwords, password hashes, and secrets are never returned or deliberately
  logged.
- Authentication failures have one public response to resist enumeration.
- Session and entity IDs are cryptographically random UUIDs in production.
- Request configuration is validated at the boundary; domain rules remain in
  their owning domains.
- External provider subjects are accepted only from cryptographically verified
  tokens. Provider email is metadata and never triggers account linking.
- Federated nonces are verified against the signed token and consumed once; raw
  nonces and provider tokens are not persisted or deliberately logged.
- Linking derives the target Human only from the authenticated GAMA session and
  never from provider email. Reconciliation is limited to a signed-out,
  federated-only active duplicate with no credential history, other provider
  relationship, live session, Tenant membership, Product Entitlement or Platform
  authority visible to GAMA. It retires the duplicate, revokes its sessions and
  moves only the verified provider relationship; it never merges Coco data.
- Repository reads return copies so callers cannot mutate persisted state
  outside repository operations.
- All SQL uses parameterized values.
- Product Workload secrets are hashed and are required explicitly; network
  location and Product identity alone do not authenticate a workload.
- The public runtime exposes no bootstrap endpoint and contains no Coco
  authorization bypass.
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
