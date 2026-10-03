# Federated authentication

## Authority model

`HumanIdentity` remains GAMA's canonical person principal. Authentication
methods are independent relationships that establish which Human is signing in:

```text
                         HumanIdentity
                         /           \
          EmailCredential             FederatedIdentity
                                            |
                               provider + providerSubject
```

Every successful method issues the same opaque GAMA session. No provider token
is stored in a GAMA session or forwarded to Product APIs. Authentication does not
create Tenant Membership, Tenant role, Product Participation, Product
Entitlement, Workforce Context, Platform Administration Membership, Firebase
authority, or Product-domain capability.

The first boundary extended for federation is the authentication application
boundary. Before this change it depended directly on `EmailCredentialRepository`
and password verification. Human Identity creation, lifecycle checks, session
issuance, validation, restoration, and downstream authorization were already
provider-independent and remain unchanged.

## Provider-neutral relationship

`FederatedIdentity` stores:

- its own opaque relationship ID
- canonical `humanIdentityId`
- normalized provider name
- provider-issued subject
- optional provider-verified email metadata
- optional verified/private-email flags
- lifecycle status and timestamps

`(provider, providerSubject)` is unconditionally unique, including retired
relationships. A provider account can never be reassigned to another Human by
retiring and recreating a row. Provider email is not unique, is not an identity
key, and is never converted into an `EmailCredential`.

The schema and repository accept a future `provider = google` relationship.
Authentication succeeds only when a verifier is registered for that provider;
this release registers Apple only.

Apple web authentication extends the same boundary. The browser receives a
single-use authorization code for a Services ID associated with Coco
Companion's primary App ID. GAMA exchanges the code directly with Apple using
server-held credentials, verifies the resulting identity token, and enters the
same provider-subject mapping and session-creation path used by the native app.
No browser-supplied subject or email is trusted.

## Sign in with Apple verification

GAMA verifies Apple identity tokens server-side using a maintained JOSE
implementation and Apple's rotating public keys at
`https://appleid.apple.com/auth/keys`. Verification requires:

- a valid Apple JWS signature and matching key ID
- issuer `https://appleid.apple.com`
- an audience in `APPLE_CLIENT_IDS`
- required subject, issued-at, expiration, and nonce claims
- current time before expiration, with only a five-second clock tolerance
- nonce equality using a constant-time comparison

These checks follow Apple's official [Verifying a user](https://developer.apple.com/documentation/signinwithapple/verifying-a-user),
[public-key](https://developer.apple.com/documentation/signinwithapplerestapi/fetch-apple%27s-public-key-for-verifying-token-signature),
and [nonce](https://developer.apple.com/documentation/authenticationservices/asauthorizationopenidrequest/nonce)
contracts. GAMA never accepts a caller-provided Apple subject, Human Identity ID,
or email assertion.

## Nonce and replay protection

For the native flow, GAMAIdentityKit generates 32 random bytes and retains their
base64url representation as the raw nonce. It sends `base64url(SHA-256(rawNonce))`
in `ASAuthorizationAppleIDRequest.nonce`. The SDK sends the raw nonce and signed
identity token to GAMA over HTTPS.

GAMA hashes the supplied raw nonce, compares it with the signed Apple claim, then
atomically inserts `(provider, nonceHash)` into
`federated_authentication_nonces`. The primary key makes the nonce single-use,
including under concurrent requests. The raw nonce and identity token are never
persisted or deliberately logged.

## First and returning sign-in

After verification, GAMA resolves only `(provider, providerSubject)`.

- Existing active relationship + active Human: issue a new ordinary GAMA session.
- Unknown relationship: transactionally create one active Human, one active
  FederatedIdentity, consume the nonce, and issue the GAMA session.
- Suspended/retired Human or disabled/retired relationship: reject sign-in.

The PostgreSQL unique constraint plus transaction retry resolves concurrent first
sign-ins for one provider subject to the winning Human. In-memory execution is
serialized to preserve the same behavior.

## Resolve-only discovery

`POST /authentication/federated/:provider/resolve` is a provider-neutral,
unauthenticated discovery boundary for credential cutovers and other flows that
must determine whether an exact verified external identity is already known
without creating or linking identity state. It runs the registered provider's
full credential verifier, consumes the verified nonce once, takes the existing
provider/subject transaction lock, and performs the same unfiltered relationship
lookup used by identity persistence.

The result is only `EXISTING` or `UNLINKED`. `EXISTING` includes active,
disabled, and retired relationship history. The use case has no Human Identity
repository, ID generator, session service, account-linking service, or authority
repository dependency, so it cannot create a Human, issue a session, link or
change a relationship, infer identity from email, or alter Tenant/Product
authority. The replay ledger entry for a successfully verified nonce is its sole
persistent write.

## Apple email and explicit account linking

The optional signed Apple `email`, `email_verified`, and `is_private_email`
claims are stored only as provider metadata. A private relay address is retained
with `provider_email_private = true`. Missing email on a returning sign-in does
not erase metadata captured earlier.

If an unknown Apple subject carries an email matching an existing password
account, ordinary Apple sign-in still creates a new Human Identity. Email equality
never changes ownership.

Linking is a separate explicit ceremony. The caller supplies an ordinary GAMA
bearer session plus a fresh provider token and nonce. The session determines the
target Human, while cryptographic provider verification determines the provider
subject. The request schema rejects caller-supplied Human, subject, email, Tenant,
Product, role and grant fields.

An unowned provider subject is attached to the authenticated Human. A relationship
already owned by that Human is an idempotent success. A provider subject owned by
another Human returns a stable reconciliation conflict unless that source is an
active, signed-out, federated-only Human with no credential history, other
federated relationship, Tenant membership, Product Entitlement or Platform
Administration membership visible to GAMA. Under that narrow policy, GAMA revokes
the source's stale sessions, reassigns only the verified provider relationship,
and retires the source Human in one transaction. It does not copy or merge Coco
cart, order, preference or other Product-domain data. Any GAMA-visible authority
or relationship makes reconciliation fail closed for a higher-level recovery or
merge workflow.

Unlinking disables rather than deletes the relationship and refuses to remove the
last active authentication method. It never deletes the Human or changes Product,
Tenant, workforce or Platform authority.

## Public API

```http
POST /authentication/federated/apple
Content-Type: application/json

{
  "identityToken": "<Apple identity token>",
  "nonce": "<raw one-time nonce>"
}
```

Success returns the normal session payload plus safe optional account metadata:

```json
{
  "session": {
    "sessionId": "<opaque GAMA session>",
    "humanIdentityId": "<canonical GAMA Human ID>",
    "createdAt": "...",
    "lastAccessedAt": "...",
    "expiresAt": "..."
  },
  "account": {
    "email": "optional-provider-metadata@example.com"
  }
}
```

The client cannot supply `subject`, `email`, `humanIdentityId`, Tenant, Product,
role, or authorization fields. Strict request validation rejects additional
properties.

The companion website uses the server-to-server code exchange endpoint:

```http
POST /authentication/federated/apple/web
Content-Type: application/json

{
  "authorizationCode": "<single-use Apple code>",
  "nonce": "<raw one-time nonce>"
}
```

GAMA signs a five-minute ES256 client-secret JWT, exchanges the code at Apple's
token endpoint using the configured Services ID and exact return URI, and then
performs the same issuer, audience, signature, expiry, nonce, replay, identity,
and session checks as native authentication.

Resolve-only discovery accepts the same strict credential body:

```http
POST /authentication/federated/apple/resolve
Content-Type: application/json

{
  "identityToken": "<Apple identity token>",
  "nonce": "<raw one-time nonce>"
}
```

Its complete success contract is one of:

```json
{ "outcome": "EXISTING" }
```

```json
{ "outcome": "UNLINKED" }
```

It returns no Human ID, provider subject, email, session, Tenant, Product, role,
or authority information. A successful result consumes the nonce even when the
outcome is `UNLINKED`; replay uses the ordinary sanitized federated-credential
error contract.

Public error codes are deliberately sanitized:

- `INVALID_REQUEST`
- `FEDERATED_PROVIDER_UNSUPPORTED`
- `FEDERATED_CREDENTIAL_INVALID`
- `FEDERATED_AUTHENTICATION_UNAVAILABLE`
- `APPLE_AUTHORIZATION_CODE_INVALID`
- `APPLE_WEB_AUTHENTICATION_UNAVAILABLE`
- `FEDERATED_IDENTITY_CONFLICT`
- `FEDERATED_VERIFICATION_UNAVAILABLE`
- `SESSION_INVALID`, `SESSION_EXPIRED`, `SESSION_REVOKED`
- `FEDERATED_IDENTITY_LINK_CONFLICT`
- `FEDERATED_IDENTITY_RECONCILIATION_REQUIRED`
- `LAST_AUTHENTICATION_METHOD`

Authenticated method management uses:

```http
GET /authentication/methods
POST /authentication/federated/apple/link
DELETE /authentication/federated/apple/link
Authorization: Bearer <ordinary GAMA session>
```

The link body is exactly `identityToken` plus raw one-time `nonce`; unlink has no
credential body. Method projections contain the canonical Human ID, active email
credential display state, provider name and safe provider email metadata. They
never contain a provider subject, bearer, provider token or nonce.

Internal typed errors retain malformed/signature/issuer/audience/expiration/nonce,
replay, lifecycle, conflict, and verification-infrastructure classifications for
testing and operations without exposing token contents.

## Configuration

`APPLE_CLIENT_IDS` is a comma-separated allowlist of Apple OAuth/OpenID client
identifiers accepted in the token `aud` claim. For native apps these are the App
IDs/bundle identifiers configured for Sign in with Apple. These identifiers are
public configuration, not secrets.

The native identity-token exchange does not require an Apple Team ID, Services
ID, private key, or client secret. Web authorization-code exchange additionally
requires all of `APPLE_WEB_CLIENT_ID`, `APPLE_WEB_REDIRECT_URI`,
`APPLE_TEAM_ID`, `APPLE_KEY_ID`, and `APPLE_PRIVATE_KEY`. The web client ID must
also appear in `APPLE_CLIENT_IDS`. The private key is stored only in the secure
runtime environment and is never committed.

When `APPLE_CLIENT_IDS` is absent, existing email/password operation and service
startup remain available, while Apple exchange fails closed with
`FEDERATED_VERIFICATION_UNAVAILABLE`.

## Persistence and migration

Migration `006_federated_identities.sql` is forward-only and additive. It creates
only `federated_identities` and `federated_authentication_nonces`, with foreign
keys to existing Humans. It performs no backfill and does not update or delete
Humans, email credentials, sessions, Tenant relationships, Product relationships,
Platform Administration membership, Coco owner state, or audit history.

Migration `007_federated_account_linking.sql` additively enforces at most one
active relationship for a Human/provider pair. The existing global
`(provider, providerSubject)` uniqueness remains authoritative. Advisory
transaction locks serialize provider-subject and Human/provider decisions across
ordinary sign-in, resolve, link, unlink and reconciliation.

Migration `008_federated_email_discovery.sql` adds only an indexed administrative
lookup path for verified provider email metadata on active relationships. The
lookup returns canonical Human IDs and provider-name labels; it never returns a
provider subject, token or nonce. Email equality remains discovery evidence only:
multiple active Humans exposing the same email produce an ambiguity conflict and
no merge or authorization mutation. Administrators can resolve a known canonical
Human ID instead.

Normal account registration currently has no identity-account audit stream;
Platform audit events are reserved for security/authorization relationships.
Federated registration follows the same behavior and creates no workforce audit
event. Link, unlink and duplicate reconciliation append safe Platform audit
events containing GAMA relationship/Human identifiers, provider and outcome;
provider subject, token and nonce material are excluded.

## Google extension point

Adding Google later requires a Google credential-acquisition adapter and a Google
`FederatedIdentityTokenVerifier` registered for `provider = google`, with Google's
issuer, audience, keys, expiration, and nonce rules. Human Identity, persistence,
session issuance, API orchestration, account-linking policy, and authorization
boundaries require no redesign. This release contains no Google SDK or server
configuration.
