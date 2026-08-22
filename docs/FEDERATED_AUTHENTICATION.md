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

## Apple email and account linking

The optional signed Apple `email`, `email_verified`, and `is_private_email`
claims are stored only as provider metadata. A private relay address is retained
with `provider_email_private = true`. Missing email on a returning sign-in does
not erase metadata captured earlier.

This release intentionally implements no account-linking endpoint. If an unknown
Apple subject carries an email matching an existing password account, GAMA
creates a new Human Identity. This can represent one physical person twice, but
prevents an unsafe email-only account takeover. Future linking must be an explicit
ceremony proving control of both the authenticated GAMA account and the external
provider credential; it must never infer ownership from matching email.

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

Public error codes are deliberately sanitized:

- `INVALID_REQUEST`
- `FEDERATED_PROVIDER_UNSUPPORTED`
- `FEDERATED_CREDENTIAL_INVALID`
- `FEDERATED_AUTHENTICATION_UNAVAILABLE`
- `FEDERATED_IDENTITY_CONFLICT`
- `FEDERATED_VERIFICATION_UNAVAILABLE`

Internal typed errors retain malformed/signature/issuer/audience/expiration/nonce,
replay, lifecycle, conflict, and verification-infrastructure classifications for
testing and operations without exposing token contents.

## Configuration

`APPLE_CLIENT_IDS` is a comma-separated allowlist of Apple OAuth/OpenID client
identifiers accepted in the token `aud` claim. For native apps these are the App
IDs/bundle identifiers configured for Sign in with Apple. These identifiers are
public configuration, not secrets.

This identity-token-only native exchange does not require an Apple Team ID,
Services ID, private key, or client secret on the GAMA server. Those credentials
would be required only for later authorization-code exchange, refresh-token,
revocation, web, or account-transfer workflows and must not be added speculatively.

When `APPLE_CLIENT_IDS` is absent, existing email/password operation and service
startup remain available, while Apple exchange fails closed with
`FEDERATED_VERIFICATION_UNAVAILABLE`.

## Persistence and migration

Migration `006_federated_identities.sql` is forward-only and additive. It creates
only `federated_identities` and `federated_authentication_nonces`, with foreign
keys to existing Humans. It performs no backfill and does not update or delete
Humans, email credentials, sessions, Tenant relationships, Product relationships,
Platform Administration membership, Coco owner state, or audit history.

Normal account registration currently has no identity-account audit stream;
Platform audit events are reserved for security/authorization relationships.
Federated registration follows the same behavior and creates no workforce audit
event.

## Google extension point

Adding Google later requires a Google credential-acquisition adapter and a Google
`FederatedIdentityTokenVerifier` registered for `provider = google`, with Google's
issuer, audience, keys, expiration, and nonce rules. Human Identity, persistence,
session issuance, API orchestration, account-linking policy, and authorization
boundaries require no redesign. This release contains no Google SDK or server
configuration.
