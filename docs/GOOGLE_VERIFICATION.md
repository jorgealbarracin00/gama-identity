# Scoped Google identity verification

This release adds account-read-only verification for exactly one privately
configured Human pair. Set `IDENTITY_GOOGLE_VERIFICATION_SCOPE` to a strict JSON
object with distinct UUID `source` and `target` values using the existing secure
release configuration procedure. Leave it absent to disable scoped verification.
HTTP callers cannot supply or select those IDs. Live IDs are never committed to
this public repository. Each durable receipt binds the original pair and app;
a future operator configuration change cannot reinterpret another pair's receipt.

`POST /administration/platform/google-recovery` requires a live session belonging
to the primary, a currently active Human and Platform Administrator membership.
Strict body modes are `inspect`, `prepare`, and `cancel` with a UUID `caseId`.
An `approve` request with UUID `caseId` and 64-character hexadecimal `reviewDigest`
is recognized only to return `403 RECOVERY_DISABLED`. There is no transfer route,
configuration switch or production grant issuer. The SDK exposes no approve mode.

Inspection reads authentication lifecycle metadata, platform/tenant authority,
capabilities, actual entitlement rows, session counts including renewable expired
access, provisioning references, email action challenges and Apple revocation
references. It returns no credential hashes, subjects, bearer IDs, renewal hashes,
provider tokens or encrypted grants. Product-local dependencies remain unknown.
Empty entitlements do not assert absence of product-local records or workforce roles.
The verification use case has read-only domain repository interfaces; its only
write interfaces are audit, replay protection and observation-case persistence.

Prepare requires a fresh primary authentication (at most five minutes; session
renewal does not reset authentication age), active Apple and Email methods and
an available unchanged `cashcast-preview` Google registration permitting primary.
The observation case lasts fifteen minutes. After preparing, use a fresh primary
Apple/Email sign-in in CashCast too, then its existing Connect Google flow.

Only that registered preview's linking service gets an optional observer. It
reuses the existing server-side code exchange, PKCE and Google OIDC verifier.
An armed case consumes the verified nonce and compares the exact provider subject
inside GAMAIdentity. It persists a match/mismatch receipt and awaited redacted audit
in one transaction, then emits the ordinary linking conflict. No relationship,
provider metadata, Human, credential or session is changed, even for an unknown
or incorrect Google account. An expired armed case fails closed until explicitly
cancelled; it never silently falls through to linking. Cancel returns to the
existing ordinary linking policy, which still rejects foreign Google ownership.
Other Humans and registrations retain existing linking behavior.

Current control is reported only for a matching proof within five minutes while
the observation case and dependency digest remain current. Changes require fresh
verification. The historical subject of an unrecorded older CashCast attempt
cannot be independently confirmed; this is explicitly reported false. The user
must choose the same Google account when reproducing the conflict.

Migration 012 creates only an observation ledger. A database sequence orders
cases independently of tied or reversed wall-clock timestamps. Its JSON key
allowlist excludes secrets and its lifecycle cannot represent an approved grant.
Proof failures and audit outages roll back nonce/receipt writes before any response.
All data responses use `Cache-Control: no-store`.

A forward/reverse recovery prototype lives exclusively in `test/recovery` and is
excluded from production TypeScript output. It tests one-use explicit synthetic
approval, reviewed dependencies, same-row domain reassignment, audit atomicity,
source session revocation and separately approved reverse recovery. Its cooperating
writer fence is test-only. Before a future transfer release, every relevant real
session/authority writer must be integrated and tested against that fence or an
equivalent proven scheme. This verification release does not enable that prototype.

Release uses the existing reviewed GitHub master -> Railway workflow. Rollback
reverts only this release's source code through the same workflow. Retain migration
012 and observation/audit rows; do not run a destructive down migration. The prior
release starts against this additive schema, retains the ledger and continues
existing session and Identity Explorer APIs. No account state requires rollback
because verification never changes ownership, lifecycle, authorization or sessions.
