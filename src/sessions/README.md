# Sessions

A Session is an independent aggregate that records an authenticated continuity
for one Human Identity. It does not own authentication or re-check identity
lifecycle.

Sessions begin `active`, become `expired` when their fixed expiry is reached,
and may be revoked explicitly. Validation returns `authenticated`, `expired`,
`revoked`, or `invalid`. Successful validation touches `lastAccessedAt` without
extending the fixed expiry. Logout revokes a session and is idempotent.

The repository contract is storage-independent. This milestone composes the
application with an isolated in-memory implementation.
