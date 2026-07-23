# Human Identity

Human Identity represents a stable human principal. The aggregate owns:

- an opaque identity identifier;
- lifecycle state (`active`, `suspended`, or `retired`);
- creation and last-change timestamps.

It deliberately does not own credentials, authentication state, sessions,
authority, roles, permissions, tenant or product membership, organisation
membership, or profile data.

New identities are active. Suspending an already suspended identity and
reactivating an already active identity are idempotent operations. Retirement
is terminal, so a retired identity cannot be suspended or reactivated.
`updatedAt` advances only when lifecycle state changes.

Application use cases coordinate the aggregate through a repository port that
saves and retrieves complete Human Identity aggregates. No persistence
technology is assumed.
