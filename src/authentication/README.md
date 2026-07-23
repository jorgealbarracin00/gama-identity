# Authentication

This module contains authentication mechanisms while keeping them separate
from Human Identity, sessions, and authorization.

## Email Credentials

An Email Credential belongs to one Human Identity and owns:

- its own opaque credential identifier;
- a normalized email address;
- a protected password hash;
- lifecycle state and timestamps.

Email is credential data, not Human Identity profile data. Credential state
does not alter Human Identity state and grants no authority.

Email normalization trims surrounding whitespace, preserves the local part
exactly, and lowercases the domain. Consequently, `Person@example.com` and
`person@example.com` are distinct normalized values. Dots, plus aliases, and
provider domains are never rewritten.

Credentials begin `active`, may be `disabled`, and terminate as `retired`.
Disable, enable, and retire operations are idempotent when already in their
target state. Retirement cannot be reversed and releases the email for a new
credential.

The baseline password policy accepts 12 through 128 characters, rejects empty
or whitespace-only input, and imposes no character-composition rules. Policy
validation is separate from the `PasswordHasher` and `PasswordVerifier` ports;
no production cryptographic implementation is selected in this phase.

The repository works with complete aggregates and must enforce one
non-retired credential per normalized email. Application use cases return
explicit metadata without password hashes or aggregate references.

Creation accepts an existing Human Identity ID without loading a Human Identity.
Existence validation remains an orchestration or persistence-integrity concern.
HTTP endpoints, full authentication, registration, sessions, persistence, MFA,
password reset, and email delivery are not part of this module.
