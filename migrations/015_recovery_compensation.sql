-- Additive proof typing and receipt-bound recovery compensation metadata only.
-- Existing account ownership, session state and classification are unchanged.
ALTER TABLE identity_management_control_proofs
 ADD COLUMN proof_kind text NOT NULL DEFAULT 'session'
 CHECK (proof_kind IN ('session','provider'));
CREATE TABLE identity_recovery_compensations (
 id uuid PRIMARY KEY,
 original_request_id uuid NOT NULL REFERENCES identity_management_operations(id),
 actor_human_identity_id text NOT NULL REFERENCES human_identities(id),
 nonce text NOT NULL,
 state text NOT NULL CHECK (state IN ('awaiting_proof','verified','completed','cancelled')),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 proof_expires_at timestamptz,
 target_session_hash text,
 CHECK ((state='awaiting_proof' AND proof_expires_at IS NULL AND target_session_hash IS NULL)
   OR state<>'awaiting_proof')
);
CREATE UNIQUE INDEX identity_recovery_one_completed_compensation
 ON identity_recovery_compensations(original_request_id) WHERE state='completed';

-- Attribute newly authenticated sessions server-side. Legacy sessions remain unknown.
-- No backfill and no existing session lifecycle/renewal value is modified.
ALTER TABLE sessions ADD COLUMN authentication_method text
 CHECK (authentication_method IS NULL OR authentication_method IN ('email_password','apple','google'));
