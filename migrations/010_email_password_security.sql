ALTER TABLE credentials
  ADD COLUMN email_verified_at timestamptz;

-- Existing password users pre-date verification. Grandfather them so this
-- migration never locks an established user out of account operations.
UPDATE credentials
SET email_verified_at = created_at
WHERE email_verified_at IS NULL;

CREATE TABLE email_action_challenges (
  id text PRIMARY KEY,
  credential_id text NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  app_id text NOT NULL CHECK (char_length(app_id) BETWEEN 1 AND 64),
  purpose text NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
  token_hash text NOT NULL UNIQUE CHECK (char_length(token_hash) = 43),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL,
  CHECK (expires_at > created_at),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE UNIQUE INDEX email_action_challenges_one_active_per_purpose
  ON email_action_challenges (credential_id, purpose)
  WHERE consumed_at IS NULL;

CREATE INDEX email_action_challenges_expiry_index
  ON email_action_challenges (expires_at);

CREATE TABLE identity_security_attempts (
  id bigserial PRIMARY KEY,
  action text NOT NULL CHECK (action IN ('registration', 'verify_email', 'resend_verification', 'forgot_password', 'reset_password')),
  subject_hash text NOT NULL CHECK (char_length(subject_hash) = 43),
  ip_hash text NOT NULL CHECK (char_length(ip_hash) = 43),
  occurred_at timestamptz NOT NULL
);

CREATE INDEX identity_security_attempts_action_subject_time_index
  ON identity_security_attempts (action, subject_hash, occurred_at DESC);

CREATE INDEX identity_security_attempts_action_ip_time_index
  ON identity_security_attempts (action, ip_hash, occurred_at DESC);
