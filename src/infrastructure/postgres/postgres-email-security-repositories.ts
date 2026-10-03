import { EmailCredentialId } from "../../authentication/credentials/domain/email-credential-id.js";
import type {
  EmailActionChallenge,
  EmailActionChallengeRepository,
  EmailActionPurpose,
  IdentitySecurityAttemptRepository,
  SecurityAttemptInput,
} from "../../authentication/email-security/ports.js";
import type { DatabaseQuery } from "./database.js";

interface ChallengeRow {
  id: string;
  credential_id: string;
  app_id: string;
  purpose: EmailActionPurpose;
  token_hash: string;
  expires_at: Date;
  consumed_at: Date | null;
  created_at: Date;
}

export class PostgresEmailActionChallengeRepository
implements EmailActionChallengeRepository {
  constructor(private readonly database: DatabaseQuery) {}

  async replaceActive(challenge: EmailActionChallenge): Promise<void> {
    await this.database.query(
      `UPDATE email_action_challenges
       SET consumed_at = $3
       WHERE credential_id = $1 AND purpose = $2 AND consumed_at IS NULL`,
      [challenge.credentialId.value, challenge.purpose, challenge.createdAt],
    );
    await this.database.query(
      `INSERT INTO email_action_challenges (
         id, credential_id, app_id, purpose, token_hash,
         expires_at, consumed_at, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        challenge.id,
        challenge.credentialId.value,
        challenge.appId,
        challenge.purpose,
        challenge.tokenHash,
        challenge.expiresAt,
        challenge.consumedAt,
        challenge.createdAt,
      ],
    );
  }

  async findByTokenHashForUpdate(
    tokenHash: string,
    purpose: EmailActionPurpose,
  ): Promise<EmailActionChallenge | null> {
    const result = await this.database.query<ChallengeRow>(
      `SELECT id, credential_id, app_id, purpose, token_hash,
              expires_at, consumed_at, created_at
       FROM email_action_challenges
       WHERE token_hash = $1 AND purpose = $2
       FOR UPDATE`,
      [tokenHash, purpose],
    );
    const row = result.rows[0];
    return row === undefined ? null : {
      id: row.id,
      credentialId: EmailCredentialId.from(row.credential_id),
      appId: row.app_id,
      purpose: row.purpose,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      consumedAt: row.consumed_at,
      createdAt: row.created_at,
    };
  }

  async consumeActiveForCredential(
    credentialId: EmailCredentialId,
    purpose: EmailActionPurpose,
    consumedAt: Date,
  ): Promise<void> {
    await this.database.query(
      `UPDATE email_action_challenges
       SET consumed_at = $3
       WHERE credential_id = $1 AND purpose = $2 AND consumed_at IS NULL`,
      [credentialId.value, purpose, consumedAt],
    );
  }

  async deleteStale(olderThan: Date): Promise<void> {
    await this.database.query(
      `DELETE FROM email_action_challenges
       WHERE expires_at < $1 OR (consumed_at IS NOT NULL AND consumed_at < $1)`,
      [olderThan],
    );
  }
}

export class PostgresIdentitySecurityAttemptRepository
implements IdentitySecurityAttemptRepository {
  constructor(private readonly database: DatabaseQuery) {}

  async consume(input: SecurityAttemptInput): Promise<boolean> {
    const result = await this.database.query<{ accepted: boolean }>(
      `WITH lock_keys AS (
         SELECT DISTINCT key
         FROM unnest(ARRAY[
           hashtextextended($1 || ':subject:' || $2, 0),
           hashtextextended($1 || ':ip:' || $3, 0)
         ]) AS key
         ORDER BY key
       ), locks AS (
         SELECT pg_advisory_xact_lock(key) FROM lock_keys
       ), recent AS (
         SELECT count(*)::int AS count
         FROM identity_security_attempts, (SELECT count(*) FROM locks) acquired
         WHERE action = $1
           AND occurred_at >= $4 - make_interval(secs => $5)
           AND (subject_hash = $2 OR ip_hash = $3)
       ), inserted AS (
         INSERT INTO identity_security_attempts (action, subject_hash, ip_hash, occurred_at)
         SELECT $1, $2, $3, $4 FROM recent WHERE count < $6
         RETURNING 1
       )
       SELECT EXISTS (SELECT 1 FROM inserted) AS accepted`,
      [
        input.action,
        input.subjectHash,
        input.ipHash,
        input.occurredAt,
        input.windowSeconds,
        input.maximumAttempts,
      ],
    );
    return result.rows[0]?.accepted === true;
  }

  async deleteOlderThan(olderThan: Date): Promise<void> {
    await this.database.query(
      "DELETE FROM identity_security_attempts WHERE occurred_at < $1",
      [olderThan],
    );
  }
}
