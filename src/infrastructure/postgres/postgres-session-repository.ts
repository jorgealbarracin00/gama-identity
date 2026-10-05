import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import {
  Session,
  type SessionStatus,
} from "../../sessions/domain/session.js";
import { SessionId } from "../../sessions/domain/session-id.js";
import type { SessionRepository } from "../../sessions/ports/session-repository.js";
import type { DatabaseQuery } from "./database.js";

interface SessionRow {
  id: string;
  human_identity_id: string;
  created_at: Date;
  authenticated_at: Date;
  last_accessed_at: Date;
  expires_at: Date;
  status: SessionStatus;
  renewal_token_hash: string | null;
  renewal_expires_at: Date | null;
}

export class PostgresSessionRepository implements SessionRepository {
  constructor(private readonly database: DatabaseQuery) {}

  async save(session: Session): Promise<void> {
    const snapshot = session.snapshot();
    await this.database.query(
      `INSERT INTO sessions (
         id, human_identity_id, created_at, last_accessed_at,
         expires_at, status, renewal_token_hash, renewal_expires_at, authenticated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (id) DO UPDATE SET
         last_accessed_at = EXCLUDED.last_accessed_at,
         status = EXCLUDED.status,
         renewal_token_hash = EXCLUDED.renewal_token_hash,
         renewal_expires_at = EXCLUDED.renewal_expires_at`,
      [
        snapshot.id.value,
        snapshot.humanIdentityId.value,
        snapshot.createdAt,
        snapshot.lastAccessedAt,
        snapshot.expiresAt,
        snapshot.status,
        snapshot.renewalTokenHash,
        snapshot.renewalExpiresAt,
        snapshot.authenticatedAt ?? snapshot.createdAt,
      ],
    );
  }

  async findById(id: SessionId): Promise<Session | null> {
    const result = await this.database.query<SessionRow>(
      `${selectSession} WHERE id = $1`,
      [id.value],
    );
    return toSession(result.rows[0]);
  }

  async findActiveById(id: SessionId): Promise<Session | null> {
    const result = await this.database.query<SessionRow>(
      `${selectSession} WHERE id = $1 AND status = 'active'`,
      [id.value],
    );
    return toSession(result.rows[0]);
  }

  async findByRenewalTokenHashForUpdate(hash: string): Promise<Session | null> {
    const result = await this.database.query<SessionRow>(
      `${selectSession} WHERE renewal_token_hash = $1 FOR UPDATE`,
      [hash],
    );
    return toSession(result.rows[0]);
  }

  async listByHumanIdentityId(humanIdentityId: HumanIdentityId): Promise<readonly Session[]> {
    const result = await this.database.query<SessionRow>(
      `${selectSession} WHERE human_identity_id = $1 ORDER BY created_at, id`,
      [humanIdentityId.value],
    );
    return result.rows.map((row) => toSession(row)!);
  }

  async revoke(id: SessionId): Promise<void> {
    await this.database.query(
      `UPDATE sessions
       SET status = 'revoked'
       WHERE id = $1 AND status <> 'revoked'`,
      [id.value],
    );
  }

  async revokeByHumanIdentityId(humanIdentityId: HumanIdentityId): Promise<void> {
    await this.database.query(
      `UPDATE sessions
       SET status = 'revoked'
       WHERE human_identity_id = $1 AND status <> 'revoked'`,
      [humanIdentityId.value],
    );
  }

  async remove(id: SessionId): Promise<void> {
    await this.database.query("DELETE FROM sessions WHERE id = $1", [id.value]);
  }
}

const selectSession = `
  SELECT id, human_identity_id, created_at, last_accessed_at,
         expires_at, status, renewal_token_hash, renewal_expires_at, authenticated_at
  FROM sessions
`;

function toSession(row: SessionRow | undefined): Session | null {
  return row === undefined
    ? null
    : Session.reconstitute({
        id: SessionId.from(row.id),
        humanIdentityId: HumanIdentityId.from(row.human_identity_id),
        createdAt: row.created_at,
        authenticatedAt: row.authenticated_at,
        lastAccessedAt: row.last_accessed_at,
        expiresAt: row.expires_at,
        status: row.status,
        renewalTokenHash: row.renewal_token_hash,
        renewalExpiresAt: row.renewal_expires_at,
      });
}
