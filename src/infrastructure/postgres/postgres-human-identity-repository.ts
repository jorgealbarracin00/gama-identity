import {
  HumanIdentity,
  type HumanIdentityStatus,
} from "../../identity/domain/human-identity.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import type { DatabaseQuery } from "./database.js";

interface HumanIdentityRow {
  id: string;
  status: HumanIdentityStatus;
  created_at: Date;
  updated_at: Date;
}

export class PostgresHumanIdentityRepository
  implements HumanIdentityRepository
{
  constructor(private readonly database: DatabaseQuery) {}

  async save(identity: HumanIdentity): Promise<void> {
    const snapshot = identity.snapshot();
    await this.database.query(
      `INSERT INTO human_identities (id, status, created_at, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET
         status = EXCLUDED.status,
         updated_at = EXCLUDED.updated_at`,
      [
        snapshot.id.value,
        snapshot.status,
        snapshot.createdAt,
        snapshot.updatedAt,
      ],
    );
  }

  async findById(id: HumanIdentityId): Promise<HumanIdentity | null> {
    const result = await this.database.query<HumanIdentityRow>(
      `SELECT id, status, created_at, updated_at
       FROM human_identities
       WHERE id = $1`,
      [id.value],
    );
    const row = result.rows[0];
    return row === undefined
      ? null
      : HumanIdentity.reconstitute({
          id: HumanIdentityId.from(row.id),
          status: row.status,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        });
  }

  async remove(id: HumanIdentityId): Promise<void> {
    await this.database.query("DELETE FROM human_identities WHERE id = $1", [
      id.value,
    ]);
  }
}
