import { AppError } from '../../shared/errors.js';
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
  write_revision: string;
}

export class PostgresHumanIdentityRepository
  implements HumanIdentityRepository
{
  private readonly versions=new WeakMap<HumanIdentity,string>();
  constructor(private readonly database: DatabaseQuery) {}

  async lockForAccountManagement(id: HumanIdentityId): Promise<void> {
    await this.database.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`account-methods:${id.value}`]);
  }

  async save(identity: HumanIdentity): Promise<void> {
    const snapshot = identity.snapshot();
    const result=await this.database.query<{write_revision:string}>(
      `INSERT INTO human_identities (id, status, created_at, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET
         status = EXCLUDED.status,
         updated_at = EXCLUDED.updated_at, write_revision=human_identities.write_revision+1
         WHERE human_identities.write_revision=$5
         RETURNING write_revision`,
      [
        snapshot.id.value,
        snapshot.status,
        snapshot.createdAt,
        snapshot.updatedAt,
        this.versions.get(identity) ?? "-1",
      ],
    );
    if(!result.rows[0]) throw new AppError("Human changed; reload before saving", "IDENTITY_WRITE_CONFLICT",409);
    this.versions.set(identity,String(result.rows[0].write_revision));
  }

  async findById(id: HumanIdentityId): Promise<HumanIdentity | null> {
    const result = await this.database.query<HumanIdentityRow>(
      `SELECT id, status, created_at, updated_at, write_revision
       FROM human_identities
       WHERE id = $1`,
      [id.value],
    );
    const row = result.rows[0];
    const identity = row === undefined
      ? null
      : HumanIdentity.reconstitute({
          id: HumanIdentityId.from(row.id),
          status: row.status,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        });
    if(identity && row) this.versions.set(identity,String(row.write_revision));
    return identity;
  }

  async remove(id: HumanIdentityId): Promise<void> {
    await this.database.query("DELETE FROM human_identities WHERE id = $1", [
      id.value,
    ]);
  }
}
