import type { PostgresDatabase } from "../../infrastructure/postgres/database.js";

/** Execute again inside the exclusive mutation transaction, never cache a grant. */
export async function continuityBlockers(db: PostgresDatabase, human: string): Promise<string[]> {
  const result = await db.query<{ lastAdmin: boolean; soleOwner: boolean }>(`
    SELECT
      EXISTS(SELECT 1 FROM platform_administration_memberships WHERE human_identity_id=$1 AND status='active')
      AND NOT EXISTS(SELECT 1 FROM platform_administration_memberships m JOIN human_identities h ON h.id=m.human_identity_id
        WHERE m.human_identity_id<>$1 AND m.status='active' AND h.status='active' AND
        (EXISTS(SELECT 1 FROM credentials c WHERE c.human_identity_id=h.id AND c.status='active') OR
         EXISTS(SELECT 1 FROM federated_identities f WHERE f.human_identity_id=h.id AND f.status='active'))) AS "lastAdmin",
      EXISTS(SELECT 1 FROM tenant_memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.human_identity_id=$1 AND m.tenant_role='owner' AND m.status<>'retired' AND t.status<>'retired'
        AND NOT EXISTS(SELECT 1 FROM tenant_memberships other JOIN human_identities h ON h.id=other.human_identity_id
          WHERE other.tenant_id=m.tenant_id AND other.human_identity_id<>$1 AND other.tenant_role='owner'
            AND other.status='active' AND h.status='active')) AS "soleOwner"`, [human]);
  const r = result.rows[0]!;
  return [ ...(r.lastAdmin ? ["LAST_FUNCTIONING_ADMINISTRATOR"] : []), ...(r.soleOwner ? ["SOLE_BUSINESS_OWNER"] : []) ];
}
