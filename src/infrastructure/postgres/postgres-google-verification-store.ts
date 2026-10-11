import type { DatabaseQuery } from "./database.js";
import type { GoogleVerificationScope, ObservationCase, VerificationStore } from "../../control-plane/application/google-recovery-verification.js";

export class PostgresGoogleVerificationStore implements VerificationStore {
  constructor(private readonly database: DatabaseQuery, private readonly scope: GoogleVerificationScope) {}
  async latestForUpdate(): Promise<ObservationCase | null> {
    await this.database.query("SELECT pg_advisory_xact_lock(710012)");
    const result = await this.database.query<{ payload: ObservationCase }>("SELECT payload FROM google_identity_verification_cases WHERE payload->>'sourceHumanIdentityId'=$1 AND payload->>'targetHumanIdentityId'=$2 AND payload->>'appId'=$3 ORDER BY sequence DESC LIMIT 1 FOR UPDATE", [this.scope.source, this.scope.target, this.scope.appId]);
    return result.rows[0]?.payload ?? null;
  }
  async save(value: ObservationCase): Promise<void> {
    await this.database.query(`INSERT INTO google_identity_verification_cases(id,created_at,payload)
      VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload`, [value.id, value.createdAt, JSON.stringify(value)]);
  }
  async extras(human: string) {
    const result = await this.database.query<{ provisioning: string; challenges: string; revocations: string }>(`SELECT
      (SELECT count(*) FROM tenant_provisioning_requests WHERE initial_owner_human_identity_id=$1) AS provisioning,
      (SELECT count(*) FROM email_action_challenges a JOIN credentials c ON c.id=a.credential_id WHERE c.human_identity_id=$1) AS challenges,
      (SELECT count(*) FROM product_apple_revocations WHERE human_identity_id=$1) AS revocations`, [human]);
    const row = result.rows[0]!;
    return { provisioningReferences: Number(row.provisioning), emailChallenges: Number(row.challenges), appleRevocationReferences: Number(row.revocations) };
  }
}
