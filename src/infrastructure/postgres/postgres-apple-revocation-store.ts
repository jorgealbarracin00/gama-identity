import type { AppleRevocationRecord, AppleRevocationStore } from "../../authentication/federated/application/product-apple-revocation.js";
import type { PostgresDatabase } from "./database.js";
export class PostgresAppleRevocationStore implements AppleRevocationStore {
  constructor(private readonly database: PostgresDatabase) {}
  async find(operationId: string): Promise<AppleRevocationRecord | null> {
    const result = await this.database.query<{ operation_id: string; human_identity_id: string; client_id: string; encrypted_token: string | null; completed_at: Date | null }>(
      "SELECT * FROM product_apple_revocations WHERE operation_id = $1", [operationId]);
    const row = result.rows[0];
    return row ? { operationId: row.operation_id, principalId: row.human_identity_id, clientId: row.client_id,
      encryptedToken: row.encrypted_token, completedAt: row.completed_at?.toISOString() ?? null } : null;
  }
  async save(record: AppleRevocationRecord): Promise<void> {
    await this.database.query(`INSERT INTO product_apple_revocations (operation_id, human_identity_id, client_id, encrypted_token)
      VALUES ($1, $2, $3, $4) ON CONFLICT (operation_id) DO NOTHING`,
      [record.operationId, record.principalId, record.clientId, record.encryptedToken]);
  }
  async complete(operationId: string): Promise<void> {
    await this.database.query("UPDATE product_apple_revocations SET encrypted_token = NULL, completed_at = COALESCE(completed_at, now()) WHERE operation_id = $1", [operationId]);
  }
}
