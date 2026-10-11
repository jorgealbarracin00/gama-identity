import type { DatabaseQuery } from "./database.js";
import type { IdentityInspectionRepository, InspectionPage, InspectionRequest, InspectedHuman, DuplicateGroup } from "../../control-plane/application/identity-explorer.js";

// Read only the metadata columns required by Console. Password hashes, provider
// subjects, sessions and encrypted provider tokens never enter this projection.
const emailMetadata = `
  SELECT human_identity_id, normalized_email AS email FROM credentials
  UNION ALL
  SELECT human_identity_id, provider_email AS email FROM federated_identities WHERE provider_email IS NOT NULL
`;

export class PostgresIdentityInspectionRepository implements IdentityInspectionRepository {
  constructor(private readonly database: DatabaseQuery) {}
  async inspect(input: InspectionRequest): Promise<InspectionPage> {
    if (input.mode === "duplicates") {
      const result = await this.database.query<{ email: string; humanIdentityIds: string[] }>(`
        WITH emails AS (${emailMetadata})
        SELECT lower(trim(email)) AS email, array_agg(DISTINCT human_identity_id ORDER BY human_identity_id) AS "humanIdentityIds"
        FROM emails WHERE lower(trim(email)) > $1
        GROUP BY lower(trim(email)) HAVING count(DISTINCT human_identity_id) > 1
        ORDER BY email LIMIT 51`, [input.cursor ?? ""]);
      const groups: DuplicateGroup[] = result.rows.map((row) => ({ email: row.email, humanIdentityIds: row.humanIdentityIds }));
      return { identities: [], duplicateGroups: groups.slice(0, 50), nextCursor: groups.length > 50 ? groups[49]!.email : null };
    }
    const values = input.mode === "details" ? [input.humanIdentityIds] : [input.cursor ?? "", input.query.trim().toLowerCase()];
    // Canonical Human currently has no name column. Return null, never infer a
    // name from email/provider subject. The search contract supports names when stored.
    const predicate = input.mode === "details" ? "h.id = ANY($1::text[])" : `h.id > $1 AND (
      strpos(lower(h.id), $2) > 0 OR EXISTS (
        SELECT 1 FROM (${emailMetadata}) e WHERE e.human_identity_id = h.id AND strpos(lower(e.email), $2) > 0
      ))`;
    const result = await this.database.query<InspectedHuman>(`
      WITH selected AS (SELECT h.id, h.status FROM human_identities h WHERE ${predicate} ORDER BY h.id LIMIT 51)
      SELECT h.id AS "humanIdentityId", NULL::text AS "displayName", h.status,
        coalesce((SELECT json_agg(json_build_object('method', m.method, 'status', m.status, 'email', m.email, 'emailVerified', m.verified) ORDER BY m.method, m.email, m.status)
          FROM (
            SELECT 'email_password' AS method, status, normalized_email AS email, email_verified_at IS NOT NULL AS verified FROM credentials WHERE human_identity_id = h.id
            UNION ALL
            SELECT provider AS method, status, provider_email AS email, provider_email_verified AS verified FROM federated_identities WHERE human_identity_id = h.id
          ) m), '[]'::json) AS "authenticationMethods"
      FROM selected h ORDER BY h.id`, values);
    return {
      identities: result.rows.slice(0, 50), duplicateGroups: [],
      nextCursor: input.mode === "search" && result.rows.length > 50 ? result.rows[49]!.humanIdentityId : null,
    };
  }
}
