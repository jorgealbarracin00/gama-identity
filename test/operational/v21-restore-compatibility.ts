import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { PostgresDatabase } from "../../src/infrastructure/postgres/database.js";
import { runMigrations } from "../../src/infrastructure/postgres/migrations.js";
const db = new PostgresDatabase(
  "postgresql:///gama_v21_restore?host=/tmp/gama-v21-backup-restore/socket&port=55440",
);
const tables = [
  "human_identities",
  "credentials",
  "federated_identities",
  "sessions",
  "tenant_memberships",
  "platform_administration_memberships",
  "product_entitlements",
  "human_product_participations",
  "platform_audit_events",
];
async function hashes() {
  const result: Record<string, string> = {};
  for (const t of tables) {
    const r = await db.query(
      `SELECT coalesce(jsonb_agg(row ORDER BY row::text),'[]'::jsonb) AS value FROM (SELECT to_jsonb(t)-'write_revision' AS row FROM ${t} t) rows`,
    );
    result[t] = createHash("sha256")
      .update(JSON.stringify(r.rows[0]!.value))
      .digest("hex");
  }
  return result;
}
try {
  const before = await hashes();
  await runMigrations(db);
  const after = await hashes();
  if (JSON.stringify(before) !== JSON.stringify(after))
    throw new Error("Existing identity data changed");
  await runMigrations(db);
  const versions = (
    await db.query("SELECT version FROM schema_migrations ORDER BY version")
  ).rows.map((x) => x.version);
  const report = {
    checkedAt: new Date().toISOString(),
    isolatedRestoreOnly: true,
    additiveMigration: "014",
    migrationIdempotence: "passed",
    existingIdentityAuthenticationSessionMembershipEntitlementAuditProjections:
      "unchanged",
    versions,
    tableHashes: after,
  };
  writeFileSync(process.argv[2]!, JSON.stringify(report, null, 2) + "\n", {
    mode: 0o600,
  });
  console.log(JSON.stringify({ ...report, tableHashes: undefined }));
} finally {
  await db.close();
}
