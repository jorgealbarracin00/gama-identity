import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

import type { PostgresDatabase } from "./database.js";

interface AppliedMigrationRow {
  readonly version: string;
  readonly checksum: string;
}

export async function runMigrations(
  database: PostgresDatabase,
  directory = resolve(process.cwd(), "migrations"),
): Promise<void> {
  const files = (await readdir(directory))
    .filter((file) => /^\d+_[a-z0-9_]+\.sql$/.test(file))
    .sort();

  await database.withTransaction(async () => {
    await database.query("SELECT pg_advisory_xact_lock(710011)");
    await database.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version text PRIMARY KEY,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    for (const file of files) {
      const sql = await readFile(resolve(directory, file), "utf8");
      const version = file.slice(0, file.indexOf("_"));
      const checksum = createHash("sha256").update(sql).digest("hex");
      const applied = await database.query<AppliedMigrationRow>(
        "SELECT version, checksum FROM schema_migrations WHERE version = $1",
        [version],
      );

      if (applied.rowCount === 1) {
        if (applied.rows[0]?.checksum !== checksum) {
          throw new Error(`Applied migration ${version} has been modified`);
        }
        continue;
      }

      await database.query(sql);
      await database.query(
        "INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)",
        [version, checksum],
      );
    }
  });
}
