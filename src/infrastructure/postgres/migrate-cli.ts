import { loadConfig } from "../../config/env.js";
import { PostgresDatabase } from "./database.js";
import { runMigrations } from "./migrations.js";

const config = loadConfig(process.env);
if (config.DATABASE_URL === undefined) {
  throw new Error("DATABASE_URL is required to run migrations");
}

const database = new PostgresDatabase(
  config.DATABASE_URL,
  config.DATABASE_SSL === "require",
);

try {
  await database.checkConnection();
  await runMigrations(database);
} finally {
  await database.close();
}
