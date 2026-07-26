import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { loadConfig } from "../../src/config/env.js";

describe("environment configuration", () => {
  it("uses memory repositories without database configuration by default", () => {
    const config = loadConfig({});
    assert.equal(config.REPOSITORY_MODE, "memory");
    assert.equal(config.DATABASE_URL, undefined);
    assert.equal(config.DATABASE_SSL, "disable");
  });

  it("accepts a PostgreSQL DATABASE_URL", () => {
    const config = loadConfig({
      REPOSITORY_MODE: "postgres",
      DATABASE_URL: "postgresql://postgres:secret@localhost:5432/gama_identity",
      DATABASE_SSL: "require",
    });
    assert.equal(config.REPOSITORY_MODE, "postgres");
    assert.equal(config.DATABASE_SSL, "require");
  });

  it("fails fast when PostgreSQL mode has no DATABASE_URL", () => {
    assert.throws(
      () => loadConfig({ REPOSITORY_MODE: "postgres" }),
      /DATABASE_URL is required/,
    );
  });

  it("rejects malformed database URLs and repository modes", () => {
    assert.throws(() =>
      loadConfig({
        REPOSITORY_MODE: "postgres",
        DATABASE_URL: "not-a-url",
      }),
    );
    assert.throws(() => loadConfig({ REPOSITORY_MODE: "filesystem" }));
  });
});
