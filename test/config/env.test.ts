import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { loadConfig } from "../../src/config/env.js";

describe("environment configuration", () => {
  it("uses memory repositories without database configuration by default", () => {
    const config = loadConfig({});
    assert.equal(config.REPOSITORY_MODE, "memory");
    assert.equal(config.DATABASE_URL, undefined);
    assert.equal(config.DATABASE_SSL, "disable");
    assert.deepEqual(config.APPLE_CLIENT_IDS, []);
  });

  it("parses one or more public Apple client identifiers without requiring Apple secrets", () => {
    const config = loadConfig({
      APPLE_CLIENT_IDS: "com.gamadynamics.coco, com.gamadynamics.console,com.gamadynamics.coco",
    });
    assert.deepEqual(config.APPLE_CLIENT_IDS, [
      "com.gamadynamics.coco",
      "com.gamadynamics.console",
    ]);
    assert.throws(() => loadConfig({ APPLE_CLIENT_IDS: " , " }), /APPLE_CLIENT_IDS/);
  });

  it("requires complete Apple web configuration and an allowlisted Services ID", () => {
    const configured = loadConfig({
      APPLE_CLIENT_IDS: "com.gamadynamics.CocoCompanion,com.gamadynamics.cocothellama.web",
      APPLE_WEB_CLIENT_ID: "com.gamadynamics.cocothellama.web",
      APPLE_WEB_REDIRECT_URI: "https://cocothellama.com/api/auth/apple/callback",
      APPLE_TEAM_ID: "33VYKC5J83",
      APPLE_KEY_ID: "ABC123DEFG",
      APPLE_PRIVATE_KEY: "private-key-material",
    });
    assert.equal(configured.APPLE_WEB_CLIENT_ID, "com.gamadynamics.cocothellama.web");
    assert.throws(() => loadConfig({
      APPLE_CLIENT_IDS: "com.gamadynamics.CocoCompanion",
      APPLE_WEB_CLIENT_ID: "com.gamadynamics.cocothellama.web",
      APPLE_WEB_REDIRECT_URI: "https://cocothellama.com/api/auth/apple/callback",
      APPLE_TEAM_ID: "33VYKC5J83",
      APPLE_KEY_ID: "ABC123DEFG",
      APPLE_PRIVATE_KEY: "private-key-material",
    }), /must include APPLE_WEB_CLIENT_ID/);
    assert.throws(() => loadConfig({
      APPLE_CLIENT_IDS: "com.gamadynamics.cocothellama.web",
      APPLE_WEB_CLIENT_ID: "com.gamadynamics.cocothellama.web",
    }), /configured completely/);
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
