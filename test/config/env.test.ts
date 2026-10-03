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
    assert.deepEqual(config.GOOGLE_CLIENT_IDS, []);
    assert.equal(config.SESSION_DURATION_SECONDS, 86_400);
    assert.equal(config.SESSION_RENEWAL_DURATION_SECONDS, 2_592_000);
  });

  it("requires the renewable session lifetime to exceed bearer lifetime", () => {
    assert.throws(
      () => loadConfig({
        SESSION_DURATION_SECONDS: "3600",
        SESSION_RENEWAL_DURATION_SECONDS: "3600",
      }),
      /SESSION_RENEWAL_DURATION_SECONDS/,
    );
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

  it("parses Google client identifiers and requires complete allowlisted web configuration", () => {
    const clientId = "123456789.apps.googleusercontent.com";
    const config = loadConfig({
      GOOGLE_CLIENT_IDS: `${clientId}, another.apps.googleusercontent.com, ${clientId}`,
      GOOGLE_WEB_CLIENT_ID: clientId,
      GOOGLE_WEB_CLIENT_SECRET: "server-only-secret",
      GOOGLE_WEB_REDIRECT_URI: "https://cocothellama.com/api/auth/google/callback",
    });
    assert.deepEqual(config.GOOGLE_CLIENT_IDS, [clientId, "another.apps.googleusercontent.com"]);
    assert.equal(config.GOOGLE_WEB_CLIENT_ID, clientId);
    assert.throws(() => loadConfig({ GOOGLE_CLIENT_IDS: " , " }), /GOOGLE_CLIENT_IDS/);
    assert.throws(() => loadConfig({
      GOOGLE_CLIENT_IDS: "another.apps.googleusercontent.com",
      GOOGLE_WEB_CLIENT_ID: clientId,
      GOOGLE_WEB_CLIENT_SECRET: "server-only-secret",
      GOOGLE_WEB_REDIRECT_URI: "https://cocothellama.com/api/auth/google/callback",
    }), /must include GOOGLE_WEB_CLIENT_ID/);
    assert.throws(() => loadConfig({
      GOOGLE_CLIENT_IDS: clientId,
      GOOGLE_WEB_CLIENT_ID: clientId,
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
