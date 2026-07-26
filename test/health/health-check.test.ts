import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { HealthCheck } from "../../src/health/health-check.js";

describe("HealthCheck", () => {
  it("reports connected PostgreSQL without exposing connection details", async () => {
    const result = await new HealthCheck({
      async check() {
        return "connected";
      },
    }).execute();
    assert.deepEqual(result, {
      status: "running",
      database: { status: "connected" },
    });
  });

  it("reports degraded health when PostgreSQL is unavailable", async () => {
    const result = await new HealthCheck({
      async check(): Promise<"connected"> {
        throw new Error("connection includes sensitive details");
      },
    }).execute();
    assert.deepEqual(result, {
      status: "degraded",
      database: { status: "unavailable" },
    });
  });
});
