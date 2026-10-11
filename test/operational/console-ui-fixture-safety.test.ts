import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { consoleFixtureDatabaseAllowed } from "./console-ui-fixture-safety.js";

describe("Console fixture destructive-seed target guard", () => {
  it("accepts only the exact loopback PostgreSQL fixture suffix for each mode", () => {
    for (const protocol of ["postgres", "postgresql"]) {
      assert.equal(consoleFixtureDatabaseAllowed(`${protocol}://127.0.0.1:55442/gama_console_v21_ui`, false), true);
      assert.equal(consoleFixtureDatabaseAllowed(`${protocol}://127.0.0.1:55442/gama_v22_ui_management_test`, true), true);
    }
    assert.equal(consoleFixtureDatabaseAllowed("postgresql://127.0.0.1:55442/gama_console_v21_ui", true), false);
    assert.equal(consoleFixtureDatabaseAllowed("postgresql://127.0.0.1:55442/gama_v22_ui_management_test", false), false);
  });
  it("rejects remote targets, query overrides, fragments, other protocols and malformed paths before seeding", () => {
    const unsafe = [undefined, "", "invalid", "postgresql://remote.example/gama_fixture_ui",
      "postgresql://localhost/gama_fixture_ui", "postgresql://[::1]/gama_fixture_ui",
      "postgresql://127.0.0.1/gama_fixture_ui?host=remote.example", "postgresql://127.0.0.1/gama_fixture_ui?port=5432",
      "postgresql://127.0.0.1/gama_fixture_ui#target", "https://127.0.0.1/gama_fixture_ui",
      "postgresql://127.0.0.1/production", "postgresql://127.0.0.1/production/fixture_ui",
      "postgresql://127.0.0.1/production%2Ffixture_ui"];
    for (const url of unsafe) assert.equal(consoleFixtureDatabaseAllowed(url, false), false, String(url));
    for (const suffix of ["?host=remote.example", "?port=5432", "#target"]) {
      assert.equal(consoleFixtureDatabaseAllowed(`postgresql://127.0.0.1/gama_fixture_management_test${suffix}`, true), false);
    }
  });
});
