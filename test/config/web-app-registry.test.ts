import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { loadConfig } from "../../src/config/env.js";

const trustedApps = [
  { id: "coco-web", displayName: "Coco", baseUrl: "https://cocothellama.com" },
  { id: "cashcast-preview", displayName: "CashCast Preview", baseUrl: "https://protected-preview.example.test" },
];
const google = { clientId: "cashcast-google-client", clientSecret: "fixture-only-secret", redirectUri: "https://protected-preview.example.test/api/auth/google/callback" };
const registered = { appId: "cashcast-preview", purpose: "preview", allowedPrincipalIds: ["authorized-test-human"], google };
function configuration(apps: unknown, changes: Record<string, string> = {}) {
  return loadConfig({ IDENTITY_TRUSTED_APPS: JSON.stringify(trustedApps), GOOGLE_CLIENT_IDS: "existing-legacy-client",
    IDENTITY_WEB_APPS: JSON.stringify(apps), ...changes });
}

describe("additive product web-client configuration", () => {
  it("preserves the legacy default with an empty optional registry", () => {
    assert.deepEqual(loadConfig({}).IDENTITY_WEB_APPS, []);
    assert.equal(loadConfig({}).IDENTITY_DEFAULT_APP_ID, "coco-web");
  });
  it("accepts a complete approved client bound to its trusted app callback", () => {
    assert.equal(configuration([registered]).IDENTITY_WEB_APPS[0]?.google?.clientId, google.clientId);
  });
  it("rejects duplicate, empty, incomplete and arbitrary app configuration", () => {
    for (const apps of [[registered, registered], [{ appId: "cashcast-preview" }], [{ appId: "cashcast-preview", google: { clientId: google.clientId } }], [{ ...registered, redirectUri: "https://evil.test" }]]) {
      assert.throws(() => configuration(apps), /web identity app registry/i);
    }
  });
  it("rejects an unregistered application", () => {
    assert.throws(() => configuration([{ ...registered, appId: "unknown-product" }]), /must identify a trusted application/i);
  });
  it("keeps preview clients out of unrestricted generic/native audiences", () => {
    assert.throws(() => configuration([registered], { GOOGLE_CLIENT_IDS: google.clientId }), /separate from unrestricted/i);
  });
  it("requires a preview existing-principal allowlist and rejects production client reuse", () => {
    assert.throws(() => configuration([{ ...registered, allowedPrincipalIds: undefined }]), /web identity app registry/i);
    const production = { appId: "coco-web", purpose: "production", google: { ...google, redirectUri: "https://cocothellama.com/api/auth/google/callback" } };
    assert.throws(() => configuration([registered, production]), /separate from unrestricted/i);
  });
  it("rejects other products, attacker origins, queries and incorrect callback paths", () => {
    for (const redirectUri of ["https://cocothellama.com/api/auth/google/callback", "https://evil.test/api/auth/google/callback", google.redirectUri + "?returnTo=evil", "https://protected-preview.example.test/api/auth/apple/callback"]) {
      assert.throws(() => configuration([{ ...registered, google: { ...google, redirectUri } }]), /trusted application origin and provider path/i);
    }
  });
});
