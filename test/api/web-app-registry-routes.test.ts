import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildApp } from "../../src/api/app.js";
import { buildTestServices } from "../operational/test-doubles.js";
import { AuthenticateAppleWeb } from "../../src/authentication/federated/application/authenticate-apple-web.js";
import { AuthenticateGoogleWeb } from "../../src/authentication/federated/application/authenticate-google-web.js";

const nonce = "registry_nonce_that_is_at_least_thirty_two_characters";
const codeVerifier = "v".repeat(43);

function fixture() {
  const data = buildTestServices();
  data.appleVerifier.accept("apple-registered-token", { subject: "stable-apple-subject", emailPrivate: true });
  data.googleVerifier.accept("google-registered-token", { subject: "stable-google-subject" });
  const calls: string[] = [];
  const apple = new AuthenticateAppleWeb({ async exchange(input) { assert.equal("appId" in input, false); calls.push("cashcast-apple"); return "apple-registered-token"; } }, data.services.authenticateFederated);
  const google = new AuthenticateGoogleWeb({ async exchange(input) { assert.equal(input.codeVerifier, codeVerifier); assert.equal("appId" in input, false); calls.push("cashcast-google"); return "google-registered-token"; } }, data.services.authenticateFederated);
  const legacyApple = new AuthenticateAppleWeb({ async exchange() { calls.push("legacy-apple"); return "apple-registered-token"; } }, data.services.authenticateFederated);
  const app = buildApp({ ...data.services, authenticateAppleWeb: legacyApple,
    webAuthenticationApps: new Map([["cashcast-preview", { apple, google }], ["apple-only", { apple }]]) });
  return { app, calls };
}

describe("registered product web-code routing", () => {
  for (const provider of ["apple", "google"] as const) {
    it(`uses only the registered ${provider} exchange for an explicit app`, async () => {
      const { app, calls } = fixture();
      try {
        const result = await app.inject({ method: "POST", url: `/authentication/federated/${provider}/web`, payload: {
          appId: "cashcast-preview", authorizationCode: "one-time-code", nonce, ...(provider === "google" ? { codeVerifier } : {}),
        } });
        assert.equal(result.statusCode, 200);
        assert.equal(result.json().session.humanIdentityId, "identity-1");
        assert.deepEqual(calls, [`cashcast-${provider}`]);
        assert.equal(result.body.includes("one-time-code"), false);
      } finally { await app.close(); }
    });
  }
  it("keeps an omitted app selector on the existing legacy exchange", async () => {
    const { app, calls } = fixture();
    try {
      const result = await app.inject({ method: "POST", url: "/authentication/federated/apple/web", payload: { authorizationCode: "code", nonce } });
      assert.equal(result.statusCode, 200); assert.deepEqual(calls, ["legacy-apple"]);
    } finally { await app.close(); }
  });
  it("never falls back to another product for an unknown app or missing provider", async () => {
    const { app, calls } = fixture();
    try {
      for (const appId of ["unknown-product", "apple-only"]) {
        const result = await app.inject({ method: "POST", url: "/authentication/federated/google/web", payload: { appId, authorizationCode: "code", nonce, codeVerifier } });
        assert.equal(result.statusCode, 503);
      }
      assert.deepEqual(calls, []);
    } finally { await app.close(); }
  });
  it("rejects caller supplied redirects, audiences, subjects or Human authority", async () => {
    const { app, calls } = fixture();
    try {
      for (const extra of [{ redirectUri: "https://evil.test" }, { clientId: "coco-client" }, { subject: "fake-subject" }, { humanIdentityId: "victim" }]) {
        const result = await app.inject({ method: "POST", url: "/authentication/federated/apple/web", payload: { appId: "cashcast-preview", authorizationCode: "code", nonce, ...extra } });
        assert.equal(result.statusCode, 400);
      }
      assert.deepEqual(calls, []);
    } finally { await app.close(); }
  });
  it("retains shared provider nonce replay protection across registered and legacy exchanges", async () => {
    const { app } = fixture();
    try {
      const first = await app.inject({ method: "POST", url: "/authentication/federated/apple/web", payload: { appId: "cashcast-preview", authorizationCode: "code-1", nonce } });
      const replay = await app.inject({ method: "POST", url: "/authentication/federated/apple/web", payload: { authorizationCode: "code-2", nonce } });
      assert.equal(first.statusCode, 200); assert.equal(replay.statusCode, 401);
      assert.equal(replay.json().error.code, "FEDERATED_CREDENTIAL_INVALID");
    } finally { await app.close(); }
  });
});
