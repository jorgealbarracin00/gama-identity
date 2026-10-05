import { exportPKCS8, generateKeyPair, jwtVerify } from "jose";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { randomUUID } from "node:crypto";
import { ProductAppleRevocation, type AppleRevocationRecord, type AppleRevocationStore, type ProductAppleTokens } from "../../../src/authentication/federated/application/product-apple-revocation.js";
import { NativeProductAppleTokens } from "../../../src/authentication/federated/adapters/product-apple-tokens.js";
import { buildTestServices } from "../../operational/test-doubles.js";
import { HumanIdentityId } from "../../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../../src/sessions/domain/session-id.js";
import { AppError } from "../../../src/shared/errors.js";

class Store implements AppleRevocationStore {
  rows = new Map<string, AppleRevocationRecord>();
  async find(id: string) { return this.rows.get(id) ?? null; }
  async save(record: AppleRevocationRecord) { if (!this.rows.has(record.operationId)) this.rows.set(record.operationId, { ...record }); }
  async complete(id: string) { this.rows.set(id, { ...this.rows.get(id)!, encryptedToken: null, completedAt: new Date().toISOString() }); }
}
async function fixture() {
  const f = buildTestServices();
  f.appleVerifier.accept("apple-token", { subject: "apple-person" });
  const result = await f.services.authenticateFederated.execute({ provider: "apple", identityToken: "apple-token", nonce: "a".repeat(40) });
  const store = new Store();
  let fail = false; let exchanges = 0; let revocations = 0;
  const tokens: ProductAppleTokens = {
    async exchange() { exchanges++; return { identityToken: "apple-token", refreshToken: "secret" }; },
    async revoke(token) { assert.equal(token, "secret"); revocations++; if (fail) throw new Error("temporary outage"); },
    encrypt: (token) => `encrypted:${token}`, decrypt: (token) => token.slice(10),
  };
  const create = () => new ProductAppleRevocation("com.gamadynamics.GroceryMaster", f.federatedIdentities, f.appleVerifier, store, tokens);
  return { ...f, result, store, create, counts: () => ({ exchanges, revocations }), setFail: (value: boolean) => { fail = value; } };
}
describe("product-scoped Apple authorization revocation", () => {
  it("requires fresh Apple proof, preserves shared identity and sessions, erases credentials after success", async () => {
    const f = await fixture(); const operation = randomUUID(); const service = f.create();
    await assert.rejects(service.execute(f.result.humanIdentityId, operation), (e) => e instanceof AppError && e.code === "APPLE_REAUTH_REQUIRED");
    await service.execute(f.result.humanIdentityId, operation, { authorizationCode: "code", nonce: "b".repeat(40) });
    assert.equal((await f.store.find(operation))?.encryptedToken, null);
    assert.equal((await f.identities.findById(HumanIdentityId.from(f.result.humanIdentityId)))?.status, "active");
    assert.equal((await f.sessions.findById(SessionId.from(f.result.session.sessionId)))?.status, "active");
    assert.equal(f.federatedIdentities.count, 1);
    await service.execute(f.result.humanIdentityId, operation);
    assert.deepEqual(f.counts(), { exchanges: 1, revocations: 1 });
  });
  it("resumes an interrupted revocation using the durable grant without exchanging a consumed code", async () => {
    const f = await fixture(); const operation = randomUUID(); f.setFail(true);
    await assert.rejects(f.create().execute(f.result.humanIdentityId, operation, { authorizationCode: "code", nonce: "b".repeat(40) }));
    assert.equal((await f.store.find(operation))?.encryptedToken, "encrypted:secret");
    f.setFail(false);
    await f.create().execute(f.result.humanIdentityId, operation);
    assert.deepEqual(f.counts(), { exchanges: 1, revocations: 2 });
  });
  it("rejects another Apple subject and an operation belonging to another Human", async () => {
    const f = await fixture(); const operation = randomUUID();
    f.appleVerifier.accept("apple-token", { subject: "different-person" });
    await assert.rejects(f.create().execute(f.result.humanIdentityId, operation, { authorizationCode: "code", nonce: "b".repeat(40) }));
    assert.equal(await f.store.find(operation), null);
    assert.equal(f.counts().revocations, 0);
    await f.store.save({ operationId: operation, principalId: "someone-else", clientId: "com.gamadynamics.GroceryMaster", encryptedToken: null, completedAt: "2026-01-01" });
    await assert.rejects(f.create().execute(f.result.humanIdentityId, operation));
  });
  it("does not require an Apple grant for a password-only Human", async () => {
    const f = await fixture();
    const human = await f.services.register.execute({ email: "other@example.com", password: "correct-password" });
    await f.create().execute(human.humanIdentityId, randomUUID());
    assert.deepEqual(f.counts(), { exchanges: 0, revocations: 0 });
  });
  it("uses only the Grocery client and Apple native token/revoke endpoints with bounded requests", async () => {
    const key = await generateKeyPair("ES256", { extractable: true });
    const calls: string[] = [];
    const tokens = new NativeProductAppleTokens({ clientId: "com.gamadynamics.GroceryMaster", teamId: "TEAM", keyId: "KEY",
      privateKey: await exportPKCS8(key.privateKey), encryptionKey: Buffer.alloc(32, 3).toString("base64") }, async (url, init) => {
      calls.push(String(url));
      assert.ok(init?.signal instanceof AbortSignal);
      const body = new URLSearchParams(init?.body as URLSearchParams);
      assert.equal(body.get("client_id"), "com.gamadynamics.GroceryMaster");
      assert.equal(body.has("redirect_uri"), false);
      const secret = await jwtVerify(body.get("client_secret")!, key.publicKey, { issuer: "TEAM", audience: "https://appleid.apple.com" });
      assert.equal(secret.payload.sub, "com.gamadynamics.GroceryMaster");
      if (String(url).endsWith("/token")) {
        assert.equal(body.get("grant_type"), "authorization_code");
        assert.equal(body.get("code"), "one-time-code");
        return Response.json({ id_token: "identity", refresh_token: "refresh-secret" });
      }
      assert.equal(body.get("token_type_hint"), "refresh_token");
      assert.equal(body.get("token"), "refresh-secret");
      return new Response(null, { status: 200 });
    });
    const grant = await tokens.exchange("one-time-code");
    await tokens.revoke(grant.refreshToken);
    assert.deepEqual(calls, ["https://appleid.apple.com/auth/token", "https://appleid.apple.com/auth/revoke"]);
  });

  it("encrypts retained grants and binds ciphertext to the product, Human and operation", () => {
    const tokens = new NativeProductAppleTokens({ clientId: "com.gamadynamics.GroceryMaster", teamId: "TEAM", keyId: "KEY", privateKey: "unused", encryptionKey: Buffer.alloc(32, 7).toString("base64") });
    const encrypted = tokens.encrypt("apple-refresh-secret", "human:product:operation");
    assert.equal(encrypted.includes("apple-refresh-secret"), false);
    assert.equal(tokens.decrypt(encrypted, "human:product:operation"), "apple-refresh-secret");
    assert.throws(() => tokens.decrypt(encrypted, "other:product:operation"));
    assert.throws(() => tokens.decrypt(encrypted.slice(0, -8) + "AAAAAAAA", "human:product:operation"));
  });
});
