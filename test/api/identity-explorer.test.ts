import { SessionId } from "../../src/sessions/domain/session-id.js";
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { buildApp } from "../../src/api/app.js";
import { buildTestServices } from "../operational/test-doubles.js";
import { inspectionPage } from "../../src/control-plane/application/identity-explorer.js";

const url = "/administration/platform/identities/inspect";
async function fixture() {
  const f = buildTestServices();
  const admin = await f.services.register.execute({ email: "admin@gama.example", password: "correct-password" });
  await f.platformAdministrationProvisioning.bootstrapAdministrator(admin.humanIdentityId, "test-operator");
  const human = await f.services.register.execute({ email: "shared@example.com", password: "correct-password" });
  f.appleVerifier.accept("secret-apple-token", { subject: "secret-apple-subject", email: "SHARED@example.com", emailVerified: true, emailPrivate: false });
  const apple = await f.services.authenticateFederated.execute({ provider: "apple", identityToken: "secret-apple-token", nonce: "explorer_apple_nonce_at_least_32_characters" });
  return { ...f, admin, human, apple };
}

describe("read-only Identity Explorer HTTP authorization and privacy", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => app?.close());

  it("requires a session and current Platform administrator for every mode", async () => {
    const f = await fixture(); app = buildApp(f.services);
    for (const payload of [{ mode: "search", query: "shared" }, { mode: "duplicates" }, { mode: "details", humanIdentityIds: [f.human.humanIdentityId, f.apple.humanIdentityId] }]) {
      assert.equal((await app.inject({ method: "POST", url, payload })).statusCode, 401);
      assert.equal((await app.inject({ method: "POST", url, payload, headers: { authorization: `Bearer ${f.human.session.sessionId}` } })).statusCode, 403);
      assert.equal((await app.inject({ method: "POST", url, payload, headers: { authorization: `Bearer ${f.admin.session.sessionId}` } })).statusCode, 200);
    }
    const membership = await f.controlPlaneRepository.findPlatformAdministrationMembership(f.admin.humanIdentityId); assert.ok(membership);
    await f.controlPlaneRepository.savePlatformAdministrationMembership({ ...membership, status: "suspended" });
    for (const payload of [{ mode: "search", query: "shared" }, { mode: "duplicates" }, { mode: "details", humanIdentityIds: [f.human.humanIdentityId] }]) {
      assert.equal((await app.inject({ method: "POST", url, payload, headers: { authorization: `Bearer ${f.admin.session.sessionId}` } })).statusCode, 403);
    }
  });

  it("finds all lifecycle states by email or Human ID and never serializes secrets", async () => {
    const f = await fixture(); app = buildApp(f.services);
    const headers = { authorization: `Bearer ${f.admin.session.sessionId}` };
    const response = await app.inject({ method: "POST", url, headers, payload: { mode: "search", query: "SHARED@EXAMPLE.COM" } });
    assert.equal(response.statusCode, 200); assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(response.json().identities.length, 2);
    assert.ok(!/passwordHash|password_hash|providerSubject|provider_subject|secret-apple|identityToken|renewalToken|encrypted_token/.test(response.body));
    assert.deepEqual(Object.keys(response.json().identities[0]).sort(), ["humanIdentityId", "displayName", "status", "authenticationMethods", "productAssociations"].sort());
    const provider = (await f.federatedIdentities.listByHumanIdentityId((await f.identities.listForInspection()).find((h) => h.id.value === f.apple.humanIdentityId)!.id))[0]!;
    provider.disable(f.clock); await f.federatedIdentities.save(provider);
    const byId = await app.inject({ method: "POST", url, headers, payload: { mode: "search", query: f.apple.humanIdentityId } });
    assert.equal(byId.json().identities[0].authenticationMethods[0].status, "disabled");
    assert.equal(byId.json().identities[0].authenticationMethods[0].emailVerified, true);
  });

  it("returns repeated email owners and both identities' authentication relationships", async () => {
    const f = await fixture(); app = buildApp(f.services);
    const headers = { authorization: `Bearer ${f.admin.session.sessionId}` };
    const duplicates = await app.inject({ method: "POST", url, headers, payload: { mode: "duplicates" } });
    assert.equal(duplicates.statusCode, 200);
    const groups = duplicates.json().duplicateGroups;
    assert.equal(groups.length, 1); assert.equal(groups[0].email, "shared@example.com");
    assert.deepEqual(new Set(groups[0].humanIdentityIds), new Set([f.human.humanIdentityId, f.apple.humanIdentityId]));
    const details = await app.inject({ method: "POST", url, headers, payload: { mode: "details", humanIdentityIds: groups[0].humanIdentityIds } });
    assert.equal(details.json().identities.length, 2);
    assert.deepEqual(new Set(details.json().identities.flatMap((h: any) => h.authenticationMethods.map((m: any) => m.method))), new Set(["email_password", "apple"]));
  });

  it("includes only recorded Human entitlements, with independent lifecycle statuses", async () => {
    const f = await fixture(); app = buildApp(f.services);
    await f.controlPlaneRepository.saveTenant({ id: "business", displayName: "Test Business", status: "active" });
    for (const id of ["assigned", "unassigned"]) {
      await f.controlPlaneRepository.saveProduct({ id, displayName: id, status: "active" });
      await f.controlPlaneRepository.saveParticipation({ tenantId: "business", productId: id, status: "active" });
    }
    await f.controlPlaneRepository.saveMembership({ tenantId: "business", humanIdentityId: f.human.humanIdentityId, tenantRole: "staff", status: "suspended", createdAt: f.clock.now(), updatedAt: f.clock.now() });
    await f.controlPlaneRepository.saveEntitlement({ tenantId: "business", productId: "assigned", humanIdentityId: f.human.humanIdentityId, status: "retired" });
    const response = await app.inject({ method: "POST", url, headers: { authorization: `Bearer ${f.admin.session.sessionId}` }, payload: { mode: "details", humanIdentityIds: [f.human.humanIdentityId] } });
    const products = response.json().identities[0].productAssociations;
    assert.equal(products.length, 1); assert.equal(products[0].productId, "assigned");
    assert.equal(products[0].entitlementStatus, "retired"); assert.equal(products[0].membershipStatus, "suspended");
  });

  it("audits inspection without search text and fails closed if audit persistence fails", async () => {
    const f = await fixture(); app = buildApp(f.services);
    const options = { method: "POST" as const, url, headers: { authorization: `Bearer ${f.admin.session.sessionId}` }, payload: { mode: "search", query: "shared@example.com" } };
    const before = f.controlPlaneRepository.auditEvents.length;
    assert.equal((await app.inject(options)).statusCode, 200);
    assert.equal(f.controlPlaneRepository.auditEvents.length, before + 1);
    assert.equal(f.controlPlaneRepository.auditEvents.at(-1)?.eventType, "platform.identity.inspected");
    assert.ok(!JSON.stringify(f.controlPlaneRepository.auditEvents.at(-1)).includes("shared@example.com"));
    f.controlPlaneRepository.appendAudit = async () => { throw new Error("audit unavailable"); };
    const rejected = await app.inject(options);
    assert.equal(rejected.statusCode, 500); assert.ok(!rejected.body.includes("shared@example.com"));
  });

  it("rejects unsupported modes, empty/unbounded requests and all mutation verbs", async () => {
    const f = await fixture(); app = buildApp(f.services);
    const headers = { authorization: `Bearer ${f.admin.session.sessionId}` };
    for (const payload of [{ mode: "merge" }, { mode: "search", query: " " }, { mode: "search", query: "x".repeat(321) }, { mode: "details", humanIdentityIds: [] }, { mode: "details", humanIdentityIds: ["a", "b", "c"] }, { mode: "duplicates", password: "secret" }]) {
      assert.equal((await app.inject({ method: "POST", url, headers, payload })).statusCode, 400);
    }
    for (const method of ["GET", "PATCH", "DELETE", "PUT"] as const) assert.equal((await app.inject({ method, url, headers })).statusCode, 404);
  });

  it("denies suspended administrator Humans and tenant workforce roles", async () => {
    const f = await fixture(); app = buildApp(f.services);
    for (const role of ["owner", "admin", "staff"] as const) {
      const worker = await f.services.register.execute({ email: `${role}@example.com`, password: "correct-password" });
      await f.controlPlaneRepository.saveMembership({ tenantId: "test-tenant", humanIdentityId: worker.humanIdentityId, tenantRole: role, status: "active", createdAt: f.clock.now(), updatedAt: f.clock.now() });
      assert.equal((await app.inject({ method: "POST", url, headers: { authorization: `Bearer ${worker.session.sessionId}` }, payload: { mode: "duplicates" } })).statusCode, 403);
    }
    const human = f.identities.listForInspection().find((h) => h.id.value === f.admin.humanIdentityId)!;
    human.suspend(f.clock); await f.identities.save(human);
    for (const payload of [{ mode: "search", query: "shared" }, { mode: "duplicates" }, { mode: "details", humanIdentityIds: [f.human.humanIdentityId] }]) {
      const response: LightMyRequestResponse = await app.inject({ method: "POST", url, headers: { authorization: `Bearer ${f.admin.session.sessionId}` }, payload });
      assert.ok([401, 403].includes(response.statusCode)); assert.ok(!response.body.includes("shared@example.com"));
    }
  });

  it("rejects revoked sessions", async () => {
    const f = await fixture(); app = buildApp(f.services);
    await f.services.logout.execute(SessionId.from(f.admin.session.sessionId));
    assert.equal((await app.inject({ method: "POST", url, headers: { authorization: `Bearer ${f.admin.session.sessionId}` }, payload: { mode: "duplicates" } })).statusCode, 401);
  });
});

describe("identity metadata filtering and pagination", () => {
  it("searches available names and pages by canonical ID", () => {
    const humans = Array.from({ length: 52 }, (_, i) => ({ humanIdentityId: `human-${String(i).padStart(3, "0")}`, displayName: "Available Name", status: "active", authenticationMethods: [] }));
    const first = inspectionPage(humans, { mode: "search", query: "available name" });
    assert.equal(first.identities.length, 50); assert.equal(first.nextCursor, "human-049");
    const second = inspectionPage(humans, { mode: "search", query: "available name", cursor: first.nextCursor! });
    assert.equal(second.identities.length, 2); assert.equal(second.nextCursor, null);
  });
  it("counts distinct Humans, preserving case normalization and inactive/unverified metadata", () => {
    const method = { method: "apple", status: "disabled", email: "Shared@example.com", emailVerified: false };
    const humans = [{ humanIdentityId: "a", displayName: null, status: "retired", authenticationMethods: [method, { ...method, method: "email_password" }] }];
    assert.equal(inspectionPage(humans, { mode: "duplicates" }).duplicateGroups.length, 0);
    const page = inspectionPage([...humans, { ...humans[0]!, humanIdentityId: "b" }], { mode: "duplicates" });
    assert.deepEqual(page.duplicateGroups, [{ email: "shared@example.com", humanIdentityIds: ["a", "b"] }]);
  });
});
