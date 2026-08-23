import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { FastifyInstance } from "fastify";

import { buildApp } from "../../src/api/app.js";
import { FederatedIdentityProvider, FederatedProviderSubject } from "../../src/authentication/federated/domain/federated-identity.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { buildTestServices } from "../operational/test-doubles.js";

const nonce = (suffix: string): string => `linking_nonce_that_is_at_least_thirty_two_chars_${suffix}`;

describe("authenticated federated account linking HTTP boundary", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => app?.close());

  it("links Apple to the authenticated Human and future Apple sign-in resolves the same Human", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const registration = await register(app);
    fixture.appleVerifier.accept("apple-link-token", {
      subject: "apple-subject-a",
      email: "relay@privaterelay.appleid.com",
      emailVerified: true,
      emailPrivate: true,
    });

    const linked = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/link",
      headers: bearer(registration.sessionId),
      payload: { identityToken: "apple-link-token", nonce: nonce("first") },
    });
    assert.equal(linked.statusCode, 200);
    assert.equal(linked.json().outcome, "linked");
    assert.equal(linked.json().humanIdentityId, registration.humanIdentityId);
    assert.equal(linked.json().methods.emailPassword.connected, true);
    assert.deepEqual(linked.json().methods.federated, [{
      provider: "apple",
      email: "relay@privaterelay.appleid.com",
      emailPrivate: true,
    }]);
    assert.equal(linked.body.includes("apple-subject-a"), false);

    fixture.appleVerifier.accept("apple-login-token", { subject: "apple-subject-a" });
    const appleLogin = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "apple-login-token", nonce: nonce("login") },
    });
    assert.equal(appleLogin.statusCode, 200);
    assert.equal(appleLogin.json().session.humanIdentityId, registration.humanIdentityId);
    assert.equal(fixture.federatedIdentities.count, 1);
  });

  it("is idempotent, never replaces the established session, and exposes provider-neutral methods", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const registration = await register(app);
    fixture.appleVerifier.accept("first-link", { subject: "stable-subject" });
    fixture.appleVerifier.accept("second-link", { subject: "stable-subject" });

    const first = await link(app, registration.sessionId, "first-link", "one");
    const second = await link(app, registration.sessionId, "second-link", "two");
    assert.equal(first.json().outcome, "linked");
    assert.equal(second.json().outcome, "already_linked");
    assert.equal(fixture.federatedIdentities.count, 1);

    const session = await fixture.sessions.findById(SessionId.from(registration.sessionId));
    assert.equal(session?.humanIdentityId.value, registration.humanIdentityId);
    const methods = await app.inject({
      method: "GET",
      url: "/authentication/methods",
      headers: bearer(registration.sessionId),
    });
    assert.equal(methods.statusCode, 200);
    assert.equal(methods.json().methods.humanIdentityId, registration.humanIdentityId);
    assert.equal(methods.json().methods.federated[0].provider, "apple");
  });

  it("requires a live GAMA session and rejects invalid credentials and replayed nonces", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const registration = await register(app);

    const missing = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/link",
      payload: { identityToken: "never-verified", nonce: nonce("missing") },
    });
    assert.equal(missing.statusCode, 401);
    assert.equal(missing.json().error.code, "SESSION_INVALID");

    const rejected = await link(app, registration.sessionId, "invalid-signature", "invalid-signature");
    assert.equal(rejected.statusCode, 401);
    assert.equal(rejected.json().error.code, "FEDERATED_CREDENTIAL_INVALID");
    assert.equal(fixture.federatedIdentities.count, 0);

    fixture.appleVerifier.accept("first-use", { subject: "replay-subject" });
    fixture.appleVerifier.accept("replayed-use", { subject: "replay-subject" });
    const first = await link(app, registration.sessionId, "first-use", "same-nonce");
    const replayed = await link(app, registration.sessionId, "replayed-use", "same-nonce");
    assert.equal(first.statusCode, 200);
    assert.equal(replayed.statusCode, 401);
    assert.equal(replayed.json().error.code, "FEDERATED_CREDENTIAL_INVALID");

    const revokedRegistration = await register(app, "revoked@example.com");
    await app.inject({ method: "POST", url: "/logout", headers: bearer(revokedRegistration.sessionId) });
    const revoked = await link(app, revokedRegistration.sessionId, "never-verified", "revoked");
    assert.equal(revoked.statusCode, 401);
    assert.equal(revoked.json().error.code, "SESSION_REVOKED");

    const expiringRegistration = await register(app, "expired@example.com");
    fixture.clock.set(new Date("2026-01-01T02:00:00.000Z"));
    const expired = await link(app, expiringRegistration.sessionId, "never-verified", "expired");
    assert.equal(expired.statusCode, 401);
    assert.equal(expired.json().error.code, "SESSION_EXPIRED");
  });

  it("never links by email equality and rejects a provider identity owned by a meaningful Human", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const canonical = await register(app, "same@example.com");
    fixture.appleVerifier.accept("matching-email-login", {
      subject: "matching-email-subject",
      email: "same@example.com",
      emailVerified: true,
    });
    const appleLogin = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "matching-email-login", nonce: nonce("matching-email-login") },
    });
    assert.equal(appleLogin.statusCode, 200);
    assert.notEqual(appleLogin.json().session.humanIdentityId, canonical.humanIdentityId);

    const other = await register(app, "other@example.com");
    fixture.appleVerifier.accept("other-link", { subject: "meaningful-subject" });
    assert.equal((await link(app, other.sessionId, "other-link", "other-link")).statusCode, 200);
    fixture.appleVerifier.accept("canonical-conflict", { subject: "meaningful-subject" });
    const conflict = await link(app, canonical.sessionId, "canonical-conflict", "canonical-conflict");
    assert.equal(conflict.statusCode, 409);
    assert.equal(conflict.json().error.code, "FEDERATED_IDENTITY_RECONCILIATION_REQUIRED");
  });

  it("rejects caller-selected identity data and a different Apple subject for an already-linked Human", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const registration = await register(app);
    fixture.appleVerifier.accept("first", { subject: "first-subject" });
    fixture.appleVerifier.accept("different", { subject: "different-subject" });
    await link(app, registration.sessionId, "first", "first");

    const injected = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/link",
      headers: bearer(registration.sessionId),
      payload: {
        identityToken: "different",
        nonce: nonce("injected"),
        humanIdentityId: "attacker-selected",
        subject: "attacker-subject",
        tenantId: "attacker-tenant",
      },
    });
    assert.equal(injected.statusCode, 400);
    assert.equal(injected.json().error.code, "INVALID_REQUEST");

    const conflict = await link(app, registration.sessionId, "different", "different");
    assert.equal(conflict.statusCode, 409);
    assert.equal(conflict.json().error.code, "FEDERATED_IDENTITY_LINK_CONFLICT");
    assert.equal(fixture.federatedIdentities.count, 1);
  });

  it("reconciles only a signed-out pristine Apple-only duplicate and records redacted audit evidence", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const canonical = await register(app);
    fixture.appleVerifier.accept("duplicate-login", { subject: "duplicate-subject" });
    const duplicateLogin = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "duplicate-login", nonce: nonce("duplicate-login") },
    });
    const duplicateSessionId = duplicateLogin.json().session.sessionId as string;
    const duplicateHumanIdentityId = duplicateLogin.json().session.humanIdentityId as string;

    fixture.appleVerifier.accept("blocked-link", { subject: "duplicate-subject" });
    const activeConflict = await link(app, canonical.sessionId, "blocked-link", "blocked");
    assert.equal(activeConflict.statusCode, 409);
    assert.equal(activeConflict.json().error.code, "FEDERATED_IDENTITY_RECONCILIATION_REQUIRED");

    await app.inject({ method: "POST", url: "/logout", headers: bearer(duplicateSessionId) });
    fixture.appleVerifier.accept("reconcile-link", { subject: "duplicate-subject" });
    const reconciled = await link(app, canonical.sessionId, "reconcile-link", "reconcile");
    assert.equal(reconciled.statusCode, 200);
    assert.equal(reconciled.json().outcome, "reconciled");
    assert.equal(reconciled.json().humanIdentityId, canonical.humanIdentityId);

    const duplicate = await fixture.identities.findById(HumanIdentityId.from(duplicateHumanIdentityId));
    assert.equal(duplicate?.status, "retired");
    const relationship = await fixture.federatedIdentities.findByProviderSubject(
      FederatedIdentityProvider.from("apple"),
      FederatedProviderSubject.from("duplicate-subject"),
    );
    assert.equal(relationship?.humanIdentityId.value, canonical.humanIdentityId);
    assert.equal(fixture.federatedIdentities.count, 1);

    const auditText = JSON.stringify(fixture.controlPlaneRepository.auditEvents);
    assert.match(auditText, /authentication\.identity\.reconciled/);
    assert.match(auditText, /authentication\.method\.linked/);
    assert.doesNotMatch(auditText, /duplicate-subject|duplicate-login|reconcile-link|linking_nonce/);
  });

  it("refuses reconciliation when the other Human has any GAMA authority", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const canonical = await register(app);
    fixture.appleVerifier.accept("authority-login", { subject: "authority-subject" });
    const duplicateLogin = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "authority-login", nonce: nonce("authority-login") },
    });
    const duplicateSessionId = duplicateLogin.json().session.sessionId as string;
    const duplicateHumanIdentityId = duplicateLogin.json().session.humanIdentityId as string;
    await app.inject({ method: "POST", url: "/logout", headers: bearer(duplicateSessionId) });
    await fixture.controlPlaneRepository.saveMembership({
      tenantId: "tenant-with-data",
      humanIdentityId: duplicateHumanIdentityId,
      tenantRole: "staff",
      status: "retired",
      createdAt: fixture.clock.now(),
      updatedAt: fixture.clock.now(),
    });

    fixture.appleVerifier.accept("authority-link", { subject: "authority-subject" });
    const conflict = await link(app, canonical.sessionId, "authority-link", "authority-link");
    assert.equal(conflict.statusCode, 409);
    assert.equal(conflict.json().error.code, "FEDERATED_IDENTITY_RECONCILIATION_REQUIRED");
    assert.equal((await fixture.identities.findById(HumanIdentityId.from(duplicateHumanIdentityId)))?.status, "active");
  });

  it("retains canonical authority without manufacturing authority for the duplicate", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const canonical = await register(app);
    const now = fixture.clock.now();
    await fixture.controlPlaneRepository.savePlatformAdministrationMembership({
      humanIdentityId: canonical.humanIdentityId,
      platformRole: "administrator",
      status: "active",
      createdAt: now,
      updatedAt: now,
    });
    await fixture.controlPlaneRepository.saveMembership({
      tenantId: "coco-development",
      humanIdentityId: canonical.humanIdentityId,
      tenantRole: "owner",
      status: "active",
      createdAt: now,
      updatedAt: now,
    });
    await fixture.controlPlaneRepository.saveParticipation({
      tenantId: "coco-development",
      productId: "coco-the-llama",
      status: "active",
    });
    await fixture.controlPlaneRepository.saveEntitlement({
      tenantId: "coco-development",
      productId: "coco-the-llama",
      humanIdentityId: canonical.humanIdentityId,
      status: "active",
    });

    fixture.appleVerifier.accept("authority-duplicate-login", { subject: "authority-duplicate-subject" });
    const duplicateLogin = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "authority-duplicate-login", nonce: nonce("authority-duplicate-login") },
    });
    const duplicateSessionId = duplicateLogin.json().session.sessionId as string;
    const duplicateHumanIdentityId = duplicateLogin.json().session.humanIdentityId as string;
    await app.inject({ method: "POST", url: "/logout", headers: bearer(duplicateSessionId) });

    fixture.appleVerifier.accept("authority-reconcile", { subject: "authority-duplicate-subject" });
    const reconciled = await link(app, canonical.sessionId, "authority-reconcile", "authority-reconcile");
    assert.equal(reconciled.statusCode, 200);
    assert.equal(reconciled.json().outcome, "reconciled");
    assert.equal((await fixture.controlPlaneRepository.findPlatformAdministrationMembership(canonical.humanIdentityId))?.platformRole, "administrator");
    assert.deepEqual(
      await fixture.controlPlaneRepository.findMembership("coco-development", canonical.humanIdentityId),
      {
        tenantId: "coco-development",
        humanIdentityId: canonical.humanIdentityId,
        tenantRole: "owner",
        status: "active",
        createdAt: now,
        updatedAt: now,
      },
    );
    assert.equal((await fixture.controlPlaneRepository.findParticipation("coco-development", "coco-the-llama"))?.status, "active");
    assert.equal((await fixture.controlPlaneRepository.findEntitlement(
      "coco-development",
      "coco-the-llama",
      canonical.humanIdentityId,
    ))?.status, "active");
    assert.equal(await fixture.controlPlaneRepository.findPlatformAdministrationMembership(duplicateHumanIdentityId), null);
    assert.deepEqual(await fixture.controlPlaneRepository.listMembershipsForHuman(duplicateHumanIdentityId), []);
    assert.deepEqual(await fixture.controlPlaneRepository.listEntitlementsForHumanAcrossTenants(duplicateHumanIdentityId), []);
  });

  it("revokes stale duplicate sessions while retiring a reconciled Human", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    fixture.appleVerifier.accept("stale-duplicate-login", { subject: "stale-duplicate-subject" });
    const duplicateLogin = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "stale-duplicate-login", nonce: nonce("stale-duplicate-login") },
    });
    const duplicateSessionId = duplicateLogin.json().session.sessionId as string;
    fixture.clock.set(new Date("2026-01-01T02:00:00.000Z"));
    const canonical = await register(app, "later-canonical@example.com");
    fixture.appleVerifier.accept("stale-duplicate-reconcile", {
      subject: "stale-duplicate-subject",
      expiresAt: new Date("2026-01-01T03:00:00.000Z"),
    });

    const reconciled = await link(app, canonical.sessionId, "stale-duplicate-reconcile", "stale-duplicate-reconcile");
    assert.equal(reconciled.statusCode, 200);
    assert.equal(reconciled.json().outcome, "reconciled");
    assert.equal((await fixture.sessions.findById(SessionId.from(duplicateSessionId)))?.status, "revoked");
  });

  it("serializes concurrent linking, duplicate reconciliation, and login races without duplicate subjects", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const sameHuman = await register(app, "same-human@example.com");
    fixture.appleVerifier.accept("same-human-one", { subject: "same-human-subject" });
    fixture.appleVerifier.accept("same-human-two", { subject: "same-human-subject" });
    const sameHumanRace = await Promise.all([
      link(app, sameHuman.sessionId, "same-human-one", "same-human-one"),
      link(app, sameHuman.sessionId, "same-human-two", "same-human-two"),
    ]);
    assert.deepEqual(
      sameHumanRace.map((response) => response.json().outcome).sort(),
      ["already_linked", "linked"],
    );

    const firstHuman = await register(app, "first@example.com");
    const secondHuman = await register(app, "second@example.com");
    fixture.appleVerifier.accept("parallel-first", { subject: "parallel-subject" });
    fixture.appleVerifier.accept("parallel-second", { subject: "parallel-subject" });
    const parallel = await Promise.all([
      link(app, firstHuman.sessionId, "parallel-first", "parallel-first"),
      link(app, secondHuman.sessionId, "parallel-second", "parallel-second"),
    ]);
    assert.deepEqual(parallel.map((response) => response.statusCode).sort(), [200, 409]);
    assert.equal(fixture.federatedIdentities.count, 2);

    const raceHuman = await register(app, "login-link-race@example.com");
    fixture.appleVerifier.accept("race-link", { subject: "login-link-race-subject" });
    fixture.appleVerifier.accept("race-login", { subject: "login-link-race-subject" });
    const [linkRace, loginRace] = await Promise.all([
      link(app, raceHuman.sessionId, "race-link", "race-link"),
      app.inject({
        method: "POST",
        url: "/authentication/federated/apple",
        payload: { identityToken: "race-login", nonce: nonce("race-login") },
      }),
    ]);
    assert.equal(loginRace.statusCode, 200);
    assert.ok(linkRace.statusCode === 200 || linkRace.statusCode === 409);
    const racedRelationship = await fixture.federatedIdentities.findByProviderSubject(
      FederatedIdentityProvider.from("apple"),
      FederatedProviderSubject.from("login-link-race-subject"),
    );
    assert.notEqual(racedRelationship, null);
    if (linkRace.statusCode === 200) {
      assert.equal(racedRelationship?.humanIdentityId.value, raceHuman.humanIdentityId);
      assert.equal(loginRace.json().session.humanIdentityId, raceHuman.humanIdentityId);
    } else {
      assert.equal(linkRace.json().error.code, "FEDERATED_IDENTITY_RECONCILIATION_REQUIRED");
      assert.equal(racedRelationship?.humanIdentityId.value, loginRace.json().session.humanIdentityId);
    }

    const duplicateFixture = buildTestServices();
    const duplicateApp = buildApp(duplicateFixture.services);
    const canonical = await register(duplicateApp, "duplicate-race@example.com");
    duplicateFixture.appleVerifier.accept("duplicate-race-login", { subject: "duplicate-race-subject" });
    const duplicateLogin = await duplicateApp.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "duplicate-race-login", nonce: nonce("duplicate-race-login") },
    });
    await duplicateApp.inject({
      method: "POST",
      url: "/logout",
      headers: bearer(duplicateLogin.json().session.sessionId),
    });
    duplicateFixture.appleVerifier.accept("duplicate-race-one", { subject: "duplicate-race-subject" });
    duplicateFixture.appleVerifier.accept("duplicate-race-two", { subject: "duplicate-race-subject" });
    const reconciliationRace = await Promise.all([
      link(duplicateApp, canonical.sessionId, "duplicate-race-one", "duplicate-race-one"),
      link(duplicateApp, canonical.sessionId, "duplicate-race-two", "duplicate-race-two"),
    ]);
    assert.deepEqual(
      reconciliationRace.map((response) => response.json().outcome).sort(),
      ["already_linked", "reconciled"],
    );
    assert.equal(duplicateFixture.federatedIdentities.count, 1);
    await duplicateApp.close();
  });

  it("allows safe unlink but never removes the last sign-in method", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const emailHuman = await register(app);
    fixture.appleVerifier.accept("email-link", { subject: "unlinkable-subject" });
    await link(app, emailHuman.sessionId, "email-link", "email-link");
    const unlinked = await app.inject({
      method: "DELETE",
      url: "/authentication/federated/apple/link",
      headers: bearer(emailHuman.sessionId),
    });
    assert.equal(unlinked.statusCode, 200);
    assert.equal(unlinked.json().outcome, "unlinked");
    assert.equal(unlinked.json().methods.federated.length, 0);

    fixture.appleVerifier.accept("apple-only-login", { subject: "last-method-subject" });
    const appleOnly = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "apple-only-login", nonce: nonce("apple-only") },
    });
    const appleOnlyMethods = await app.inject({
      method: "GET",
      url: "/authentication/methods",
      headers: bearer(appleOnly.json().session.sessionId),
    });
    assert.equal(appleOnlyMethods.statusCode, 200);
    assert.equal(appleOnlyMethods.json().methods.emailPassword.connected, false);
    assert.deepEqual(appleOnlyMethods.json().methods.federated.map((value: { provider: string }) => value.provider), ["apple"]);
    assert.equal(appleOnlyMethods.body.includes("last-method-subject"), false);
    const lastMethod = await app.inject({
      method: "DELETE",
      url: "/authentication/federated/apple/link",
      headers: bearer(appleOnly.json().session.sessionId),
    });
    assert.equal(lastMethod.statusCode, 409);
    assert.equal(lastMethod.json().error.code, "LAST_AUTHENTICATION_METHOD");
  });
});

async function register(
  app: FastifyInstance,
  email = "owner@example.com",
): Promise<{ sessionId: string; humanIdentityId: string }> {
  const response = await app.inject({
    method: "POST",
    url: "/register",
    payload: { email, password: "correct-password" },
  });
  assert.equal(response.statusCode, 201);
  return {
    sessionId: response.json().session.sessionId,
    humanIdentityId: response.json().session.humanIdentityId,
  };
}

function bearer(sessionId: string): { authorization: string } {
  return { authorization: `Bearer ${sessionId}` };
}

function link(
  app: FastifyInstance,
  sessionId: string,
  identityToken: string,
  nonceSuffix: string,
) {
  return app.inject({
    method: "POST",
    url: "/authentication/federated/apple/link",
    headers: bearer(sessionId),
    payload: { identityToken, nonce: nonce(nonceSuffix) },
  });
}
