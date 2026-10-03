import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FederatedAuthenticationError, FederatedIdentitySubjectConflictError } from "../../../src/authentication/federated/application/errors.js";
import {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
} from "../../../src/authentication/federated/domain/federated-identity.js";
import { HumanIdentityId } from "../../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../../src/sessions/domain/session-id.js";
import { COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID } from "../../../src/control-plane/models.js";
import {
  buildTestServices,
  FederatedIdentityIds,
} from "../../operational/test-doubles.js";

const nonceA = "nonce_A_that_is_at_least_thirty_two_characters_123";
const nonceB = "nonce_B_that_is_at_least_thirty_two_characters_123";

describe("provider-neutral federated authentication", () => {
  it("creates one Human, one Apple FederatedIdentity and one ordinary GAMA session", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("apple-token-1", {
      subject: "apple-subject-1",
      email: "relay@privaterelay.appleid.com",
      emailVerified: true,
      emailPrivate: true,
    });
    const result = await fixture.services.authenticateFederated.execute({
      provider: "apple",
      identityToken: "apple-token-1",
      nonce: nonceA,
    });

    assert.equal(result.created, true);
    assert.equal(result.humanIdentityId, "identity-1");
    assert.equal(result.providerEmail, "relay@privaterelay.appleid.com");
    assert.equal(fixture.federatedIdentities.count, 1);
    assert.equal((await fixture.sessions.findById(SessionId.from(result.session.sessionId)))?.humanIdentityId.value, "identity-1");
    assert.equal(await fixture.credentials.findByHumanIdentityId(HumanIdentityId.from("identity-1")), null);

    const stored = await fixture.federatedIdentities.findByProviderSubject(
      FederatedIdentityProvider.from("apple"),
      FederatedProviderSubject.from("apple-subject-1"),
    );
    assert.equal(stored?.providerEmailPrivate, true);
    assert.equal(stored?.providerEmailVerified, true);
  });

  it("returns the same Human on later Apple logins and preserves email when Apple omits it", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("first-token", { subject: "apple-subject-1", email: "person@example.com" });
    fixture.appleVerifier.accept("returning-token", { subject: "apple-subject-1" });
    const first = await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "first-token", nonce: nonceA });
    const returning = await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "returning-token", nonce: nonceB });

    assert.equal(first.humanIdentityId, returning.humanIdentityId);
    assert.equal(returning.created, false);
    assert.equal(returning.providerEmail, "person@example.com");
    assert.equal(fixture.federatedIdentities.count, 1);
    assert.notEqual(first.session.sessionId, returning.session.sessionId);
  });

  it("serializes concurrent first sign-ins for one provider subject", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("concurrent-1", { subject: "concurrent-subject" });
    fixture.appleVerifier.accept("concurrent-2", { subject: "concurrent-subject" });
    const [first, second] = await Promise.all([
      fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "concurrent-1", nonce: nonceA }),
      fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "concurrent-2", nonce: nonceB }),
    ]);
    assert.equal(first.humanIdentityId, second.humanIdentityId);
    assert.deepEqual([first.created, second.created].sort(), [false, true]);
    assert.equal(fixture.federatedIdentities.count, 1);
  });

  it("rejects nonce replay", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("replayed-token", { subject: "apple-subject-1" });
    await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "replayed-token", nonce: nonceA });
    await assert.rejects(
      fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "replayed-token", nonce: nonceA }),
      (error: unknown) => error instanceof FederatedAuthenticationError && error.code === "CREDENTIAL_REPLAYED",
    );
  });

  it("never silently links an unknown Apple subject to a matching email account", async () => {
    const fixture = buildTestServices();
    const existing = await fixture.services.register.execute({
      email: "wife@gmail.com",
      password: "correct-password",
    });
    fixture.appleVerifier.accept("apple-token", { subject: "APPLE-123", email: "wife@gmail.com", emailVerified: true });
    const apple = await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "apple-token", nonce: nonceA });
    assert.notEqual(apple.humanIdentityId, existing.humanIdentityId);
    assert.equal(apple.humanIdentityId, "identity-2");
  });

  it("does not create workforce or Platform authority", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("apple-token", { subject: "customer-only" });
    const result = await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "apple-token", nonce: nonceA });
    assert.equal(await fixture.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, result.humanIdentityId), null);
    assert.equal(await fixture.controlPlaneRepository.findParticipation(COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID), null);
    assert.equal(await fixture.controlPlaneRepository.findEntitlement(COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID, result.humanIdentityId), null);
    assert.equal(await fixture.controlPlaneRepository.findPlatformAdministrationMembership(result.humanIdentityId), null);
    assert.deepEqual(fixture.controlPlaneRepository.auditEvents, []);
  });

  it("restores existing authorization when the FederatedIdentity already belongs to that Human", async () => {
    const fixture = buildTestServices();
    const existing = await fixture.services.register.execute({ email: "owner@example.com", password: "correct-password" });
    await fixture.services.controlPlane.bootstrapCoco({
      ownerHumanIdentityId: existing.humanIdentityId,
      workloadSecret: "test-workload-secret-at-least-24",
      actorReference: "test:bootstrap",
    });
    await fixture.federatedIdentities.save(FederatedIdentity.create(
      new FederatedIdentityIds(),
      HumanIdentityId.from(existing.humanIdentityId),
      FederatedIdentityProvider.from("apple"),
      FederatedProviderSubject.from("linked-owner"),
      { email: "owner@example.com", emailVerified: true, emailPrivate: false },
      fixture.clock,
    ));
    fixture.appleVerifier.accept("linked-token", { subject: "linked-owner" });
    const login = await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "linked-token", nonce: nonceA });
    assert.equal(login.humanIdentityId, existing.humanIdentityId);
    assert.equal((await fixture.services.controlPlane.workforceContext(login.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID)).workforceContextSatisfied, true);
  });

  it("rejects suspended Humans and does not create another Human", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("first", { subject: "suspended-subject" });
    fixture.appleVerifier.accept("second", { subject: "suspended-subject" });
    const first = await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "first", nonce: nonceA });
    const identity = await fixture.identities.findById(HumanIdentityId.from(first.humanIdentityId));
    assert.ok(identity);
    identity.suspend(fixture.clock);
    await fixture.identities.save(identity);
    await assert.rejects(
      fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "second", nonce: nonceB }),
      (error: unknown) => error instanceof FederatedAuthenticationError && error.code === "IDENTITY_UNAVAILABLE",
    );
    assert.equal(fixture.federatedIdentities.count, 1);
  });

  it("enforces provider-subject uniqueness and permits different subjects", async () => {
    const fixture = buildTestServices();
    const ids = new FederatedIdentityIds();
    const first = FederatedIdentity.create(
      ids,
      HumanIdentityId.from("human-a"),
      FederatedIdentityProvider.from("apple"),
      FederatedProviderSubject.from("same-subject"),
      { email: null, emailVerified: null, emailPrivate: null },
      fixture.clock,
    );
    const conflict = FederatedIdentity.create(
      ids,
      HumanIdentityId.from("human-b"),
      FederatedIdentityProvider.from("apple"),
      FederatedProviderSubject.from("same-subject"),
      { email: null, emailVerified: null, emailPrivate: null },
      fixture.clock,
    );
    await fixture.federatedIdentities.save(first);
    await assert.rejects(fixture.federatedIdentities.save(conflict), FederatedIdentitySubjectConflictError);

    fixture.appleVerifier.accept("other", { subject: "different-subject" });
    const other = await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "other", nonce: nonceA });
    assert.notEqual(other.humanIdentityId, first.humanIdentityId.value);
  });

  it("creates one Human, one Google FederatedIdentity and one ordinary GAMA session", async () => {
    const fixture = buildTestServices();
    fixture.googleVerifier.accept("google-token", {
      subject: "google-subject",
      email: "person@example.com",
      emailVerified: true,
    });
    const result = await fixture.services.authenticateFederated.execute({
      provider: "google",
      identityToken: "google-token",
      nonce: nonceA,
    });
    assert.equal(result.created, true);
    assert.equal(result.humanIdentityId, "identity-1");
    assert.equal(result.providerEmail, "person@example.com");
    assert.equal(fixture.federatedIdentities.count, 1);
    assert.equal(
      (await fixture.sessions.findById(SessionId.from(result.session.sessionId)))?.humanIdentityId.value,
      "identity-1",
    );
    const stored = await fixture.federatedIdentities.findByProviderSubject(
      FederatedIdentityProvider.from("google"),
      FederatedProviderSubject.from("google-subject"),
    );
    assert.equal(stored?.providerEmailVerified, true);
    assert.equal(stored?.providerEmailPrivate, null);
  });

  it("returns the same Human for a returning Google subject", async () => {
    const fixture = buildTestServices();
    fixture.googleVerifier.accept("google-first", { subject: "google-subject", email: "person@example.com" });
    fixture.googleVerifier.accept("google-returning", { subject: "google-subject" });
    const first = await fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "google-first", nonce: nonceA });
    const returning = await fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "google-returning", nonce: nonceB });
    assert.equal(first.humanIdentityId, returning.humanIdentityId);
    assert.equal(returning.created, false);
    assert.equal(returning.providerEmail, "person@example.com");
    assert.equal(fixture.federatedIdentities.count, 1);
    assert.notEqual(first.session.sessionId, returning.session.sessionId);
  });

  it("never merges different Google subjects that present the same email", async () => {
    const fixture = buildTestServices();
    fixture.googleVerifier.accept("google-one", { subject: "google-subject-one", email: "same@example.com", emailVerified: true });
    fixture.googleVerifier.accept("google-two", { subject: "google-subject-two", email: "same@example.com", emailVerified: true });
    const first = await fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "google-one", nonce: nonceA });
    const second = await fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "google-two", nonce: nonceB });
    assert.notEqual(first.humanIdentityId, second.humanIdentityId);
    assert.equal(fixture.federatedIdentities.count, 2);
  });

  it("never merges a Google subject into a password account by matching email", async () => {
    const fixture = buildTestServices();
    const passwordAccount = await fixture.services.register.execute({
      email: "person@example.com",
      password: "correct-password",
    });
    fixture.googleVerifier.accept("google-token", { subject: "google-subject", email: "person@example.com", emailVerified: true });
    const google = await fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "google-token", nonce: nonceA });
    assert.notEqual(google.humanIdentityId, passwordAccount.humanIdentityId);
  });

  it("never merges a Google subject into an Apple identity by matching email", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("apple-token", { subject: "apple-subject", email: "same@example.com", emailVerified: true });
    fixture.googleVerifier.accept("google-token", { subject: "google-subject", email: "same@example.com", emailVerified: true });
    const apple = await fixture.services.authenticateFederated.execute({ provider: "apple", identityToken: "apple-token", nonce: nonceA });
    const google = await fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "google-token", nonce: nonceB });
    assert.notEqual(google.humanIdentityId, apple.humanIdentityId);
    assert.equal(fixture.federatedIdentities.count, 2);
  });

  it("rejects Google nonce replay", async () => {
    const fixture = buildTestServices();
    fixture.googleVerifier.accept("google-token", { subject: "google-subject" });
    await fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "google-token", nonce: nonceA });
    await assert.rejects(
      fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "google-token", nonce: nonceA }),
      (error: unknown) => error instanceof FederatedAuthenticationError && error.code === "CREDENTIAL_REPLAYED",
    );
  });
});
