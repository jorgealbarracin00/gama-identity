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

  it("can persist a future Google relationship while Google authentication stays unsupported", async () => {
    const fixture = buildTestServices();
    const google = FederatedIdentity.create(
      new FederatedIdentityIds(),
      HumanIdentityId.from("future-human"),
      FederatedIdentityProvider.from("google"),
      FederatedProviderSubject.from("google-subject"),
      { email: "future@example.com", emailVerified: true, emailPrivate: false },
      fixture.clock,
    );
    await fixture.federatedIdentities.save(google);
    assert.equal((await fixture.federatedIdentities.findByProviderSubject(
      FederatedIdentityProvider.from("google"),
      FederatedProviderSubject.from("google-subject"),
    ))?.id.value, google.id.value);
    await assert.rejects(
      fixture.services.authenticateFederated.execute({ provider: "google", identityToken: "unused", nonce: nonceA }),
      (error: unknown) => error instanceof FederatedAuthenticationError && error.code === "PROVIDER_UNSUPPORTED",
    );
  });
});
