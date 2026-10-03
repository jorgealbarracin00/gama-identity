import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FederatedAuthenticationError } from "../../../src/authentication/federated/application/errors.js";
import {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
  type FederatedIdentityStatus,
} from "../../../src/authentication/federated/domain/federated-identity.js";
import { FederatedIdentityId } from "../../../src/authentication/federated/domain/federated-identity-id.js";
import { HumanIdentityId } from "../../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../../src/sessions/domain/session-id.js";
import { buildTestServices } from "../../operational/test-doubles.js";

const nonce = (suffix: string): string =>
  `resolution_nonce_that_is_at_least_thirty_two_chars_${suffix}`;

describe("provider-neutral federated identity resolution", () => {
  for (const status of ["active", "disabled", "retired"] as const) {
    it(`reports EXISTING for a known ${status} relationship without changing it`, async () => {
      const fixture = buildTestServices();
      const subject = `${status}-apple-subject`;
      const existing = relationship(subject, status);
      await fixture.federatedIdentities.save(existing);
      const before = (await findRelationship(fixture, subject))?.snapshot();
      fixture.appleVerifier.accept(`${status}-token`, {
        subject,
        email: "new-metadata@example.com",
        emailVerified: true,
      });

      const result = await fixture.services.resolveFederatedIdentity.execute({
        provider: "apple",
        identityToken: `${status}-token`,
        nonce: nonce(status),
      });

      assert.deepEqual(result, { outcome: "EXISTING" });
      assert.deepEqual((await findRelationship(fixture, subject))?.snapshot(), before);
      assert.equal(fixture.federatedIdentities.count, 1);
      assert.equal(
        await fixture.sessions.findById(SessionId.from("session-1")),
        null,
      );
    });
  }

  it("reports UNLINKED for an unknown verified subject without creating identity state", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("unknown-token", {
      subject: "unknown-apple-subject",
      email: "unknown@example.com",
      emailVerified: true,
    });

    const result = await fixture.services.resolveFederatedIdentity.execute({
      provider: "apple",
      identityToken: "unknown-token",
      nonce: nonce("unknown"),
    });

    assert.deepEqual(result, { outcome: "UNLINKED" });
    assert.equal(fixture.federatedIdentities.count, 0);
    assert.equal(
      await fixture.identities.findById(HumanIdentityId.from("identity-1")),
      null,
    );
    assert.equal(
      await fixture.sessions.findById(SessionId.from("session-1")),
      null,
    );
  });

  it("consumes a successfully verified nonce exactly once", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("first-token", { subject: "unknown-subject" });
    fixture.appleVerifier.accept("replay-token", { subject: "unknown-subject" });
    const inputNonce = nonce("replay");

    assert.deepEqual(
      await fixture.services.resolveFederatedIdentity.execute({
        provider: "apple",
        identityToken: "first-token",
        nonce: inputNonce,
      }),
      { outcome: "UNLINKED" },
    );
    await assert.rejects(
      fixture.services.resolveFederatedIdentity.execute({
        provider: "apple",
        identityToken: "replay-token",
        nonce: inputNonce,
      }),
      (error: unknown) =>
        error instanceof FederatedAuthenticationError &&
        error.code === "CREDENTIAL_REPLAYED",
    );
    assert.equal(fixture.federatedIdentities.count, 0);
  });

  it("rejects unsupported providers before any identity lookup or mutation", async () => {
    const fixture = buildTestServices();
    await assert.rejects(
      fixture.services.resolveFederatedIdentity.execute({
        provider: "microsoft",
        identityToken: "unused-token",
        nonce: nonce("unsupported"),
      }),
      (error: unknown) =>
        error instanceof FederatedAuthenticationError &&
        error.code === "PROVIDER_UNSUPPORTED",
    );
    assert.equal(fixture.federatedIdentities.count, 0);
    assert.equal(
      await fixture.identities.findById(HumanIdentityId.from("identity-1")),
      null,
    );
    assert.equal(
      await fixture.sessions.findById(SessionId.from("session-1")),
      null,
    );
  });
});

function relationship(
  subject: string,
  status: FederatedIdentityStatus,
): FederatedIdentity {
  const timestamp = new Date("2025-12-01T00:00:00.000Z");
  return FederatedIdentity.reconstitute({
    id: FederatedIdentityId.from(`federated-${status}`),
    humanIdentityId: HumanIdentityId.from(`human-${status}`),
    provider: FederatedIdentityProvider.from("apple"),
    providerSubject: FederatedProviderSubject.from(subject),
    providerEmail: "original@example.com",
    providerEmailVerified: true,
    providerEmailPrivate: false,
    status,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

async function findRelationship(
  fixture: ReturnType<typeof buildTestServices>,
  subject: string,
): Promise<FederatedIdentity | null> {
  return fixture.federatedIdentities.findByProviderSubject(
    FederatedIdentityProvider.from("apple"),
    FederatedProviderSubject.from(subject),
  );
}
