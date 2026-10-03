import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";

import { buildApp } from "../../src/api/app.js";
import {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
} from "../../src/authentication/federated/domain/federated-identity.js";
import { FederatedIdentityId } from "../../src/authentication/federated/domain/federated-identity-id.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { buildTestServices } from "../operational/test-doubles.js";

const nonce = (suffix: string): string =>
  `route_resolution_nonce_that_is_at_least_thirty_two_chars_${suffix}`;

describe("federated identity resolve-only HTTP boundary", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => app?.close());

  it("returns only EXISTING for the exact verified relationship", async () => {
    const fixture = buildTestServices();
    const subject = "known-sensitive-subject";
    const humanIdentityId = "known-sensitive-human";
    const providerEmail = "known-sensitive@example.com";
    const identityToken = "known-sensitive-token";
    const rawNonce = nonce("known-sensitive");
    await fixture.federatedIdentities.save(FederatedIdentity.reconstitute({
      id: FederatedIdentityId.from("known-federated-identity"),
      humanIdentityId: HumanIdentityId.from(humanIdentityId),
      provider: FederatedIdentityProvider.from("apple"),
      providerSubject: FederatedProviderSubject.from(subject),
      providerEmail,
      providerEmailVerified: true,
      providerEmailPrivate: false,
      status: "disabled",
      createdAt: fixture.clock.now(),
      updatedAt: fixture.clock.now(),
    }));
    fixture.appleVerifier.accept(identityToken, { subject, email: providerEmail });
    app = buildApp(fixture.services);

    const response = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/resolve",
      payload: { identityToken, nonce: rawNonce },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), { outcome: "EXISTING" });
    for (const sensitive of [
      subject,
      humanIdentityId,
      providerEmail,
      identityToken,
      rawNonce,
      "session",
      "tenant",
      "authority",
    ]) {
      assert.equal(response.body.includes(sensitive), false);
    }
    assert.equal(
      await fixture.sessions.findById(SessionId.from("session-1")),
      null,
    );
  });

  it("returns only UNLINKED for an unknown valid subject and creates nothing", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("unknown-token", {
      subject: "unknown-subject",
      email: "unknown@example.com",
    });
    app = buildApp(fixture.services);

    const response = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/resolve",
      payload: { identityToken: "unknown-token", nonce: nonce("unknown") },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), { outcome: "UNLINKED" });
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

  it("rejects malformed requests and caller-supplied identity or authority fields", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("valid-token", { subject: "verified-subject" });
    app = buildApp(fixture.services);

    const malformed = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/resolve",
      payload: { identityToken: "valid-token" },
    });
    assert.equal(malformed.statusCode, 400);
    assert.equal(malformed.json().error.code, "INVALID_REQUEST");

    for (const injected of [
      { humanIdentityId: "attacker-human" },
      { principalId: "attacker-principal" },
      { email: "attacker@example.com" },
      { subject: "attacker-subject" },
      { providerSubject: "attacker-provider-subject" },
      { tenant: "attacker-tenant" },
      { product: "attacker-product" },
      { role: "owner" },
      { authority: "administrator" },
    ]) {
      const response: LightMyRequestResponse = await app.inject({
        method: "POST",
        url: "/authentication/federated/apple/resolve",
        payload: {
          identityToken: "valid-token",
          nonce: nonce(Object.keys(injected)[0] ?? "field"),
          ...injected,
        },
      });
      assert.equal(response.statusCode, 400);
      assert.equal(response.json().error.code, "INVALID_REQUEST");
    }
    assert.equal(fixture.federatedIdentities.count, 0);
  });

  it("returns safe typed failures for invalid credentials, replay and unsupported providers", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const rawNonce = nonce("invalid");
    const invalid = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/resolve",
      payload: { identityToken: "sensitive-invalid-token", nonce: rawNonce },
    });
    assert.equal(invalid.statusCode, 401);
    assert.equal(invalid.json().error.code, "FEDERATED_CREDENTIAL_INVALID");
    assert.equal(invalid.body.includes("sensitive-invalid-token"), false);
    assert.equal(invalid.body.includes(rawNonce), false);

    fixture.appleVerifier.accept("first-token", { subject: "replay-subject" });
    fixture.appleVerifier.accept("second-token", { subject: "replay-subject" });
    const replayNonce = nonce("replay");
    const first = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/resolve",
      payload: { identityToken: "first-token", nonce: replayNonce },
    });
    const replay = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple/resolve",
      payload: { identityToken: "second-token", nonce: replayNonce },
    });
    assert.equal(first.statusCode, 200);
    assert.equal(replay.statusCode, 401);
    assert.equal(replay.json().error.code, "FEDERATED_CREDENTIAL_INVALID");
    assert.equal(replay.body.includes(replayNonce), false);

    const unsupported = await app.inject({
      method: "POST",
      url: "/authentication/federated/microsoft/resolve",
      payload: { identityToken: "unused-token", nonce: nonce("unsupported") },
    });
    assert.equal(unsupported.statusCode, 400);
    assert.equal(unsupported.json().error.code, "FEDERATED_PROVIDER_UNSUPPORTED");
  });
});
