import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildTestServices } from "../../operational/test-doubles.js";
import { AuthenticateFederated } from "../../../src/authentication/federated/application/authenticate-federated.js";
import { FederatedIdentityTokenVerifiers } from "../../../src/authentication/federated/application/token-verifier.js";
import { FederatedAuthenticationError } from "../../../src/authentication/federated/application/errors.js";
import { CreateSession } from "../../../src/sessions/application/use-cases.js";
import { SessionId } from "../../../src/sessions/domain/session-id.js";
import { FederatedIdentityProvider, FederatedProviderSubject } from "../../../src/authentication/federated/domain/federated-identity.js";

function restricted(data: ReturnType<typeof buildTestServices>, principalIds: string[]) {
  let creationAttempts = 0;
  let sessionsCreated = 0;
  const authentication = new AuthenticateFederated(
    new FederatedIdentityTokenVerifiers([data.appleVerifier]), data.federatedIdentities, data.federatedNonces, data.identities,
    { next() { creationAttempts++; throw new Error("Preview must never create a Human"); } },
    { next() { throw new Error("Preview must never create a provider relationship"); } },
    new CreateSession(data.sessions, { next() { return SessionId.from(`preview-session-${++sessionsCreated}`); } }, data.clock, 3600),
    data.clock, async (work) => work(), new Set(principalIds),
  );
  return { authentication, creations: () => creationAttempts, sessions: () => sessionsCreated };
}

describe("preview existing-principal policy before creation", () => {
  it("denies a verified unknown provider subject before Human, relationship or session creation", async () => {
    const data = buildTestServices();
    data.appleVerifier.accept("unknown-valid-provider-token", { subject: "unknown-test-subject" });
    const policy = restricted(data, ["approved-test-human"]);
    await assert.rejects(policy.authentication.execute({ provider: "apple", identityToken: "unknown-valid-provider-token", nonce: "unknown_nonce_with_at_least_thirty_two_characters" }), (error: unknown) => error instanceof FederatedAuthenticationError && error.code === "IDENTITY_UNAVAILABLE");
    assert.equal(policy.creations(), 0); assert.equal(policy.sessions(), 0);
    assert.equal(await data.federatedIdentities.findByProviderSubject(FederatedIdentityProvider.from("apple"), FederatedProviderSubject.from("unknown-test-subject")), null);
  });
  it("denies an existing unapproved principal before metadata or session mutation", async () => {
    const data = buildTestServices();
    data.appleVerifier.accept("existing-token", { subject: "existing-subject", email: "before@example.test" });
    await data.services.authenticateFederated.execute({ provider: "apple", identityToken: "existing-token", nonce: "initial_nonce_with_at_least_thirty_two_characters" });
    data.appleVerifier.accept("fresh-token", { subject: "existing-subject", email: "after@example.test" });
    const policy = restricted(data, ["different-approved-human"]);
    await assert.rejects(policy.authentication.execute({ provider: "apple", identityToken: "fresh-token", nonce: "fresh_nonce_with_at_least_thirty_two_characters" }), (error: unknown) => error instanceof FederatedAuthenticationError && error.code === "IDENTITY_UNAVAILABLE");
    const relationship = await data.federatedIdentities.findByProviderSubject(FederatedIdentityProvider.from("apple"), FederatedProviderSubject.from("existing-subject"));
    assert.equal(relationship?.providerEmail, "before@example.test"); assert.equal(policy.sessions(), 0); assert.equal(policy.creations(), 0);
  });
  it("permits only the existing verified relationship for an authorized test Human", async () => {
    const data = buildTestServices();
    data.appleVerifier.accept("existing-token", { subject: "approved-subject" });
    const original = await data.services.authenticateFederated.execute({ provider: "apple", identityToken: "existing-token", nonce: "initial_nonce_with_at_least_thirty_two_characters" });
    const policy = restricted(data, [original.humanIdentityId]);
    const result = await policy.authentication.execute({ provider: "apple", identityToken: "existing-token", nonce: "another_nonce_with_at_least_thirty_two_characters" });
    assert.equal(result.humanIdentityId, original.humanIdentityId); assert.equal(result.created, false);
    assert.equal(result.session.sessionId, "preview-session-1"); assert.equal(policy.creations(), 0);
  });
});
