import assert from "node:assert/strict";
import { before, describe, it } from "node:test";

import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
} from "jose";

import { GoogleIdentityTokenVerifier } from "../../../src/authentication/federated/adapters/google-identity-token-verifier.js";
import { FederatedAuthenticationError } from "../../../src/authentication/federated/application/errors.js";
import { MutableClock } from "../../operational/test-doubles.js";

const issuer = "https://accounts.google.com";
const audience = "123456789.apps.googleusercontent.com";
const rawNonce = "google_nonce_that_is_at_least_thirty_two_characters_123";
const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));

describe("Google identity-token verification", () => {
  let privateKey: CryptoKey;
  let otherPrivateKey: CryptoKey;
  let verifier: GoogleIdentityTokenVerifier;

  before(async () => {
    const primary = await generateKeyPair("RS256", { modulusLength: 2048 });
    const other = await generateKeyPair("RS256", { modulusLength: 2048 });
    privateKey = primary.privateKey;
    otherPrivateKey = other.privateKey;
    const publicJwk: JWK = { ...(await exportJWK(primary.publicKey)), kid: "google-test-key", alg: "RS256" };
    verifier = new GoogleIdentityTokenVerifier({
      clientIds: [audience],
      keyResolver: createLocalJWKSet({ keys: [publicJwk] }),
      clock,
    });
  });

  it("verifies signature, issuer, audience, expiry, raw nonce, subject and email metadata", async () => {
    const verified = await verifier.verify({
      identityToken: await token({ email: "person@example.com", email_verified: true }),
      nonce: rawNonce,
    });
    assert.equal(verified.provider.value, "google");
    assert.equal(verified.providerSubject.value, "google-subject-1");
    assert.deepEqual(verified.metadata, {
      email: "person@example.com",
      emailVerified: true,
      emailPrivate: null,
    });
  });

  it("accepts Google's legacy issuer and absent email claims", async () => {
    const verified = await verifier.verify({
      identityToken: await token({}, { tokenIssuer: "accounts.google.com" }),
      nonce: rawNonce,
    });
    assert.deepEqual(verified.metadata, {
      email: null,
      emailVerified: null,
      emailPrivate: null,
    });
  });

  it("rejects malformed credentials, missing subjects and invalid signatures", async () => {
    await rejectsWith("MALFORMED_CREDENTIAL", () => verifier.verify({ identityToken: "not-a-jwt", nonce: rawNonce }));
    await rejectsWith("MALFORMED_CREDENTIAL", async () => verifier.verify({
      identityToken: await token({}, { tokenSubject: null }),
      nonce: rawNonce,
    }));
    await rejectsWith("INVALID_SIGNATURE", async () => verifier.verify({
      identityToken: await token({}, { signingKey: otherPrivateKey }),
      nonce: rawNonce,
    }));
  });

  it("rejects wrong issuer, wrong audience and expired credentials", async () => {
    await rejectsWith("WRONG_ISSUER", async () => verifier.verify({
      identityToken: await token({}, { tokenIssuer: "https://issuer.invalid" }),
      nonce: rawNonce,
    }));
    await rejectsWith("WRONG_AUDIENCE", async () => verifier.verify({
      identityToken: await token({}, { tokenAudience: "other.apps.googleusercontent.com" }),
      nonce: rawNonce,
    }));
    await rejectsWith("EXPIRED_CREDENTIAL", async () => verifier.verify({
      identityToken: await token({}, { expiresAt: "2025-12-31T23:00:00.000Z" }),
      nonce: rawNonce,
    }));
  });

  it("rejects nonce mismatch and malformed Google email metadata", async () => {
    await rejectsWith("NONCE_MISMATCH", async () => verifier.verify({
      identityToken: await token(),
      nonce: "different_nonce_that_is_at_least_thirty_two_characters_123",
    }));
    await rejectsWith("MALFORMED_CREDENTIAL", async () => verifier.verify({
      identityToken: await token({ email: 42 }),
      nonce: rawNonce,
    }));
    await rejectsWith("MALFORMED_CREDENTIAL", async () => verifier.verify({
      identityToken: await token({ email_verified: "true" }),
      nonce: rawNonce,
    }));
  });

  async function token(
    claims: Record<string, unknown> = {},
    options: {
      signingKey?: CryptoKey;
      tokenIssuer?: string;
      tokenAudience?: string;
      tokenSubject?: string | null;
      expiresAt?: string;
    } = {},
  ): Promise<string> {
    let builder = new SignJWT({ nonce: rawNonce, ...claims })
      .setProtectedHeader({ alg: "RS256", kid: "google-test-key" })
      .setIssuer(options.tokenIssuer ?? issuer)
      .setAudience(options.tokenAudience ?? audience)
      .setIssuedAt(Math.floor(clock.now().getTime() / 1000))
      .setExpirationTime(Math.floor(new Date(options.expiresAt ?? "2026-01-01T00:10:00.000Z").getTime() / 1000));
    if (options.tokenSubject !== null) {
      builder = builder.setSubject(options.tokenSubject ?? "google-subject-1");
    }
    return builder.sign(options.signingKey ?? privateKey);
  }
});

async function rejectsWith(
  code: FederatedAuthenticationError["code"],
  operation: () => Promise<unknown>,
): Promise<void> {
  await assert.rejects(operation, (error: unknown) =>
    error instanceof FederatedAuthenticationError && error.code === code,
  );
}
