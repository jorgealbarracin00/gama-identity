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

import { AppleIdentityTokenVerifier } from "../../../src/authentication/federated/adapters/apple-identity-token-verifier.js";
import { FederatedAuthenticationError } from "../../../src/authentication/federated/application/errors.js";
import { MutableClock } from "../../operational/test-doubles.js";

const issuer = "https://appleid.apple.com";
const audience = "com.gamadynamics.coco";
const rawNonce = "nonce_value_that_is_at_least_thirty_two_characters_123";
const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));

describe("Apple identity-token verification", () => {
  let privateKey: CryptoKey;
  let otherPrivateKey: CryptoKey;
  let verifier: AppleIdentityTokenVerifier;

  before(async () => {
    const primary = await generateKeyPair("RS256", { modulusLength: 2048 });
    const other = await generateKeyPair("RS256", { modulusLength: 2048 });
    privateKey = primary.privateKey;
    otherPrivateKey = other.privateKey;
    const publicJwk: JWK = { ...(await exportJWK(primary.publicKey)), kid: "apple-test-key", alg: "RS256" };
    verifier = new AppleIdentityTokenVerifier({
      clientIds: [audience],
      keyResolver: createLocalJWKSet({ keys: [publicJwk] }),
      clock,
    });
  });

  it("verifies signature, issuer, audience, expiry, nonce, subject and Apple email metadata", async () => {
    const identityToken = await token({
      email: "relay@privaterelay.appleid.com",
      email_verified: "true",
      is_private_email: "true",
    });
    const verified = await verifier.verify({ identityToken, nonce: rawNonce });
    assert.equal(verified.provider.value, "apple");
    assert.equal(verified.providerSubject.value, "apple-subject-1");
    assert.deepEqual(verified.metadata, {
      email: "relay@privaterelay.appleid.com",
      emailVerified: true,
      emailPrivate: true,
    });
  });

  it("rejects malformed credentials and invalid signatures", async () => {
    await rejectsWith("MALFORMED_CREDENTIAL", () => verifier.verify({ identityToken: "not-a-jwt", nonce: rawNonce }));
    await rejectsWith("MALFORMED_CREDENTIAL", async () => verifier.verify({
      identityToken: await token({}, { tokenSubject: "" }),
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
      identityToken: await token({}, { tokenAudience: "com.example.other" }),
      nonce: rawNonce,
    }));
    await rejectsWith("EXPIRED_CREDENTIAL", async () => verifier.verify({
      identityToken: await token({}, { expiresAt: "2025-12-31T23:00:00.000Z" }),
      nonce: rawNonce,
    }));
  });

  it("rejects a nonce mismatch", async () => {
    await rejectsWith("NONCE_MISMATCH", async () => verifier.verify({
      identityToken: await token(),
      nonce: "different_nonce_that_is_at_least_thirty_two_characters_123",
    }));
  });

  it("allows the email claim to be absent on a returning authorization", async () => {
    const verified = await verifier.verify({ identityToken: await token(), nonce: rawNonce });
    assert.deepEqual(verified.metadata, {
      email: null,
      emailVerified: null,
      emailPrivate: null,
    });
  });

  async function token(
    claims: Record<string, unknown> = {},
    options: {
      signingKey?: CryptoKey;
      tokenIssuer?: string;
      tokenAudience?: string;
      tokenSubject?: string;
      expiresAt?: string;
    } = {},
  ): Promise<string> {
    const nonceHash = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawNonce)),
    ).toString("base64url");
    return new SignJWT({ nonce: nonceHash, ...claims })
      .setProtectedHeader({ alg: "RS256", kid: "apple-test-key" })
      .setIssuer(options.tokenIssuer ?? issuer)
      .setAudience(options.tokenAudience ?? audience)
      .setSubject(options.tokenSubject ?? "apple-subject-1")
      .setIssuedAt(Math.floor(clock.now().getTime() / 1000))
      .setExpirationTime(Math.floor(new Date(options.expiresAt ?? "2026-01-01T00:10:00.000Z").getTime() / 1000))
      .sign(options.signingKey ?? privateKey);
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
