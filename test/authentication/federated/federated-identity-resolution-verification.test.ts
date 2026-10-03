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
import {
  InMemoryFederatedAuthenticationNonceRepository,
  InMemoryFederatedIdentityRepository,
} from "../../../src/authentication/federated/adapters/in-memory-federated-identity-repository.js";
import { FederatedAuthenticationError } from "../../../src/authentication/federated/application/errors.js";
import { ResolveFederatedIdentity } from "../../../src/authentication/federated/application/resolve-federated-identity.js";
import { FederatedIdentityTokenVerifiers } from "../../../src/authentication/federated/application/token-verifier.js";
import { MutableClock } from "../../operational/test-doubles.js";

const issuer = "https://appleid.apple.com";
const audience = "com.gamadynamics.GroceryMaster";
const rawNonce = "resolve_apple_nonce_that_is_at_least_thirty_two_characters_123";
const clock = new MutableClock(new Date("2026-01-01T00:00:00.000Z"));

describe("resolve-only Apple credential verification", () => {
  let privateKey: CryptoKey;
  let otherPrivateKey: CryptoKey;
  let verifier: AppleIdentityTokenVerifier;

  before(async () => {
    const primary = await generateKeyPair("RS256", { modulusLength: 2048 });
    const other = await generateKeyPair("RS256", { modulusLength: 2048 });
    privateKey = primary.privateKey;
    otherPrivateKey = other.privateKey;
    const publicJwk: JWK = {
      ...(await exportJWK(primary.publicKey)),
      kid: "apple-resolve-test-key",
      alg: "RS256",
    };
    verifier = new AppleIdentityTokenVerifier({
      clientIds: [audience],
      keyResolver: createLocalJWKSet({ keys: [publicJwk] }),
      clock,
    });
  });

  it("rejects a wrong Apple audience", async () => {
    await rejectsWith("WRONG_AUDIENCE", async () => resolve(
      await token({ tokenAudience: "com.example.other" }),
      rawNonce,
    ));
  });

  it("rejects an invalid Apple signature", async () => {
    await rejectsWith("INVALID_SIGNATURE", async () => resolve(
      await token({ signingKey: otherPrivateKey }),
      rawNonce,
    ));
  });

  it("rejects an expired Apple token", async () => {
    await rejectsWith("EXPIRED_CREDENTIAL", async () => resolve(
      await token({ expiresAt: "2025-12-31T23:00:00.000Z" }),
      rawNonce,
    ));
  });

  it("rejects an Apple nonce mismatch", async () => {
    await rejectsWith("NONCE_MISMATCH", async () => resolve(
      await token(),
      "different_resolve_nonce_that_is_at_least_thirty_two_chars_123",
    ));
  });

  async function resolve(identityToken: string, nonce: string): Promise<unknown> {
    const useCase = new ResolveFederatedIdentity(
      new FederatedIdentityTokenVerifiers([verifier]),
      new InMemoryFederatedIdentityRepository(),
      new InMemoryFederatedAuthenticationNonceRepository(),
      clock,
      async (work) => work(),
    );
    return useCase.execute({ provider: "apple", identityToken, nonce });
  }

  async function token(
    options: {
      signingKey?: CryptoKey;
      tokenAudience?: string;
      expiresAt?: string;
    } = {},
  ): Promise<string> {
    const nonceHash = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawNonce)),
    ).toString("base64url");
    return new SignJWT({ nonce: nonceHash })
      .setProtectedHeader({ alg: "RS256", kid: "apple-resolve-test-key" })
      .setIssuer(issuer)
      .setAudience(options.tokenAudience ?? audience)
      .setSubject("apple-resolve-subject")
      .setIssuedAt(Math.floor(clock.now().getTime() / 1000))
      .setExpirationTime(Math.floor(new Date(
        options.expiresAt ?? "2026-01-01T00:10:00.000Z",
      ).getTime() / 1000))
      .sign(options.signingKey ?? privateKey);
  }
});

async function rejectsWith(
  code: FederatedAuthenticationError["code"],
  operation: () => Promise<unknown>,
): Promise<void> {
  await assert.rejects(
    operation,
    (error: unknown) =>
      error instanceof FederatedAuthenticationError && error.code === code,
  );
}
