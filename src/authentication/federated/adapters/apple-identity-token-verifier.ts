import { createHash, timingSafeEqual } from "node:crypto";

import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";

import type { Clock } from "../../../shared/clock.js";
import { SystemClock } from "../../../shared/clock.js";
import {
  FederatedIdentityProvider,
  FederatedProviderSubject,
  type FederatedProviderMetadata,
} from "../domain/federated-identity.js";
import { FederatedAuthenticationError } from "../application/errors.js";
import type {
  FederatedCredentialInput,
  FederatedIdentityTokenVerifier,
  VerifiedFederatedCredential,
} from "../application/token-verifier.js";

const appleIssuer = "https://appleid.apple.com";
const appleKeysURL = new URL("https://appleid.apple.com/auth/keys");
const appleProvider = FederatedIdentityProvider.from("apple");
const maximumIdentityTokenLength = 16_384;
const rawNoncePattern = /^[A-Za-z0-9_-]{32,256}$/;

export interface AppleIdentityTokenVerifierOptions {
  readonly clientIds: readonly string[];
  readonly keyResolver?: JWTVerifyGetKey;
  readonly clock?: Clock;
}

export class AppleIdentityTokenVerifier implements FederatedIdentityTokenVerifier {
  readonly provider = appleProvider;
  private readonly clientIds: string[];
  private readonly keyResolver: JWTVerifyGetKey;
  private readonly clock: Clock;

  constructor(options: AppleIdentityTokenVerifierOptions) {
    if (options.clientIds.length === 0 || options.clientIds.some((clientId) => clientId.trim().length === 0)) {
      throw new Error("At least one Apple client identifier is required");
    }
    this.clientIds = [...new Set(options.clientIds)];
    this.keyResolver = options.keyResolver ?? createRemoteJWKSet(appleKeysURL);
    this.clock = options.clock ?? new SystemClock();
  }

  async verify(input: FederatedCredentialInput): Promise<VerifiedFederatedCredential> {
    if (
      input.identityToken.length === 0 ||
      input.identityToken.length > maximumIdentityTokenLength ||
      !rawNoncePattern.test(input.nonce)
    ) {
      throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
    }

    const nonceHash = createHash("sha256").update(input.nonce, "utf8").digest("base64url");
    try {
      const { payload } = await jwtVerify(input.identityToken, this.keyResolver, {
        algorithms: ["RS256"],
        issuer: appleIssuer,
        audience: this.clientIds,
        requiredClaims: ["sub", "iat", "exp", "nonce"],
        currentDate: this.clock.now(),
        clockTolerance: 5,
      });
      if (typeof payload.nonce !== "string" || !constantTimeEqual(payload.nonce, nonceHash)) {
        throw new FederatedAuthenticationError("NONCE_MISMATCH");
      }
      if (typeof payload.sub !== "string" || typeof payload.exp !== "number") {
        throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
      }

      let providerSubject: FederatedProviderSubject;
      try {
        providerSubject = FederatedProviderSubject.from(payload.sub);
      } catch {
        throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
      }
      const metadata = appleMetadata(payload);
      return {
        provider: this.provider,
        providerSubject,
        metadata,
        nonceHash,
        expiresAt: new Date(payload.exp * 1000),
      };
    } catch (error) {
      if (error instanceof FederatedAuthenticationError) throw error;
      throw translateJoseError(error);
    }
  }
}

function appleMetadata(payload: Record<string, unknown>): FederatedProviderMetadata {
  const email = payload.email;
  if (email !== undefined && (typeof email !== "string" || email.length === 0 || email.length > 320)) {
    throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
  }
  return {
    email: typeof email === "string" ? email : null,
    emailVerified: booleanClaim(payload.email_verified),
    emailPrivate: booleanClaim(payload.is_private_email),
  };
}

function booleanClaim(value: unknown): boolean | null {
  if (value === undefined) return null;
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
}

function constantTimeEqual(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
}

function translateJoseError(error: unknown): FederatedAuthenticationError {
  if (error instanceof joseErrors.JWTExpired) {
    return new FederatedAuthenticationError("EXPIRED_CREDENTIAL");
  }
  if (error instanceof joseErrors.JWTClaimValidationFailed) {
    if (error.claim === "iss") return new FederatedAuthenticationError("WRONG_ISSUER");
    if (error.claim === "aud") return new FederatedAuthenticationError("WRONG_AUDIENCE");
    return new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
  }
  if (
    error instanceof joseErrors.JWSSignatureVerificationFailed ||
    error instanceof joseErrors.JWKSNoMatchingKey
  ) {
    return new FederatedAuthenticationError("INVALID_SIGNATURE");
  }
  if (
    error instanceof joseErrors.JWKSTimeout ||
    error instanceof joseErrors.JOSENotSupported
  ) {
    return new FederatedAuthenticationError("VERIFICATION_UNAVAILABLE");
  }
  if (error instanceof joseErrors.JOSEError) {
    return new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
  }
  return new FederatedAuthenticationError("VERIFICATION_UNAVAILABLE");
}

export const APPLE_FEDERATED_PROVIDER = appleProvider;
