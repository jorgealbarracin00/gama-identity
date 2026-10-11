import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";

import type { Clock } from "../../../shared/clock.js";
import { SystemClock } from "../../../shared/clock.js";
import { FederatedAuthenticationError } from "../application/errors.js";
import type {
  FederatedCredentialInput,
  FederatedIdentityTokenVerifier,
  VerifiedFederatedCredential,
} from "../application/token-verifier.js";
import {
  FederatedIdentityProvider,
  FederatedProviderSubject,
  type FederatedProviderMetadata,
} from "../domain/federated-identity.js";
import {
  constantTimeEqual,
  sha256Base64Url,
  translateOidcJoseError,
} from "./oidc-verification.js";

const googleIssuers = ["https://accounts.google.com", "accounts.google.com"];
const googleKeysURL = new URL("https://www.googleapis.com/oauth2/v3/certs");
const googleProvider = FederatedIdentityProvider.from("google");
const maximumIdentityTokenLength = 16_384;
const rawNoncePattern = /^[A-Za-z0-9_-]{32,256}$/u;

export interface GoogleIdentityTokenVerifierOptions {
  readonly clientIds: readonly string[];
  readonly keyResolver?: JWTVerifyGetKey;
  readonly clock?: Clock;
  /** Recovery-only policy; omission preserves existing product sign-in. */
  readonly maximumAuthenticationAgeSeconds?: number;
}

export class GoogleIdentityTokenVerifier implements FederatedIdentityTokenVerifier {
  readonly provider = googleProvider;
  private readonly clientIds: string[];
  private readonly keyResolver: JWTVerifyGetKey;
  private readonly clock: Clock;
  private readonly maximumAuthenticationAgeSeconds: number | undefined;

  constructor(options: GoogleIdentityTokenVerifierOptions) {
    if (options.clientIds.length === 0 || options.clientIds.some((clientId) => clientId.trim().length === 0)) {
      throw new Error("At least one Google client identifier is required");
    }
    this.clientIds = [...new Set(options.clientIds)];
    this.keyResolver = options.keyResolver ?? createRemoteJWKSet(googleKeysURL);
    this.clock = options.clock ?? new SystemClock();
    const maximumAge=options.maximumAuthenticationAgeSeconds;
    if(maximumAge!==undefined && (!Number.isInteger(maximumAge)||maximumAge<1||maximumAge>300))throw new Error("Recovery authentication age is invalid");
    this.maximumAuthenticationAgeSeconds=maximumAge;
  }

  async verify(input: FederatedCredentialInput): Promise<VerifiedFederatedCredential> {
    if (
      input.identityToken.length === 0 ||
      input.identityToken.length > maximumIdentityTokenLength ||
      !rawNoncePattern.test(input.nonce)
    ) {
      throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
    }

    try {
      const { payload } = await jwtVerify(input.identityToken, this.keyResolver, {
        algorithms: ["RS256"],
        issuer: googleIssuers,
        audience: this.clientIds,
        requiredClaims: ["sub", "iat", "exp", "nonce", ...(this.maximumAuthenticationAgeSeconds===undefined?[]:["auth_time"])],
        currentDate: this.clock.now(),
        clockTolerance: 5,
      });
      if (typeof payload.nonce !== "string" || !constantTimeEqual(payload.nonce, input.nonce)) {
        throw new FederatedAuthenticationError("NONCE_MISMATCH");
      }
      if (typeof payload.sub !== "string" || typeof payload.exp !== "number") {
        throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
      }

      if(this.maximumAuthenticationAgeSeconds!==undefined) {
        if(typeof payload.aud!=="string" || !this.clientIds.includes(payload.aud) ||
          (payload.azp!==undefined && payload.azp!==payload.aud))
          throw new FederatedAuthenticationError("WRONG_AUDIENCE");
        const now=Math.floor(this.clock.now().getTime()/1000),authenticated=payload.auth_time;
        if(typeof authenticated!=="number" || !Number.isInteger(authenticated) || authenticated<0 || authenticated>now+5)
          throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
        if(now-authenticated>this.maximumAuthenticationAgeSeconds)
          throw new FederatedAuthenticationError("EXPIRED_CREDENTIAL");
      }
      let providerSubject: FederatedProviderSubject;
      try {
        providerSubject = FederatedProviderSubject.from(payload.sub);
      } catch {
        throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
      }
      return {
        provider: this.provider,
        providerSubject,
        metadata: googleMetadata(payload),
        nonceHash: sha256Base64Url(input.nonce),
        expiresAt: new Date(payload.exp * 1_000),
      };
    } catch (error) {
      if (error instanceof FederatedAuthenticationError) throw error;
      throw translateOidcJoseError(error);
    }
  }
}

function googleMetadata(payload: Record<string, unknown>): FederatedProviderMetadata {
  const email = payload.email;
  const emailVerified = payload.email_verified;
  if (email !== undefined && (typeof email !== "string" || email.length === 0 || email.length > 320)) {
    throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
  }
  if (emailVerified !== undefined && typeof emailVerified !== "boolean") {
    throw new FederatedAuthenticationError("MALFORMED_CREDENTIAL");
  }
  return {
    email: typeof email === "string" ? email : null,
    emailVerified: typeof emailVerified === "boolean" ? emailVerified : null,
    emailPrivate: null,
  };
}

export const GOOGLE_FEDERATED_PROVIDER = googleProvider;
