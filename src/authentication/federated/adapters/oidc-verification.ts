import { createHash, timingSafeEqual } from "node:crypto";

import { errors as joseErrors } from "jose";

import { FederatedAuthenticationError } from "../application/errors.js";

export function sha256Base64Url(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

export function constantTimeEqual(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
}

export function translateOidcJoseError(error: unknown): FederatedAuthenticationError {
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
