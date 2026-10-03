import { importPKCS8, SignJWT, type CryptoKey } from "jose";

import type { Clock } from "../../../shared/clock.js";
import { SystemClock } from "../../../shared/clock.js";
import type { AppleAuthorizationCodeExchanger } from "../ports/apple-authorization-code-exchanger.js";

const appleTokenEndpoint = "https://appleid.apple.com/auth/token";
const appleAudience = "https://appleid.apple.com";
const maximumAuthorizationCodeLength = 4_096;
const maximumIdentityTokenLength = 16_384;

export type AppleAuthorizationCodeExchangeFailure =
  | "AUTHORIZATION_CODE_REJECTED"
  | "TOKEN_EXCHANGE_UNAVAILABLE";

export class AppleAuthorizationCodeExchangeError extends Error {
  constructor(readonly code: AppleAuthorizationCodeExchangeFailure) {
    super(code);
    this.name = "AppleAuthorizationCodeExchangeError";
  }
}

export interface AppleAuthorizationCodeExchangerOptions {
  readonly clientId: string;
  readonly teamId: string;
  readonly keyId: string;
  readonly privateKey: string;
  readonly redirectUri: string;
  readonly request?: typeof fetch;
  readonly clock?: Clock;
}

/** Exchanges a one-time Apple web authorization grant entirely server-side. */
export class AppleWebAuthorizationCodeExchanger implements AppleAuthorizationCodeExchanger {
  private readonly signingKey: Promise<CryptoKey>;
  private readonly request: typeof fetch;
  private readonly clock: Clock;

  constructor(private readonly options: AppleAuthorizationCodeExchangerOptions) {
    this.signingKey = importPKCS8(options.privateKey.replace(/\\n/g, "\n"), "ES256");
    this.request = options.request ?? fetch;
    this.clock = options.clock ?? new SystemClock();
  }

  async exchange(authorizationCode: string): Promise<string> {
    if (
      authorizationCode.length === 0 ||
      authorizationCode.length > maximumAuthorizationCodeLength ||
      /[\u0000-\u001f\u007f]/u.test(authorizationCode)
    ) {
      throw new AppleAuthorizationCodeExchangeError("AUTHORIZATION_CODE_REJECTED");
    }

    const now = Math.floor(this.clock.now().getTime() / 1_000);
    let clientSecret: string;
    try {
      clientSecret = await new SignJWT({})
        .setProtectedHeader({ alg: "ES256", kid: this.options.keyId })
        .setIssuer(this.options.teamId)
        .setSubject(this.options.clientId)
        .setAudience(appleAudience)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(await this.signingKey);
    } catch {
      throw new AppleAuthorizationCodeExchangeError("TOKEN_EXCHANGE_UNAVAILABLE");
    }

    let response: Response;
    try {
      response = await this.request(appleTokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: this.options.clientId,
          client_secret: clientSecret,
          code: authorizationCode,
          grant_type: "authorization_code",
          redirect_uri: this.options.redirectUri,
        }),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new AppleAuthorizationCodeExchangeError("TOKEN_EXCHANGE_UNAVAILABLE");
    }

    const body = await response.json().catch(() => null) as {
      id_token?: unknown;
      error?: unknown;
    } | null;
    if (!response.ok) {
      const code = body?.error;
      if (code === "invalid_grant" || code === "invalid_request") {
        throw new AppleAuthorizationCodeExchangeError("AUTHORIZATION_CODE_REJECTED");
      }
      throw new AppleAuthorizationCodeExchangeError("TOKEN_EXCHANGE_UNAVAILABLE");
    }
    if (
      typeof body?.id_token !== "string" ||
      body.id_token.length === 0 ||
      body.id_token.length > maximumIdentityTokenLength
    ) {
      throw new AppleAuthorizationCodeExchangeError("TOKEN_EXCHANGE_UNAVAILABLE");
    }
    return body.id_token;
  }
}
