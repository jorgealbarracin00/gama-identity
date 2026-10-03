import type {
  WebAuthorizationCodeExchangeInput,
  WebAuthorizationCodeExchanger,
} from "../ports/web-authorization-code-exchanger.js";

const googleTokenEndpoint = "https://oauth2.googleapis.com/token";
const maximumAuthorizationCodeLength = 4_096;
const maximumIdentityTokenLength = 16_384;
const codeVerifierPattern = /^[A-Za-z0-9._~-]{43,128}$/u;

export type GoogleAuthorizationCodeExchangeFailure =
  | "AUTHORIZATION_CODE_REJECTED"
  | "TOKEN_EXCHANGE_UNAVAILABLE";

export class GoogleAuthorizationCodeExchangeError extends Error {
  constructor(readonly code: GoogleAuthorizationCodeExchangeFailure) {
    super(code);
    this.name = "GoogleAuthorizationCodeExchangeError";
  }
}

export interface GoogleAuthorizationCodeExchangerOptions {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly request?: typeof fetch;
}

/** Exchanges a one-time Google web authorization grant entirely server-side. */
export class GoogleWebAuthorizationCodeExchanger implements WebAuthorizationCodeExchanger {
  private readonly request: typeof fetch;

  constructor(private readonly options: GoogleAuthorizationCodeExchangerOptions) {
    this.request = options.request ?? fetch;
  }

  async exchange(input: WebAuthorizationCodeExchangeInput): Promise<string> {
    if (
      input.authorizationCode.length === 0 ||
      input.authorizationCode.length > maximumAuthorizationCodeLength ||
      /[\u0000-\u001f\u007f]/u.test(input.authorizationCode) ||
      input.codeVerifier === undefined ||
      !codeVerifierPattern.test(input.codeVerifier)
    ) {
      throw new GoogleAuthorizationCodeExchangeError("AUTHORIZATION_CODE_REJECTED");
    }

    let response: Response;
    try {
      response = await this.request(googleTokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: this.options.clientId,
          client_secret: this.options.clientSecret,
          code: input.authorizationCode,
          code_verifier: input.codeVerifier,
          grant_type: "authorization_code",
          redirect_uri: this.options.redirectUri,
        }),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new GoogleAuthorizationCodeExchangeError("TOKEN_EXCHANGE_UNAVAILABLE");
    }

    const body = await response.json().catch(() => null) as {
      id_token?: unknown;
      error?: unknown;
    } | null;
    if (!response.ok) {
      const code = body?.error;
      if (code === "invalid_grant" || code === "invalid_request") {
        throw new GoogleAuthorizationCodeExchangeError("AUTHORIZATION_CODE_REJECTED");
      }
      throw new GoogleAuthorizationCodeExchangeError("TOKEN_EXCHANGE_UNAVAILABLE");
    }
    if (
      typeof body?.id_token !== "string" ||
      body.id_token.length === 0 ||
      body.id_token.length > maximumIdentityTokenLength
    ) {
      throw new GoogleAuthorizationCodeExchangeError("TOKEN_EXCHANGE_UNAVAILABLE");
    }
    return body.id_token;
  }
}
