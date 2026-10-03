import type { AuthenticateFederated, FederatedAuthenticationResult } from "./authenticate-federated.js";
import type { AppleAuthorizationCodeExchanger } from "../ports/apple-authorization-code-exchanger.js";

export interface AuthenticateAppleWebInput {
  readonly authorizationCode: string;
  readonly nonce: string;
}

/**
 * Converts Apple's short-lived web authorization grant into the same verified
 * credential path used by native Coco clients. Identity mapping and GAMA
 * session creation remain owned by AuthenticateFederated.
 */
export class AuthenticateAppleWeb {
  constructor(
    private readonly authorizationCodes: AppleAuthorizationCodeExchanger,
    private readonly authenticateFederated: AuthenticateFederated,
  ) {}

  async execute(input: AuthenticateAppleWebInput): Promise<FederatedAuthenticationResult> {
    const identityToken = await this.authorizationCodes.exchange(input.authorizationCode);
    return this.authenticateFederated.execute({
      provider: "apple",
      identityToken,
      nonce: input.nonce,
    });
  }
}
