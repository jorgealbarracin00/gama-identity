import type {
  WebAuthorizationCodeExchangeInput,
  WebAuthorizationCodeExchanger,
} from "../ports/web-authorization-code-exchanger.js";
import type {
  AuthenticateFederated,
  FederatedAuthenticationResult,
} from "./authenticate-federated.js";

export interface AuthenticateFederatedWebInput extends WebAuthorizationCodeExchangeInput {
  readonly nonce: string;
}

/**
 * Converts a provider's one-time web grant into the same verified credential
 * path used by every federated client. Provider verification, identity mapping,
 * replay protection, and GAMA session creation remain provider-neutral.
 */
export class AuthenticateFederatedWeb {
  constructor(
    private readonly provider: string,
    private readonly authorizationCodes: WebAuthorizationCodeExchanger,
    private readonly authenticateFederated: AuthenticateFederated,
  ) {}

  async execute(input: AuthenticateFederatedWebInput): Promise<FederatedAuthenticationResult> {
    const identityToken = await this.authorizationCodes.exchange(input);
    return this.authenticateFederated.execute({
      provider: this.provider,
      identityToken,
      nonce: input.nonce,
    });
  }
}
