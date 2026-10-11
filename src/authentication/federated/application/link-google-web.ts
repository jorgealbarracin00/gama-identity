import type { SessionId } from "../../../sessions/domain/session-id.js";
import type { WebAuthorizationCodeExchanger } from "../ports/web-authorization-code-exchanger.js";
import type { AuthenticateFederatedWebInput } from "./authenticate-federated-web.js";
import type { FederatedLinkResult, ManageFederatedAuthenticationMethods } from "./manage-federated-authentication-methods.js";

export interface GoogleWebLinkInput extends AuthenticateFederatedWebInput {
  readonly codeVerifier: string;
}

/** Reuses a registered web proof to add Google to the live caller's account. */
export class LinkGoogleWeb {
  constructor(
    private readonly authorizationCodes: WebAuthorizationCodeExchanger,
    private readonly methods: ManageFederatedAuthenticationMethods,
  ) {}

  async execute(sessionId: SessionId, input: GoogleWebLinkInput): Promise<FederatedLinkResult> {
    const target = await this.methods.preflightLink(sessionId);
    const identityToken = await this.authorizationCodes.exchange({
      authorizationCode: input.authorizationCode,
      codeVerifier: input.codeVerifier,
    });
    return this.methods.link(sessionId, {
      provider: "google",
      identityToken,
      nonce: input.nonce,
    }, target);
  }
}
