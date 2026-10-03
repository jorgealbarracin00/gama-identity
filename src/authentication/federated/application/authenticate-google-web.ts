import type { WebAuthorizationCodeExchanger } from "../ports/web-authorization-code-exchanger.js";
import type { AuthenticateFederated } from "./authenticate-federated.js";
import { AuthenticateFederatedWeb } from "./authenticate-federated-web.js";

export class AuthenticateGoogleWeb extends AuthenticateFederatedWeb {
  constructor(
    authorizationCodes: WebAuthorizationCodeExchanger,
    authenticateFederated: AuthenticateFederated,
  ) {
    super("google", authorizationCodes, authenticateFederated);
  }
}
