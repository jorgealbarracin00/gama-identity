import type { AuthenticateFederated } from "./authenticate-federated.js";
import type { AppleAuthorizationCodeExchanger } from "../ports/apple-authorization-code-exchanger.js";
import { AuthenticateFederatedWeb } from "./authenticate-federated-web.js";

/**
 * Converts Apple's short-lived web authorization grant into the same verified
 * credential path used by native Coco clients. Identity mapping and GAMA
 * session creation remain owned by AuthenticateFederated.
 */
export class AuthenticateAppleWeb extends AuthenticateFederatedWeb {
  constructor(
    authorizationCodes: AppleAuthorizationCodeExchanger,
    authenticateFederated: AuthenticateFederated,
  ) {
    super("apple", authorizationCodes, authenticateFederated);
  }
}
