import type { EmailCredentialRepository } from "../credentials/ports/email-credential-repository.js";
import type { PasswordVerifier } from "../credentials/ports/password-operations.js";
import { NormalizedEmail } from "../credentials/domain/email.js";
import { InvalidEmailError } from "../credentials/domain/errors.js";
import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";

export type AuthenticationResult =
  | { readonly outcome: "success"; readonly humanIdentityId: HumanIdentityId }
  | { readonly outcome: "invalid_credentials" }
  | { readonly outcome: "credential_unavailable" }
  | { readonly outcome: "identity_unavailable" };

export interface AuthenticateInput {
  readonly email: string;
  readonly plaintextPassword: string;
}

export class Authenticate {
  constructor(
    private readonly credentials: EmailCredentialRepository,
    private readonly identities: HumanIdentityRepository,
    private readonly passwordVerifier: PasswordVerifier,
  ) {}

  async execute(input: AuthenticateInput): Promise<AuthenticationResult> {
    let email: NormalizedEmail;
    try {
      email = NormalizedEmail.from(input.email);
    } catch (error) {
      if (error instanceof InvalidEmailError) {
        return { outcome: "invalid_credentials" };
      }
      throw error;
    }
    const credential = await this.credentials.findByNormalizedEmail(email);

    if (credential === null) {
      return { outcome: "invalid_credentials" };
    }

    if (!credential.isEligibleForAuthentication()) {
      return { outcome: "credential_unavailable" };
    }

    const passwordMatches = await credential.verifyPassword(
      input.plaintextPassword,
      this.passwordVerifier,
    );
    if (!passwordMatches) {
      return { outcome: "invalid_credentials" };
    }

    const identity = await this.identities.findById(
      credential.humanIdentityId,
    );
    if (identity === null || identity.status !== "active") {
      return { outcome: "identity_unavailable" };
    }

    return {
      outcome: "success",
      humanIdentityId: identity.id,
    };
  }
}
