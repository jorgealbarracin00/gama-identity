import type { EmailCredentialId } from "../domain/email-credential-id.js";

export class EmailCredentialNotFoundError extends Error {
  constructor(readonly credentialId: EmailCredentialId) {
    super(`Email Credential ${credentialId.value} was not found`);
    this.name = "EmailCredentialNotFoundError";
  }
}
