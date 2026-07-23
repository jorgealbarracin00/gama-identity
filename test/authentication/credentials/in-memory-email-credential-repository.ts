import type { EmailCredential } from "../../../src/authentication/credentials/domain/email-credential.js";
import type { EmailCredentialId } from "../../../src/authentication/credentials/domain/email-credential-id.js";
import { EmailAlreadyInUseError } from "../../../src/authentication/credentials/domain/errors.js";
import type { NormalizedEmail } from "../../../src/authentication/credentials/domain/email.js";
import type { EmailCredentialRepository } from "../../../src/authentication/credentials/ports/email-credential-repository.js";

export class InMemoryEmailCredentialRepository
  implements EmailCredentialRepository
{
  private readonly credentials = new Map<string, EmailCredential>();

  async save(credential: EmailCredential): Promise<void> {
    const conflict = [...this.credentials.values()].find(
      (stored) =>
        stored.id.value !== credential.id.value &&
        stored.status !== "retired" &&
        stored.email.equals(credential.email),
    );

    if (conflict !== undefined && credential.status !== "retired") {
      throw new EmailAlreadyInUseError();
    }

    this.credentials.set(credential.id.value, credential.copy());
  }

  async findById(id: EmailCredentialId): Promise<EmailCredential | null> {
    return this.credentials.get(id.value)?.copy() ?? null;
  }

  async findByNormalizedEmail(
    email: NormalizedEmail,
  ): Promise<EmailCredential | null> {
    const credential = [...this.credentials.values()].find(
      (stored) => stored.status !== "retired" && stored.email.equals(email),
    );

    return credential?.copy() ?? null;
  }
}
