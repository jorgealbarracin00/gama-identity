import type { EmailCredential } from "../domain/email-credential.js";
import type { EmailCredentialId } from "../domain/email-credential-id.js";
import { EmailAlreadyInUseError } from "../domain/errors.js";
import type { NormalizedEmail } from "../domain/email.js";
import type { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";
import type { EmailCredentialRepository } from "../ports/email-credential-repository.js";

export class InMemoryEmailCredentialRepository
  implements EmailCredentialRepository
{
  private readonly credentials = new Map<string, EmailCredential>();

  async save(credential: EmailCredential): Promise<void> {
    const existing = await this.findByNormalizedEmail(credential.email);
    if (
      existing !== null &&
      !existing.id.equals(credential.id)
    ) {
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
    for (const credential of this.credentials.values()) {
      if (
        credential.status !== "retired" &&
        credential.email.equals(email)
      ) {
        return credential.copy();
      }
    }
    return null;
  }

  async findByHumanIdentityId(
    humanIdentityId: HumanIdentityId,
  ): Promise<EmailCredential | null> {
    for (const credential of this.credentials.values()) {
      if (
        credential.status !== "retired" &&
        credential.humanIdentityId.equals(humanIdentityId)
      ) {
        return credential.copy();
      }
    }
    return null;
  }

  async listByHumanIdentityId(
    humanIdentityId: HumanIdentityId,
  ): Promise<readonly EmailCredential[]> {
    return [...this.credentials.values()]
      .filter((credential) => credential.humanIdentityId.equals(humanIdentityId))
      .map((credential) => credential.copy());
  }

  async remove(id: EmailCredentialId): Promise<void> {
    this.credentials.delete(id.value);
  }
}
