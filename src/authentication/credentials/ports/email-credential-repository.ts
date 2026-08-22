import type { EmailCredential } from "../domain/email-credential.js";
import type { EmailCredentialId } from "../domain/email-credential-id.js";
import type { NormalizedEmail } from "../domain/email.js";
import type { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";

export interface EmailCredentialRepository {
  /**
   * Implementations must atomically enforce that a normalized email belongs
   * to at most one non-retired credential.
   */
  save(credential: EmailCredential): Promise<void>;
  findById(id: EmailCredentialId): Promise<EmailCredential | null>;
  /** Finds the non-retired credential currently claiming this email. */
  findByNormalizedEmail(
    email: NormalizedEmail,
  ): Promise<EmailCredential | null>;
  /** Finds the non-retired email credential associated with this Human Identity. */
  findByHumanIdentityId(
    humanIdentityId: HumanIdentityId,
  ): Promise<EmailCredential | null>;
}
