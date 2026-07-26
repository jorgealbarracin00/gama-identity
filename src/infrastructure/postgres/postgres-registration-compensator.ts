import type { EmailCredentialId } from "../../authentication/credentials/domain/email-credential-id.js";
import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { RegistrationCompensator } from "../../operations/application/use-cases.js";
import type { SessionId } from "../../sessions/domain/session-id.js";
import type { PostgresEmailCredentialRepository } from "./postgres-email-credential-repository.js";
import type { PostgresHumanIdentityRepository } from "./postgres-human-identity-repository.js";
import type { PostgresSessionRepository } from "./postgres-session-repository.js";

export class PostgresRegistrationCompensator
  implements RegistrationCompensator
{
  constructor(
    private readonly identities: PostgresHumanIdentityRepository,
    private readonly credentials: PostgresEmailCredentialRepository,
    private readonly sessions: PostgresSessionRepository,
  ) {}

  removeIdentity(id: HumanIdentityId): Promise<void> {
    return this.identities.remove(id);
  }

  removeCredential(id: EmailCredentialId): Promise<void> {
    return this.credentials.remove(id);
  }

  removeSession(id: SessionId): Promise<void> {
    return this.sessions.remove(id);
  }
}
