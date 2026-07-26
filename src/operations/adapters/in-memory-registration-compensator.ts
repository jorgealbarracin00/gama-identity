import type { EmailCredentialId } from "../../authentication/credentials/domain/email-credential-id.js";
import type { InMemoryEmailCredentialRepository } from "../../authentication/credentials/adapters/in-memory-email-credential-repository.js";
import type { InMemoryHumanIdentityRepository } from "../../identity/adapters/in-memory-human-identity-repository.js";
import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { InMemorySessionRepository } from "../../sessions/adapters/in-memory-session-repository.js";
import type { SessionId } from "../../sessions/domain/session-id.js";
import type { RegistrationCompensator } from "../application/use-cases.js";

export class InMemoryRegistrationCompensator
  implements RegistrationCompensator
{
  constructor(
    private readonly identities: InMemoryHumanIdentityRepository,
    private readonly credentials: InMemoryEmailCredentialRepository,
    private readonly sessions: InMemorySessionRepository,
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
