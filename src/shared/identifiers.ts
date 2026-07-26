import { randomUUID } from "node:crypto";

import type { EmailCredentialIdGenerator } from "../authentication/credentials/domain/email-credential-id.js";
import { EmailCredentialId } from "../authentication/credentials/domain/email-credential-id.js";
import type { HumanIdentityIdGenerator } from "../identity/domain/human-identity-id.js";
import { HumanIdentityId } from "../identity/domain/human-identity-id.js";
import type { SessionIdGenerator } from "../sessions/domain/session-id.js";
import { SessionId } from "../sessions/domain/session-id.js";

export class UuidHumanIdentityIdGenerator
  implements HumanIdentityIdGenerator
{
  next(): HumanIdentityId {
    return HumanIdentityId.from(randomUUID());
  }
}

export class UuidEmailCredentialIdGenerator
  implements EmailCredentialIdGenerator
{
  next(): EmailCredentialId {
    return EmailCredentialId.from(randomUUID());
  }
}

export class UuidSessionIdGenerator implements SessionIdGenerator {
  next(): SessionId {
    return SessionId.from(randomUUID());
  }
}
