import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { Clock } from "../../shared/clock.js";
import { Session } from "../domain/session.js";
import type { SessionId, SessionIdGenerator } from "../domain/session-id.js";
import type { SessionRepository } from "../ports/session-repository.js";

export interface SessionMetadata {
  readonly sessionId: string;
  readonly humanIdentityId: string;
  readonly createdAt: string;
  readonly lastAccessedAt: string;
  readonly expiresAt: string;
}

export type SessionValidationResult =
  | ({ readonly outcome: "authenticated" } & SessionMetadata)
  | { readonly outcome: "expired" }
  | { readonly outcome: "revoked" }
  | { readonly outcome: "invalid" };

function metadata(session: Session): SessionMetadata {
  return {
    sessionId: session.id.value,
    humanIdentityId: session.humanIdentityId.value,
    createdAt: session.createdAt.toISOString(),
    lastAccessedAt: session.lastAccessedAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
  };
}

export class CreateSession {
  constructor(
    private readonly repository: SessionRepository,
    private readonly idGenerator: SessionIdGenerator,
    private readonly clock: Clock,
    private readonly durationSeconds: number,
  ) {}

  async execute(humanIdentityId: HumanIdentityId): Promise<SessionMetadata> {
    const session = Session.create(
      this.idGenerator,
      humanIdentityId,
      this.durationSeconds,
      this.clock,
    );
    await this.repository.save(session);
    return metadata(session);
  }
}

export class ValidateSession {
  constructor(
    private readonly repository: SessionRepository,
    private readonly clock: Clock,
  ) {}

  async execute(id: SessionId): Promise<SessionValidationResult> {
    const session = await this.repository.findById(id);
    if (session === null) return { outcome: "invalid" };
    if (session.status === "revoked") return { outcome: "revoked" };
    if (!session.validate(this.clock)) {
      await this.repository.save(session);
      return { outcome: "expired" };
    }
    session.touch(this.clock);
    await this.repository.save(session);
    return { outcome: "authenticated", ...metadata(session) };
  }
}

export class Logout {
  constructor(private readonly repository: SessionRepository) {}

  async execute(id: SessionId): Promise<void> {
    await this.repository.revoke(id);
  }
}
