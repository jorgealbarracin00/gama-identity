import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { Clock } from "../../shared/clock.js";
import { Session } from "../domain/session.js";
import type { SessionId, SessionIdGenerator } from "../domain/session-id.js";
import {
  SecureSessionRenewalTokenGenerator,
  type SessionRenewalTokenGenerator,
} from "../domain/session-renewal-token.js";
import type { SessionRepository } from "../ports/session-repository.js";

export interface SessionMetadata {
  readonly sessionId: string;
  readonly humanIdentityId: string;
  readonly createdAt: string;
  readonly authenticatedAt: string;
  readonly lastAccessedAt: string;
  readonly expiresAt: string;
}

export interface CreatedSession extends SessionMetadata {
  readonly renewalToken: string;
  readonly renewalExpiresAt: string;
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
    authenticatedAt: session.authenticatedAt.toISOString(),
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
    private readonly renewalTokens: SessionRenewalTokenGenerator = new SecureSessionRenewalTokenGenerator(),
    private readonly renewalDurationSeconds = 2_592_000,
  ) {}

  async execute(humanIdentityId: HumanIdentityId, authenticatedAt?: Date): Promise<CreatedSession> {
    const renewalToken = this.renewalTokens.next();
    const session = Session.create(
      this.idGenerator,
      humanIdentityId,
      this.durationSeconds,
      renewalToken.hash,
      this.renewalDurationSeconds,
      this.clock,
      authenticatedAt,
    );
    await this.repository.save(session);
    return {
      ...metadata(session),
      renewalToken: renewalToken.value,
      renewalExpiresAt: session.renewalExpiresAt!.toISOString(),
    };
  }
}

export type SessionRenewalFailure = "invalid" | "expired" | "revoked";

export class SessionRenewalError extends Error {
  constructor(readonly reason: SessionRenewalFailure) {
    super("Session cannot be renewed");
  }
}

export class RenewSession {
  constructor(
    private readonly repository: SessionRepository,
    private readonly createSession: CreateSession,
    private readonly renewalTokens: SessionRenewalTokenGenerator,
    private readonly clock: Clock,
    private readonly atomically: <T>(work: () => Promise<T>) => Promise<T>,
  ) {}

  async execute(renewalToken: string): Promise<CreatedSession> {
    let hash: string;
    try {
      hash = this.renewalTokens.hash(renewalToken);
    } catch {
      throw new SessionRenewalError("invalid");
    }
    return this.atomically(async () => {
      const previous = await this.repository.findByRenewalTokenHashForUpdate(hash);
      if (previous === null) throw new SessionRenewalError("invalid");
      const availability = previous.canRenew(this.clock);
      if (availability !== "available") {
        if (availability === "expired") {
          previous.revoke();
          await this.repository.save(previous);
        }
        throw new SessionRenewalError(
          availability === "revoked" ? "revoked" : availability === "expired" ? "expired" : "invalid",
        );
      }
      previous.revoke();
      await this.repository.save(previous);
      return this.createSession.execute(previous.humanIdentityId, previous.authenticatedAt);
    });
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
