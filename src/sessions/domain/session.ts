import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { Clock } from "../../shared/clock.js";
import { SessionUnavailableError } from "./errors.js";
import type { SessionIdGenerator } from "./session-id.js";
import { SessionId } from "./session-id.js";

export type SessionStatus = "active" | "expired" | "revoked";

export class Session {
  private constructor(
    private readonly sessionId: SessionId,
    private readonly ownerId: HumanIdentityId,
    private readonly creationTime: Date,
    private lastAccessTime: Date,
    private readonly expirationTime: Date,
    private lifecycleStatus: SessionStatus,
  ) {}

  static create(
    idGenerator: SessionIdGenerator,
    humanIdentityId: HumanIdentityId,
    durationSeconds: number,
    clock: Clock,
  ): Session {
    if (!Number.isInteger(durationSeconds) || durationSeconds <= 0) {
      throw new Error("Session duration must be a positive integer");
    }
    const now = clock.now();
    return new Session(
      idGenerator.next(),
      humanIdentityId,
      new Date(now),
      new Date(now),
      new Date(now.getTime() + durationSeconds * 1000),
      "active",
    );
  }

  get id(): SessionId { return this.sessionId; }
  get humanIdentityId(): HumanIdentityId { return this.ownerId; }
  get status(): SessionStatus { return this.lifecycleStatus; }
  get createdAt(): Date { return new Date(this.creationTime); }
  get lastAccessedAt(): Date { return new Date(this.lastAccessTime); }
  get expiresAt(): Date { return new Date(this.expirationTime); }

  validate(clock: Clock): boolean {
    if (this.lifecycleStatus !== "active") return false;
    if (clock.now().getTime() >= this.expirationTime.getTime()) {
      this.lifecycleStatus = "expired";
      return false;
    }
    return true;
  }

  touch(clock: Clock): void {
    if (!this.validate(clock)) {
      throw new SessionUnavailableError(this.lifecycleStatus);
    }
    this.lastAccessTime = new Date(clock.now());
  }

  expire(clock: Clock): void {
    if (
      this.lifecycleStatus === "active" &&
      clock.now().getTime() >= this.expirationTime.getTime()
    ) {
      this.lifecycleStatus = "expired";
    }
  }

  revoke(): void {
    if (this.lifecycleStatus === "revoked") return;
    this.lifecycleStatus = "revoked";
  }

  copy(): Session {
    return new Session(
      this.sessionId,
      this.ownerId,
      this.createdAt,
      this.lastAccessedAt,
      this.expiresAt,
      this.lifecycleStatus,
    );
  }
}
