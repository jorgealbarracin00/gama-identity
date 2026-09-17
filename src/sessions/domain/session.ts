import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { Clock } from "../../shared/clock.js";
import { SessionUnavailableError } from "./errors.js";
import type { SessionIdGenerator } from "./session-id.js";
import { SessionId } from "./session-id.js";

export type SessionStatus = "active" | "expired" | "revoked";

export interface SessionSnapshot {
  readonly id: SessionId;
  readonly humanIdentityId: HumanIdentityId;
  readonly createdAt: Date;
  readonly lastAccessedAt: Date;
  readonly expiresAt: Date;
  readonly status: SessionStatus;
  readonly renewalTokenHash: string | null;
  readonly renewalExpiresAt: Date | null;
}

export class Session {
  private constructor(
    private readonly sessionId: SessionId,
    private readonly ownerId: HumanIdentityId,
    private readonly creationTime: Date,
    private lastAccessTime: Date,
    private readonly expirationTime: Date,
    private lifecycleStatus: SessionStatus,
    private readonly renewalHash: string | null,
    private readonly renewalExpirationTime: Date | null,
  ) {}

  static create(
    idGenerator: SessionIdGenerator,
    humanIdentityId: HumanIdentityId,
    durationSeconds: number,
    renewalTokenHash: string,
    renewalDurationSeconds: number,
    clock: Clock,
  ): Session {
    if (!Number.isInteger(durationSeconds) || durationSeconds <= 0 ||
        !Number.isInteger(renewalDurationSeconds) || renewalDurationSeconds <= durationSeconds) {
      throw new Error("Session and renewal durations must be positive and renewal must be longer");
    }
    const now = clock.now();
    return new Session(
      idGenerator.next(),
      humanIdentityId,
      new Date(now),
      new Date(now),
      new Date(now.getTime() + durationSeconds * 1000),
      "active",
      renewalTokenHash,
      new Date(now.getTime() + renewalDurationSeconds * 1000),
    );
  }

  static reconstitute(snapshot: SessionSnapshot): Session {
    return new Session(
      snapshot.id,
      snapshot.humanIdentityId,
      new Date(snapshot.createdAt),
      new Date(snapshot.lastAccessedAt),
      new Date(snapshot.expiresAt),
      snapshot.status,
      snapshot.renewalTokenHash,
      snapshot.renewalExpiresAt === null ? null : new Date(snapshot.renewalExpiresAt),
    );
  }

  get id(): SessionId { return this.sessionId; }
  get humanIdentityId(): HumanIdentityId { return this.ownerId; }
  get status(): SessionStatus { return this.lifecycleStatus; }
  get createdAt(): Date { return new Date(this.creationTime); }
  get lastAccessedAt(): Date { return new Date(this.lastAccessTime); }
  get expiresAt(): Date { return new Date(this.expirationTime); }
  get renewalTokenHash(): string | null { return this.renewalHash; }
  get renewalExpiresAt(): Date | null {
    return this.renewalExpirationTime === null ? null : new Date(this.renewalExpirationTime);
  }

  canRenew(clock: Clock): "available" | "expired" | "revoked" | "unavailable" {
    if (this.lifecycleStatus === "revoked") return "revoked";
    if (this.renewalHash === null || this.renewalExpirationTime === null) return "unavailable";
    return clock.now().getTime() < this.renewalExpirationTime.getTime() ? "available" : "expired";
  }

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
      this.renewalHash,
      this.renewalExpiresAt,
    );
  }

  snapshot(): SessionSnapshot {
    return {
      id: this.sessionId,
      humanIdentityId: this.ownerId,
      createdAt: this.createdAt,
      lastAccessedAt: this.lastAccessedAt,
      expiresAt: this.expiresAt,
      status: this.lifecycleStatus,
      renewalTokenHash: this.renewalHash,
      renewalExpiresAt: this.renewalExpiresAt,
    };
  }
}
