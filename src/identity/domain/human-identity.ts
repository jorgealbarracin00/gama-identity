import type { Clock } from "../../shared/clock.js";
import { InvalidHumanIdentityTransitionError } from "./errors.js";
import {
  type HumanIdentityIdGenerator,
  HumanIdentityId,
} from "./human-identity-id.js";

export type HumanIdentityStatus = "active" | "suspended" | "retired";

export interface HumanIdentitySnapshot {
  id: HumanIdentityId;
  status: HumanIdentityStatus;
  createdAt: Date;
  updatedAt: Date;
}

export class HumanIdentity {
  private constructor(
    private readonly identityId: HumanIdentityId,
    private lifecycleStatus: HumanIdentityStatus,
    private readonly creationTime: Date,
    private lastUpdatedTime: Date,
  ) {}

  static create(
    idGenerator: HumanIdentityIdGenerator,
    clock: Clock,
  ): HumanIdentity {
    const now = clock.now();

    return new HumanIdentity(
      idGenerator.next(),
      "active",
      new Date(now.getTime()),
      new Date(now.getTime()),
    );
  }

  get id(): HumanIdentityId {
    return this.identityId;
  }

  get status(): HumanIdentityStatus {
    return this.lifecycleStatus;
  }

  get createdAt(): Date {
    return new Date(this.creationTime.getTime());
  }

  get updatedAt(): Date {
    return new Date(this.lastUpdatedTime.getTime());
  }

  suspend(clock: Clock): void {
    if (this.lifecycleStatus === "suspended") {
      return;
    }

    if (this.lifecycleStatus === "retired") {
      throw new InvalidHumanIdentityTransitionError("retired", "suspended");
    }

    this.transitionTo("suspended", clock);
  }

  reactivate(clock: Clock): void {
    if (this.lifecycleStatus === "active") {
      return;
    }

    if (this.lifecycleStatus === "retired") {
      throw new InvalidHumanIdentityTransitionError("retired", "active");
    }

    this.transitionTo("active", clock);
  }

  retire(clock: Clock): void {
    if (this.lifecycleStatus === "retired") {
      return;
    }

    this.transitionTo("retired", clock);
  }

  snapshot(): HumanIdentitySnapshot {
    return {
      id: this.identityId,
      status: this.lifecycleStatus,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }

  private transitionTo(status: HumanIdentityStatus, clock: Clock): void {
    const now = clock.now();
    this.lifecycleStatus = status;
    this.lastUpdatedTime = new Date(now.getTime());
  }
}
