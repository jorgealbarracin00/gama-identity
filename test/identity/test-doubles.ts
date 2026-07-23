import type { Clock } from "../../src/shared/clock.js";
import type { HumanIdentity } from "../../src/identity/domain/human-identity.js";
import {
  HumanIdentityId,
  type HumanIdentityIdGenerator,
} from "../../src/identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../src/identity/ports/human-identity-repository.js";

export class FixedClock implements Clock {
  constructor(private currentTime: Date) {}

  now(): Date {
    return new Date(this.currentTime.getTime());
  }

  set(time: Date): void {
    this.currentTime = time;
  }
}

export class FixedIdentityIdGenerator implements HumanIdentityIdGenerator {
  constructor(private readonly value: string) {}

  next(): HumanIdentityId {
    return HumanIdentityId.from(this.value);
  }
}

export class InMemoryHumanIdentityRepository
  implements HumanIdentityRepository
{
  private readonly identities = new Map<string, HumanIdentity>();
  saveCount = 0;

  async save(identity: HumanIdentity): Promise<void> {
    this.identities.set(identity.id.value, identity);
    this.saveCount += 1;
  }

  async findById(id: HumanIdentityId): Promise<HumanIdentity | null> {
    return this.identities.get(id.value) ?? null;
  }
}
