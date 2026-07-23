export class HumanIdentityId {
  private constructor(readonly value: string) {}

  static from(value: string): HumanIdentityId {
    if (value.trim().length === 0) {
      throw new Error("Human Identity ID must not be empty");
    }

    return new HumanIdentityId(value);
  }

  equals(other: HumanIdentityId): boolean {
    return this.value === other.value;
  }
}

export interface HumanIdentityIdGenerator {
  next(): HumanIdentityId;
}
