export class FederatedIdentityId {
  private constructor(readonly value: string) {}

  static from(value: string): FederatedIdentityId {
    if (value.trim().length === 0) {
      throw new Error("Federated Identity ID must not be empty");
    }
    return new FederatedIdentityId(value);
  }

  equals(other: FederatedIdentityId): boolean {
    return this.value === other.value;
  }
}

export interface FederatedIdentityIdGenerator {
  next(): FederatedIdentityId;
}
