export class SessionId {
  private constructor(readonly value: string) {}

  static from(value: string): SessionId {
    if (value.trim().length === 0) {
      throw new Error("Session ID must not be empty");
    }
    return new SessionId(value);
  }

  equals(other: SessionId): boolean {
    return this.value === other.value;
  }
}

export interface SessionIdGenerator {
  next(): SessionId;
}
