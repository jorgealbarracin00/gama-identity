export class EmailCredentialId {
  private constructor(readonly value: string) {}

  static from(value: string): EmailCredentialId {
    if (value.trim().length === 0) {
      throw new Error("Email Credential ID must not be empty");
    }

    return new EmailCredentialId(value);
  }

  equals(other: EmailCredentialId): boolean {
    return this.value === other.value;
  }
}

export interface EmailCredentialIdGenerator {
  next(): EmailCredentialId;
}
