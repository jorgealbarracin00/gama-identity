export class PasswordHash {
  private constructor(readonly value: string) {}

  static from(value: string): PasswordHash {
    if (value.length === 0) {
      throw new Error("Password hash must not be empty");
    }

    return new PasswordHash(value);
  }
}
