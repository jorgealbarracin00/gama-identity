import { InvalidPasswordError } from "./errors.js";

export interface PasswordPolicy {
  validate(plaintextPassword: string): void;
}

export class BaselinePasswordPolicy implements PasswordPolicy {
  static readonly minimumLength = 12;
  static readonly maximumLength = 128;

  validate(plaintextPassword: string): void {
    if (plaintextPassword.trim().length === 0) {
      throw new InvalidPasswordError("empty");
    }

    if (plaintextPassword.length < BaselinePasswordPolicy.minimumLength) {
      throw new InvalidPasswordError("too_short");
    }

    if (plaintextPassword.length > BaselinePasswordPolicy.maximumLength) {
      throw new InvalidPasswordError("too_long");
    }
  }
}
