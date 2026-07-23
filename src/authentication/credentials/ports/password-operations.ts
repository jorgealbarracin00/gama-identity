import type { PasswordHash } from "../domain/password.js";

export interface PasswordHasher {
  hash(plaintextPassword: string): Promise<PasswordHash>;
}

export interface PasswordVerifier {
  verify(
    plaintextPassword: string,
    passwordHash: PasswordHash,
  ): Promise<boolean>;
}
