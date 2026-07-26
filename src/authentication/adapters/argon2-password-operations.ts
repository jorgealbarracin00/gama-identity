import {
  argon2id,
  hash as argon2Hash,
  verify as argon2Verify,
} from "argon2";

import { PasswordHash } from "../credentials/domain/password.js";
import type {
  PasswordHasher,
  PasswordVerifier,
} from "../credentials/ports/password-operations.js";

export interface Argon2PasswordOptions {
  readonly memoryCost: number;
  readonly timeCost: number;
  readonly parallelism: number;
}

export class Argon2PasswordOperations
  implements PasswordHasher, PasswordVerifier
{
  constructor(private readonly options: Argon2PasswordOptions) {}

  async hash(plaintextPassword: string): Promise<PasswordHash> {
    const digest = await argon2Hash(plaintextPassword, {
      type: argon2id,
      memoryCost: this.options.memoryCost,
      timeCost: this.options.timeCost,
      parallelism: this.options.parallelism,
    });
    return PasswordHash.from(digest);
  }

  async verify(
    plaintextPassword: string,
    passwordHash: PasswordHash,
  ): Promise<boolean> {
    try {
      return await argon2Verify(passwordHash.value, plaintextPassword);
    } catch {
      return false;
    }
  }
}
