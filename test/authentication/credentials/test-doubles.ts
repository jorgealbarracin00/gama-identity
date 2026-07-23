import {
  EmailCredentialId,
  type EmailCredentialIdGenerator,
} from "../../../src/authentication/credentials/domain/email-credential-id.js";
import { PasswordHash } from "../../../src/authentication/credentials/domain/password.js";
import type {
  PasswordHasher,
  PasswordVerifier,
} from "../../../src/authentication/credentials/ports/password-operations.js";
import type { Clock } from "../../../src/shared/clock.js";

export class FixedClock implements Clock {
  constructor(private currentTime: Date) {}

  now(): Date {
    return new Date(this.currentTime.getTime());
  }

  set(time: Date): void {
    this.currentTime = time;
  }
}

export class FixedEmailCredentialIdGenerator
  implements EmailCredentialIdGenerator
{
  constructor(private readonly value: string) {}

  next(): EmailCredentialId {
    return EmailCredentialId.from(this.value);
  }
}

export class DeterministicPasswordOperations
  implements PasswordHasher, PasswordVerifier
{
  hashCalls = 0;

  async hash(plaintextPassword: string): Promise<PasswordHash> {
    this.hashCalls += 1;
    return PasswordHash.from(`test-hash:${plaintextPassword}`);
  }

  async verify(
    plaintextPassword: string,
    passwordHash: PasswordHash,
  ): Promise<boolean> {
    return passwordHash.value === `test-hash:${plaintextPassword}`;
  }
}
