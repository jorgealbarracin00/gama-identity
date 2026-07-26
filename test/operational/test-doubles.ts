import type { PasswordHasher, PasswordVerifier } from "../../src/authentication/credentials/ports/password-operations.js";
import { PasswordHash } from "../../src/authentication/credentials/domain/password.js";
import type { Clock } from "../../src/shared/clock.js";
import { HumanIdentityId, type HumanIdentityIdGenerator } from "../../src/identity/domain/human-identity-id.js";
import { EmailCredentialId, type EmailCredentialIdGenerator } from "../../src/authentication/credentials/domain/email-credential-id.js";
import { SessionId, type SessionIdGenerator } from "../../src/sessions/domain/session-id.js";
import { InMemoryHumanIdentityRepository } from "../../src/identity/adapters/in-memory-human-identity-repository.js";
import { InMemoryEmailCredentialRepository } from "../../src/authentication/credentials/adapters/in-memory-email-credential-repository.js";
import { InMemorySessionRepository } from "../../src/sessions/adapters/in-memory-session-repository.js";
import { CreateHumanIdentity } from "../../src/identity/application/use-cases.js";
import { CreateEmailCredential } from "../../src/authentication/credentials/application/use-cases.js";
import { BaselinePasswordPolicy } from "../../src/authentication/credentials/domain/password-policy.js";
import { Authenticate } from "../../src/authentication/application/authenticate.js";
import { CreateSession, Logout, ValidateSession } from "../../src/sessions/application/use-cases.js";
import { InMemoryRegistrationCompensator } from "../../src/operations/adapters/in-memory-registration-compensator.js";
import { Login, Register } from "../../src/operations/application/use-cases.js";
import type { IdentityServices } from "../../src/api/services.js";

export class MutableClock implements Clock {
  constructor(private value: Date) {}
  now(): Date { return new Date(this.value); }
  set(value: Date): void { this.value = value; }
}

export class IdentityIds implements HumanIdentityIdGenerator {
  private sequence = 0;
  next(): HumanIdentityId {
    this.sequence += 1;
    return HumanIdentityId.from(`identity-${this.sequence}`);
  }
}

export class CredentialIds implements EmailCredentialIdGenerator {
  private sequence = 0;
  next(): EmailCredentialId {
    this.sequence += 1;
    return EmailCredentialId.from(`credential-${this.sequence}`);
  }
}

export class SessionIds implements SessionIdGenerator {
  private sequence = 0;
  next(): SessionId {
    this.sequence += 1;
    return SessionId.from(`session-${this.sequence}`);
  }
}

export class DeterministicPasswords
  implements PasswordHasher, PasswordVerifier
{
  async hash(plaintextPassword: string): Promise<PasswordHash> {
    return PasswordHash.from(`test:${plaintextPassword}`);
  }

  async verify(
    plaintextPassword: string,
    passwordHash: PasswordHash,
  ): Promise<boolean> {
    return passwordHash.value === `test:${plaintextPassword}`;
  }
}

export function buildTestServices(): {
  services: IdentityServices;
  clock: MutableClock;
  identities: InMemoryHumanIdentityRepository;
  credentials: InMemoryEmailCredentialRepository;
  sessions: InMemorySessionRepository;
} {
  const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
  const identities = new InMemoryHumanIdentityRepository();
  const credentials = new InMemoryEmailCredentialRepository();
  const sessions = new InMemorySessionRepository();
  const passwords = new DeterministicPasswords();
  const createIdentity = new CreateHumanIdentity(
    identities,
    new IdentityIds(),
    clock,
  );
  const createCredential = new CreateEmailCredential(
    credentials,
    new CredentialIds(),
    clock,
    new BaselinePasswordPolicy(),
    passwords,
  );
  const authenticate = new Authenticate(
    credentials,
    identities,
    passwords,
  );
  const createSession = new CreateSession(
    sessions,
    new SessionIds(),
    clock,
    3600,
  );
  const services = {
    register: new Register(
      createIdentity,
      createCredential,
      authenticate,
      createSession,
      new InMemoryRegistrationCompensator(
        identities,
        credentials,
        sessions,
      ),
    ),
    login: new Login(authenticate, createSession),
    logout: new Logout(sessions),
    validateSession: new ValidateSession(sessions, clock),
  };
  return { services, clock, identities, credentials, sessions };
}
