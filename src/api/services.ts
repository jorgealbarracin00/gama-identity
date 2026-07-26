import { Argon2PasswordOperations } from "../authentication/adapters/argon2-password-operations.js";
import { Authenticate } from "../authentication/application/authenticate.js";
import { InMemoryEmailCredentialRepository } from "../authentication/credentials/adapters/in-memory-email-credential-repository.js";
import { CreateEmailCredential } from "../authentication/credentials/application/use-cases.js";
import { BaselinePasswordPolicy } from "../authentication/credentials/domain/password-policy.js";
import { config } from "../config/index.js";
import { InMemoryHumanIdentityRepository } from "../identity/adapters/in-memory-human-identity-repository.js";
import { CreateHumanIdentity } from "../identity/application/use-cases.js";
import { InMemoryRegistrationCompensator } from "../operations/adapters/in-memory-registration-compensator.js";
import { Login, Register } from "../operations/application/use-cases.js";
import { InMemorySessionRepository } from "../sessions/adapters/in-memory-session-repository.js";
import {
  CreateSession,
  Logout,
  ValidateSession,
} from "../sessions/application/use-cases.js";
import { SystemClock } from "../shared/clock.js";
import {
  UuidEmailCredentialIdGenerator,
  UuidHumanIdentityIdGenerator,
  UuidSessionIdGenerator,
} from "../shared/identifiers.js";

export interface IdentityServices {
  readonly register: Register;
  readonly login: Login;
  readonly logout: Logout;
  readonly validateSession: ValidateSession;
}

export function buildIdentityServices(): IdentityServices {
  const clock = new SystemClock();
  const identities = new InMemoryHumanIdentityRepository();
  const credentials = new InMemoryEmailCredentialRepository();
  const sessions = new InMemorySessionRepository();
  const passwordOperations = new Argon2PasswordOperations({
    memoryCost: config.PASSWORD_HASH_MEMORY_KIB,
    timeCost: config.PASSWORD_HASH_ITERATIONS,
    parallelism: config.PASSWORD_HASH_PARALLELISM,
  });

  const createIdentity = new CreateHumanIdentity(
    identities,
    new UuidHumanIdentityIdGenerator(),
    clock,
  );
  const createCredential = new CreateEmailCredential(
    credentials,
    new UuidEmailCredentialIdGenerator(),
    clock,
    new BaselinePasswordPolicy(),
    passwordOperations,
  );
  const authenticate = new Authenticate(
    credentials,
    identities,
    passwordOperations,
  );
  const createSession = new CreateSession(
    sessions,
    new UuidSessionIdGenerator(),
    clock,
    config.SESSION_DURATION_SECONDS,
  );

  return {
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
}
