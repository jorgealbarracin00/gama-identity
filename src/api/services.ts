import { Argon2PasswordOperations } from "../authentication/adapters/argon2-password-operations.js";
import { Authenticate } from "../authentication/application/authenticate.js";
import { InMemoryEmailCredentialRepository } from "../authentication/credentials/adapters/in-memory-email-credential-repository.js";
import { CreateEmailCredential } from "../authentication/credentials/application/use-cases.js";
import { BaselinePasswordPolicy } from "../authentication/credentials/domain/password-policy.js";
import { config } from "../config/index.js";
import type { Config } from "../config/env.js";
import type { EmailCredentialRepository } from "../authentication/credentials/ports/email-credential-repository.js";
import type { HumanIdentityRepository } from "../identity/ports/human-identity-repository.js";
import type { RegistrationCompensator, CredentialsInput, RegistrationResult } from "../operations/application/use-cases.js";
import type { SessionRepository } from "../sessions/ports/session-repository.js";
import { PostgresDatabase } from "../infrastructure/postgres/database.js";
import { runMigrations } from "../infrastructure/postgres/migrations.js";
import { PostgresHumanIdentityRepository } from "../infrastructure/postgres/postgres-human-identity-repository.js";
import { PostgresEmailCredentialRepository } from "../infrastructure/postgres/postgres-email-credential-repository.js";
import { PostgresSessionRepository } from "../infrastructure/postgres/postgres-session-repository.js";
import { PostgresRegistrationCompensator } from "../infrastructure/postgres/postgres-registration-compensator.js";
import { TransactionalRegister } from "../infrastructure/postgres/transactional-register.js";
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
import { logger } from "../shared/logger.js";

export interface IdentityServices {
  readonly register: {
    execute(input: CredentialsInput): Promise<RegistrationResult>;
  };
  readonly login: Login;
  readonly logout: Logout;
  readonly validateSession: ValidateSession;
}

export interface DatabaseHealth {
  check(): Promise<"connected" | "not_configured">;
}

export interface ApplicationRuntime {
  readonly services: IdentityServices;
  readonly databaseHealth: DatabaseHealth;
  close(): Promise<void>;
}

export function buildIdentityServices(): IdentityServices {
  return buildMemoryRuntime().services;
}

export async function buildRuntime(
  runtimeConfig: Config = config,
): Promise<ApplicationRuntime> {
  if (runtimeConfig.REPOSITORY_MODE === "memory") {
    return buildMemoryRuntime(runtimeConfig);
  }

  const database = new PostgresDatabase(
    runtimeConfig.DATABASE_URL!,
    runtimeConfig.DATABASE_SSL === "require",
    (error) => {
      const code = (error as Error & { code?: string }).code;
      logger.error({ code }, "Unexpected idle PostgreSQL client error");
    },
  );
  try {
    await database.checkConnection();
    await runMigrations(database);
  } catch (error) {
    await database.close();
    throw error;
  }

  const identities = new PostgresHumanIdentityRepository(database);
  const credentials = new PostgresEmailCredentialRepository(database);
  const sessions = new PostgresSessionRepository(database);
  const services = composeServices(
    runtimeConfig,
    identities,
    credentials,
    sessions,
    new PostgresRegistrationCompensator(
      identities,
      credentials,
      sessions,
    ),
  );

  return {
    services: {
      ...services,
      register: new TransactionalRegister(services.register, database),
    },
    databaseHealth: {
      async check() {
        await database.checkConnection();
        return "connected";
      },
    },
    close: () => database.close(),
  };
}

function buildMemoryRuntime(runtimeConfig: Config = config): ApplicationRuntime {
  const clock = new SystemClock();
  const identities = new InMemoryHumanIdentityRepository();
  const credentials = new InMemoryEmailCredentialRepository();
  const sessions = new InMemorySessionRepository();
  const services = composeServices(
    runtimeConfig,
    identities,
    credentials,
    sessions,
    new InMemoryRegistrationCompensator(
      identities,
      credentials,
      sessions,
    ),
    clock,
  );

  return {
    services,
    databaseHealth: {
      async check() {
        return "not_configured";
      },
    },
    async close() {},
  };
}

function composeServices(
  runtimeConfig: Config,
  identities: HumanIdentityRepository,
  credentials: EmailCredentialRepository,
  sessions: SessionRepository,
  compensator: RegistrationCompensator,
  clock = new SystemClock(),
): {
  register: Register;
  login: Login;
  logout: Logout;
  validateSession: ValidateSession;
} {
  const passwordOperations = new Argon2PasswordOperations({
    memoryCost: runtimeConfig.PASSWORD_HASH_MEMORY_KIB,
    timeCost: runtimeConfig.PASSWORD_HASH_ITERATIONS,
    parallelism: runtimeConfig.PASSWORD_HASH_PARALLELISM,
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
    runtimeConfig.SESSION_DURATION_SECONDS,
  );

  return {
    register: new Register(
      createIdentity,
      createCredential,
      authenticate,
      createSession,
      compensator,
    ),
    login: new Login(authenticate, createSession),
    logout: new Logout(sessions),
    validateSession: new ValidateSession(sessions, clock),
  };
}
