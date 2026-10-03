import { Argon2PasswordOperations } from "../authentication/adapters/argon2-password-operations.js";
import { AppleIdentityTokenVerifier, APPLE_FEDERATED_PROVIDER } from "../authentication/federated/adapters/apple-identity-token-verifier.js";
import { AppleWebAuthorizationCodeExchanger } from "../authentication/federated/adapters/apple-authorization-code-exchanger.js";
import {
  InMemoryFederatedAuthenticationNonceRepository,
  InMemoryFederatedIdentityRepository,
} from "../authentication/federated/adapters/in-memory-federated-identity-repository.js";
import { AuthenticateFederated } from "../authentication/federated/application/authenticate-federated.js";
import { AuthenticateAppleWeb } from "../authentication/federated/application/authenticate-apple-web.js";
import { ManageFederatedAuthenticationMethods } from "../authentication/federated/application/manage-federated-authentication-methods.js";
import {
  FederatedIdentityTokenVerifiers,
  UnavailableFederatedIdentityTokenVerifier,
} from "../authentication/federated/application/token-verifier.js";
import type {
  FederatedAuthenticationNonceRepository,
  FederatedIdentityRepository,
} from "../authentication/federated/ports/federated-identity-repository.js";
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
import {
  PostgresFederatedAuthenticationNonceRepository,
  PostgresFederatedIdentityRepository,
} from "../infrastructure/postgres/postgres-federated-identity-repository.js";
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
import { SystemClock, type Clock } from "../shared/clock.js";
import {
  UuidEmailCredentialIdGenerator,
  UuidFederatedIdentityIdGenerator,
  UuidHumanIdentityIdGenerator,
  UuidSessionIdGenerator,
} from "../shared/identifiers.js";
import { logger } from "../shared/logger.js";
import { ControlPlane } from "../control-plane/application/control-plane.js";
import { InMemoryControlPlaneRepository } from "../control-plane/adapters/in-memory-control-plane-repository.js";
import { PostgresControlPlaneRepository } from "../infrastructure/postgres/postgres-control-plane-repository.js";
import { WorkforceAdministration } from "../control-plane/application/workforce-administration.js";
import { AdministrationPrincipals } from "../control-plane/application/administration-principals.js";
import {
  PlatformAdministration,
  PlatformAdministrationProvisioning,
} from "../control-plane/application/platform-administration.js";
import { TenantTeamAdministration } from "../control-plane/application/tenant-team-administration.js";
import type { ControlPlaneRepository } from "../control-plane/ports/control-plane-repository.js";
import { SerialExecutor } from "../shared/serial-executor.js";

export interface AdministrationServices {
  readonly platform: PlatformAdministration;
  readonly tenantTeam: TenantTeamAdministration;
}

export interface IdentityServices {
  readonly register: {
    execute(input: CredentialsInput): Promise<RegistrationResult>;
  };
  readonly login: Login;
  readonly authenticateFederated: AuthenticateFederated;
  readonly authenticateAppleWeb?: AuthenticateAppleWeb;
  readonly federatedAuthenticationMethods: ManageFederatedAuthenticationMethods;
  readonly logout: Logout;
  readonly validateSession: ValidateSession;
  readonly controlPlane: ControlPlane;
  readonly administration: AdministrationServices;
}

export interface DatabaseHealth {
  check(): Promise<"connected" | "not_configured">;
}

export interface ApplicationRuntime {
  readonly services: IdentityServices;
  readonly databaseHealth: DatabaseHealth;
  readonly controlPlane: ControlPlane;
  readonly workforceAdministration: WorkforceAdministration;
  readonly platformAdministrationProvisioning: PlatformAdministrationProvisioning;
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
  const federatedIdentities = new PostgresFederatedIdentityRepository(database);
  const federatedNonces = new PostgresFederatedAuthenticationNonceRepository(database);
  const controlPlaneRepository = new PostgresControlPlaneRepository(database);
  const services = composeServices(
    runtimeConfig,
    identities,
    credentials,
    sessions,
    federatedIdentities,
    federatedNonces,
    controlPlaneRepository,
    new PostgresRegistrationCompensator(
      identities,
      credentials,
      sessions,
    ),
    new SystemClock(),
    (work) => database.withTransaction(work),
  );
  const clock = new SystemClock();
  const controlPlane = new ControlPlane(
    controlPlaneRepository,
    identities,
    createPasswordOperations(runtimeConfig),
    clock,
    (work) => database.withTransaction(work),
  );
  const workforceAdministration = new WorkforceAdministration(
    controlPlaneRepository,
    identities,
    credentials,
    federatedIdentities,
    clock,
    (work) => database.withTransaction(work),
  );
  const administration = composeAdministration(
    controlPlaneRepository,
    identities,
    credentials,
    controlPlane,
    workforceAdministration,
    clock,
    (work) => database.withTransaction(work),
  );
  const platformAdministrationProvisioning = new PlatformAdministrationProvisioning(
    controlPlaneRepository,
    identities,
    clock,
    (work) => database.withTransaction(work),
  );

  return {
    services: {
      ...services,
      register: new TransactionalRegister(services.register, database),
      controlPlane,
      administration,
    },
    databaseHealth: {
      async check() {
        await database.checkConnection();
        return "connected";
      },
    },
    controlPlane,
    workforceAdministration,
    platformAdministrationProvisioning,
    close: () => database.close(),
  };
}

function buildMemoryRuntime(runtimeConfig: Config = config): ApplicationRuntime {
  const clock = new SystemClock();
  const identities = new InMemoryHumanIdentityRepository();
  const credentials = new InMemoryEmailCredentialRepository();
  const sessions = new InMemorySessionRepository();
  const federatedIdentities = new InMemoryFederatedIdentityRepository();
  const federatedNonces = new InMemoryFederatedAuthenticationNonceRepository();
  const controlPlaneRepository = new InMemoryControlPlaneRepository();
  const serial = new SerialExecutor();
  const services = composeServices(
    runtimeConfig,
    identities,
    credentials,
    sessions,
    federatedIdentities,
    federatedNonces,
    controlPlaneRepository,
    new InMemoryRegistrationCompensator(
      identities,
      credentials,
      sessions,
    ),
    clock,
    (work) => serial.execute(work),
  );
  const controlPlane = new ControlPlane(
    controlPlaneRepository,
    identities,
    createPasswordOperations(runtimeConfig),
    clock,
  );
  const workforceAdministration = new WorkforceAdministration(
    controlPlaneRepository,
    identities,
    credentials,
    federatedIdentities,
    clock,
  );
  const administration = composeAdministration(
    controlPlaneRepository,
    identities,
    credentials,
    controlPlane,
    workforceAdministration,
    clock,
  );
  const platformAdministrationProvisioning = new PlatformAdministrationProvisioning(
    controlPlaneRepository,
    identities,
    clock,
  );

  return {
    services: { ...services, controlPlane, administration },
    databaseHealth: {
      async check() {
        return "not_configured";
      },
    },
    controlPlane,
    workforceAdministration,
    platformAdministrationProvisioning,
    async close() {},
  };
}

function composeAdministration(
  repository: ControlPlaneRepository,
  identities: HumanIdentityRepository,
  credentials: EmailCredentialRepository,
  controlPlane: ControlPlane,
  workforceAdministration: WorkforceAdministration,
  clock: Clock,
  atomically: <T>(work: () => Promise<T>) => Promise<T> = async (work) => work(),
): AdministrationServices {
  const principals = new AdministrationPrincipals(repository, identities, controlPlane);
  return {
    platform: new PlatformAdministration(
      principals,
      workforceAdministration,
      repository,
      identities,
      credentials,
      clock,
      atomically,
    ),
    tenantTeam: new TenantTeamAdministration(principals, workforceAdministration, repository),
  };
}

function composeServices(
  runtimeConfig: Config,
  identities: HumanIdentityRepository,
  credentials: EmailCredentialRepository,
  sessions: SessionRepository,
  federatedIdentities: FederatedIdentityRepository,
  federatedNonces: FederatedAuthenticationNonceRepository,
  controlPlaneRepository: ControlPlaneRepository,
  compensator: RegistrationCompensator,
  clock = new SystemClock(),
  atomically: <T>(work: () => Promise<T>) => Promise<T> = async (work) => work(),
): {
  register: Register;
  login: Login;
  authenticateFederated: AuthenticateFederated;
  authenticateAppleWeb?: AuthenticateAppleWeb;
  federatedAuthenticationMethods: ManageFederatedAuthenticationMethods;
  logout: Logout;
  validateSession: ValidateSession;
} {
  const passwordOperations = createPasswordOperations(runtimeConfig);

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
  const appleVerifier = runtimeConfig.APPLE_CLIENT_IDS.length === 0
    ? new UnavailableFederatedIdentityTokenVerifier(APPLE_FEDERATED_PROVIDER)
    : new AppleIdentityTokenVerifier({ clientIds: runtimeConfig.APPLE_CLIENT_IDS });
  const authenticateFederated = new AuthenticateFederated(
    new FederatedIdentityTokenVerifiers([appleVerifier]),
    federatedIdentities,
    federatedNonces,
    identities,
    new UuidHumanIdentityIdGenerator(),
    new UuidFederatedIdentityIdGenerator(),
    createSession,
    clock,
    atomically,
  );
  const appleWebConfig = appleWebConfiguration(runtimeConfig);
  const authenticateAppleWeb = appleWebConfig === null
    ? undefined
    : new AuthenticateAppleWeb(
      new AppleWebAuthorizationCodeExchanger(appleWebConfig),
      authenticateFederated,
    );
  const federatedAuthenticationMethods = new ManageFederatedAuthenticationMethods(
    new FederatedIdentityTokenVerifiers([appleVerifier]),
    federatedIdentities,
    federatedNonces,
    identities,
    credentials,
    sessions,
    controlPlaneRepository,
    new UuidFederatedIdentityIdGenerator(),
    clock,
    atomically,
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
    authenticateFederated,
    ...(authenticateAppleWeb === undefined ? {} : { authenticateAppleWeb }),
    federatedAuthenticationMethods,
    logout: new Logout(sessions),
    validateSession: new ValidateSession(sessions, clock),
  };
}

function appleWebConfiguration(runtimeConfig: Config): {
  clientId: string;
  teamId: string;
  keyId: string;
  privateKey: string;
  redirectUri: string;
} | null {
  if (
    runtimeConfig.APPLE_WEB_CLIENT_ID === undefined ||
    runtimeConfig.APPLE_WEB_REDIRECT_URI === undefined ||
    runtimeConfig.APPLE_TEAM_ID === undefined ||
    runtimeConfig.APPLE_KEY_ID === undefined ||
    runtimeConfig.APPLE_PRIVATE_KEY === undefined
  ) {
    return null;
  }
  return {
    clientId: runtimeConfig.APPLE_WEB_CLIENT_ID,
    teamId: runtimeConfig.APPLE_TEAM_ID,
    keyId: runtimeConfig.APPLE_KEY_ID,
    privateKey: runtimeConfig.APPLE_PRIVATE_KEY,
    redirectUri: runtimeConfig.APPLE_WEB_REDIRECT_URI,
  };
}

function createPasswordOperations(runtimeConfig: Config): Argon2PasswordOperations {
  return new Argon2PasswordOperations({
    memoryCost: runtimeConfig.PASSWORD_HASH_MEMORY_KIB,
    timeCost: runtimeConfig.PASSWORD_HASH_ITERATIONS,
    parallelism: runtimeConfig.PASSWORD_HASH_PARALLELISM,
  });
}
