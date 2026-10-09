import { ProductAppleRevocation } from "../authentication/federated/application/product-apple-revocation.js";
import { NativeProductAppleTokens } from "../authentication/federated/adapters/product-apple-tokens.js";
import { PostgresAppleRevocationStore } from "../infrastructure/postgres/postgres-apple-revocation-store.js";
import { Argon2PasswordOperations } from "../authentication/adapters/argon2-password-operations.js";
import { AppleIdentityTokenVerifier, APPLE_FEDERATED_PROVIDER } from "../authentication/federated/adapters/apple-identity-token-verifier.js";
import { AppleWebAuthorizationCodeExchanger } from "../authentication/federated/adapters/apple-authorization-code-exchanger.js";
import { GoogleWebAuthorizationCodeExchanger } from "../authentication/federated/adapters/google-authorization-code-exchanger.js";
import { GoogleIdentityTokenVerifier, GOOGLE_FEDERATED_PROVIDER } from "../authentication/federated/adapters/google-identity-token-verifier.js";
import {
  InMemoryFederatedAuthenticationNonceRepository,
  InMemoryFederatedIdentityRepository,
} from "../authentication/federated/adapters/in-memory-federated-identity-repository.js";
import { AuthenticateFederated } from "../authentication/federated/application/authenticate-federated.js";
import { AuthenticateAppleWeb } from "../authentication/federated/application/authenticate-apple-web.js";
import { AuthenticateGoogleWeb } from "../authentication/federated/application/authenticate-google-web.js";
import { ManageFederatedAuthenticationMethods } from "../authentication/federated/application/manage-federated-authentication-methods.js";
import { ResolveFederatedIdentity } from "../authentication/federated/application/resolve-federated-identity.js";
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
import {
  DisabledIdentityEmailService,
  InMemoryEmailActionChallengeRepository,
  InMemoryIdentitySecurityAttemptRepository,
  ResendIdentityEmailService,
  SecureEmailActionTokenGenerator,
} from "../authentication/email-security/adapters.js";
import { EmailPasswordSecurity } from "../authentication/email-security/application.js";
import type {
  EmailActionChallengeRepository,
  IdentityEmailService,
  IdentitySecurityAttemptRepository,
} from "../authentication/email-security/ports.js";
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
  PostgresEmailActionChallengeRepository,
  PostgresIdentitySecurityAttemptRepository,
} from "../infrastructure/postgres/postgres-email-security-repositories.js";
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
  RenewSession,
  ValidateSession,
} from "../sessions/application/use-cases.js";
import { SecureSessionRenewalTokenGenerator } from "../sessions/domain/session-renewal-token.js";
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
  readonly groceryAppleRevocation?: { serviceToken: string; service: ProductAppleRevocation };
  readonly register: {
    execute(input: CredentialsInput): Promise<RegistrationResult>;
  };
  readonly login: Login;
  readonly authenticateFederated: AuthenticateFederated;
  readonly authenticateAppleWeb?: AuthenticateAppleWeb;
  readonly authenticateGoogleWeb?: AuthenticateGoogleWeb;
  readonly webAuthenticationApps?: ReadonlyMap<string, { apple?: AuthenticateAppleWeb; google?: AuthenticateGoogleWeb }>;
  readonly resolveFederatedIdentity: ResolveFederatedIdentity;
  readonly federatedAuthenticationMethods: ManageFederatedAuthenticationMethods;
  readonly logout: Logout;
  readonly renewSession: RenewSession;
  readonly validateSession: ValidateSession;
  readonly emailPasswordSecurity: EmailPasswordSecurity;
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
  const emailChallenges = new PostgresEmailActionChallengeRepository(database);
  const securityAttempts = new PostgresIdentitySecurityAttemptRepository(database);
  const services = composeServices(
    runtimeConfig,
    identities,
    credentials,
    sessions,
    federatedIdentities,
    federatedNonces,
    emailChallenges,
    securityAttempts,
    createIdentityEmailService(runtimeConfig),
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
      ...(runtimeConfig.GROCERY_REVOCATION_SERVICE_TOKEN === undefined ? {} : {
        groceryAppleRevocation: { serviceToken: runtimeConfig.GROCERY_REVOCATION_SERVICE_TOKEN,
          service: new ProductAppleRevocation("com.gamadynamics.GroceryMaster", federatedIdentities,
            new AppleIdentityTokenVerifier({ clientIds: ["com.gamadynamics.GroceryMaster"] }),
            new PostgresAppleRevocationStore(database), new NativeProductAppleTokens({
              clientId: "com.gamadynamics.GroceryMaster", teamId: runtimeConfig.GROCERY_APPLE_TEAM_ID!,
              keyId: runtimeConfig.GROCERY_APPLE_KEY_ID!, privateKey: runtimeConfig.GROCERY_APPLE_PRIVATE_KEY!,
              encryptionKey: runtimeConfig.GROCERY_APPLE_GRANT_ENCRYPTION_KEY!,
            })) },
      }),
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
  const emailChallenges = new InMemoryEmailActionChallengeRepository();
  const securityAttempts = new InMemoryIdentitySecurityAttemptRepository();
  const serial = new SerialExecutor();
  const services = composeServices(
    runtimeConfig,
    identities,
    credentials,
    sessions,
    federatedIdentities,
    federatedNonces,
    emailChallenges,
    securityAttempts,
    createIdentityEmailService(runtimeConfig),
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
  emailChallenges: EmailActionChallengeRepository,
  securityAttempts: IdentitySecurityAttemptRepository,
  identityEmailService: IdentityEmailService,
  controlPlaneRepository: ControlPlaneRepository,
  compensator: RegistrationCompensator,
  clock = new SystemClock(),
  atomically: <T>(work: () => Promise<T>) => Promise<T> = async (work) => work(),
): {
  register: Register;
  login: Login;
  authenticateFederated: AuthenticateFederated;
  authenticateAppleWeb?: AuthenticateAppleWeb;
  authenticateGoogleWeb?: AuthenticateGoogleWeb;
  webAuthenticationApps?: ReadonlyMap<string, { apple?: AuthenticateAppleWeb; google?: AuthenticateGoogleWeb }>;
  resolveFederatedIdentity: ResolveFederatedIdentity;
  federatedAuthenticationMethods: ManageFederatedAuthenticationMethods;
  logout: Logout;
  renewSession: RenewSession;
  validateSession: ValidateSession;
  emailPasswordSecurity: EmailPasswordSecurity;
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
  const renewalTokens = new SecureSessionRenewalTokenGenerator();
  const createSession = new CreateSession(
    sessions,
    new UuidSessionIdGenerator(),
    clock,
    runtimeConfig.SESSION_DURATION_SECONDS,
    renewalTokens,
    runtimeConfig.SESSION_RENEWAL_DURATION_SECONDS,
  );
  const validateSession = new ValidateSession(sessions, clock);
  const emailPasswordSecurity = new EmailPasswordSecurity(
    credentials,
    sessions,
    validateSession,
    emailChallenges,
    securityAttempts,
    identityEmailService,
    runtimeConfig.IDENTITY_TRUSTED_APPS,
    new SecureEmailActionTokenGenerator(),
    new BaselinePasswordPolicy(),
    passwordOperations,
    clock,
    {
      defaultAppId: runtimeConfig.IDENTITY_DEFAULT_APP_ID,
      verificationTtlSeconds: runtimeConfig.IDENTITY_EMAIL_VERIFICATION_TTL_SECONDS,
      passwordResetTtlSeconds: runtimeConfig.IDENTITY_PASSWORD_RESET_TTL_SECONDS,
      rateLimitWindowSeconds: runtimeConfig.IDENTITY_RATE_LIMIT_WINDOW_SECONDS,
      rateLimitMaximumAttempts: runtimeConfig.IDENTITY_RATE_LIMIT_MAXIMUM_ATTEMPTS,
      rateLimitSecret: runtimeConfig.IDENTITY_RATE_LIMIT_SECRET,
    },
    atomically,
  );
  const appleVerifier = runtimeConfig.APPLE_CLIENT_IDS.length === 0
    ? new UnavailableFederatedIdentityTokenVerifier(APPLE_FEDERATED_PROVIDER)
    : new AppleIdentityTokenVerifier({ clientIds: runtimeConfig.APPLE_CLIENT_IDS });
  const googleVerifier = runtimeConfig.GOOGLE_CLIENT_IDS.length === 0
    ? new UnavailableFederatedIdentityTokenVerifier(GOOGLE_FEDERATED_PROVIDER)
    : new GoogleIdentityTokenVerifier({ clientIds: runtimeConfig.GOOGLE_CLIENT_IDS });
  const federatedVerifiers = new FederatedIdentityTokenVerifiers([appleVerifier, googleVerifier]);
  const authenticateFederated = new AuthenticateFederated(
    federatedVerifiers,
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
  const googleWebConfig = googleWebConfiguration(runtimeConfig);
  const authenticateGoogleWeb = googleWebConfig === null
    ? undefined
    : new AuthenticateGoogleWeb(
      new GoogleWebAuthorizationCodeExchanger(googleWebConfig),
      authenticateFederated,
    );
  const webAuthenticationApps = new Map<string, { apple?: AuthenticateAppleWeb; google?: AuthenticateGoogleWeb }>();
  for (const registeredApp of runtimeConfig.IDENTITY_WEB_APPS) {
    const registered: { apple?: AuthenticateAppleWeb; google?: AuthenticateGoogleWeb } = {};
    // Each exchange validates only its registered client audience while sharing
    // canonical Human resolution and durable provider nonce replay protection.
    if (registeredApp.apple !== undefined) {
      const authentication = new AuthenticateFederated(
        new FederatedIdentityTokenVerifiers([new AppleIdentityTokenVerifier({ clientIds: [registeredApp.apple.clientId] })]),
        federatedIdentities, federatedNonces, identities,
        new UuidHumanIdentityIdGenerator(), new UuidFederatedIdentityIdGenerator(),
        createSession, clock, atomically,
        registeredApp.allowedPrincipalIds === undefined ? undefined : new Set(registeredApp.allowedPrincipalIds),
      );
      registered.apple = new AuthenticateAppleWeb(new AppleWebAuthorizationCodeExchanger(registeredApp.apple), authentication);
    }
    if (registeredApp.google !== undefined) {
      const authentication = new AuthenticateFederated(
        new FederatedIdentityTokenVerifiers([new GoogleIdentityTokenVerifier({ clientIds: [registeredApp.google.clientId] })]),
        federatedIdentities, federatedNonces, identities,
        new UuidHumanIdentityIdGenerator(), new UuidFederatedIdentityIdGenerator(),
        createSession, clock, atomically,
        registeredApp.allowedPrincipalIds === undefined ? undefined : new Set(registeredApp.allowedPrincipalIds),
      );
      registered.google = new AuthenticateGoogleWeb(new GoogleWebAuthorizationCodeExchanger(registeredApp.google), authentication);
    }
    webAuthenticationApps.set(registeredApp.appId, registered);
  }
  const resolveFederatedIdentity = new ResolveFederatedIdentity(
    federatedVerifiers,
    federatedIdentities,
    federatedNonces,
    clock,
    atomically,
  );
  const federatedAuthenticationMethods = new ManageFederatedAuthenticationMethods(
    federatedVerifiers,
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
    ...(authenticateGoogleWeb === undefined ? {} : { authenticateGoogleWeb }),
    ...(webAuthenticationApps.size === 0 ? {} : { webAuthenticationApps }),
    resolveFederatedIdentity,
    federatedAuthenticationMethods,
    logout: new Logout(sessions),
    renewSession: new RenewSession(sessions, createSession, renewalTokens, clock, atomically),
    validateSession,
    emailPasswordSecurity,
  };
}

function createIdentityEmailService(runtimeConfig: Config): IdentityEmailService {
  if (runtimeConfig.IDENTITY_EMAIL_PROVIDER === "resend") {
    return new ResendIdentityEmailService(
      runtimeConfig.RESEND_API_KEY!,
      runtimeConfig.IDENTITY_EMAIL_FROM!,
    );
  }
  return new DisabledIdentityEmailService();
}

function googleWebConfiguration(runtimeConfig: Config): {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
} | null {
  if (
    runtimeConfig.GOOGLE_WEB_CLIENT_ID === undefined ||
    runtimeConfig.GOOGLE_WEB_CLIENT_SECRET === undefined ||
    runtimeConfig.GOOGLE_WEB_REDIRECT_URI === undefined
  ) {
    return null;
  }
  return {
    clientId: runtimeConfig.GOOGLE_WEB_CLIENT_ID,
    clientSecret: runtimeConfig.GOOGLE_WEB_CLIENT_SECRET,
    redirectUri: runtimeConfig.GOOGLE_WEB_REDIRECT_URI,
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
