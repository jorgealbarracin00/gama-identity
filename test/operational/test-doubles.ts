import { createHash } from "node:crypto";

import type { PasswordHasher, PasswordVerifier } from "../../src/authentication/credentials/ports/password-operations.js";
import {
  InMemoryFederatedAuthenticationNonceRepository,
  InMemoryFederatedIdentityRepository,
} from "../../src/authentication/federated/adapters/in-memory-federated-identity-repository.js";
import { AuthenticateFederated } from "../../src/authentication/federated/application/authenticate-federated.js";
import { ManageFederatedAuthenticationMethods } from "../../src/authentication/federated/application/manage-federated-authentication-methods.js";
import { ResolveFederatedIdentity } from "../../src/authentication/federated/application/resolve-federated-identity.js";
import { FederatedAuthenticationError } from "../../src/authentication/federated/application/errors.js";
import {
  FederatedIdentityTokenVerifiers,
  type FederatedCredentialInput,
  type FederatedIdentityTokenVerifier,
  type VerifiedFederatedCredential,
} from "../../src/authentication/federated/application/token-verifier.js";
import {
  FederatedIdentityProvider,
  FederatedProviderSubject,
} from "../../src/authentication/federated/domain/federated-identity.js";
import { FederatedIdentityId, type FederatedIdentityIdGenerator } from "../../src/authentication/federated/domain/federated-identity-id.js";
import { PasswordHash } from "../../src/authentication/credentials/domain/password.js";
import type { Clock } from "../../src/shared/clock.js";
import { HumanIdentityId, type HumanIdentityIdGenerator } from "../../src/identity/domain/human-identity-id.js";
import { EmailCredentialId, type EmailCredentialIdGenerator } from "../../src/authentication/credentials/domain/email-credential-id.js";
import { SessionId, type SessionIdGenerator } from "../../src/sessions/domain/session-id.js";
import type { SessionRenewalTokenGenerator } from "../../src/sessions/domain/session-renewal-token.js";
import { InMemoryHumanIdentityRepository } from "../../src/identity/adapters/in-memory-human-identity-repository.js";
import { InMemoryEmailCredentialRepository } from "../../src/authentication/credentials/adapters/in-memory-email-credential-repository.js";
import { InMemorySessionRepository } from "../../src/sessions/adapters/in-memory-session-repository.js";
import { CreateHumanIdentity } from "../../src/identity/application/use-cases.js";
import { CreateEmailCredential } from "../../src/authentication/credentials/application/use-cases.js";
import { BaselinePasswordPolicy } from "../../src/authentication/credentials/domain/password-policy.js";
import { Authenticate } from "../../src/authentication/application/authenticate.js";
import { CreateSession, Logout, RenewSession, ValidateSession } from "../../src/sessions/application/use-cases.js";
import { InMemoryRegistrationCompensator } from "../../src/operations/adapters/in-memory-registration-compensator.js";
import { Login, Register } from "../../src/operations/application/use-cases.js";
import type { IdentityServices } from "../../src/api/services.js";
import { ControlPlane } from "../../src/control-plane/application/control-plane.js";
import { InMemoryControlPlaneRepository } from "../../src/control-plane/adapters/in-memory-control-plane-repository.js";
import { WorkforceAdministration } from "../../src/control-plane/application/workforce-administration.js";
import { AdministrationPrincipals } from "../../src/control-plane/application/administration-principals.js";
import {
  PlatformAdministration,
  PlatformAdministrationProvisioning,
} from "../../src/control-plane/application/platform-administration.js";
import { TenantTeamAdministration } from "../../src/control-plane/application/tenant-team-administration.js";
import { SerialExecutor } from "../../src/shared/serial-executor.js";
import {
  InMemoryEmailActionChallengeRepository,
  InMemoryIdentitySecurityAttemptRepository,
  SecureEmailActionTokenGenerator,
} from "../../src/authentication/email-security/adapters.js";
import { EmailPasswordSecurity } from "../../src/authentication/email-security/application.js";
import type {
  IdentityEmailMessage,
  IdentityEmailService,
} from "../../src/authentication/email-security/ports.js";

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

export class RenewalTokens implements SessionRenewalTokenGenerator {
  private sequence = 0;
  next(): { readonly value: string; readonly hash: string } {
    this.sequence += 1;
    const value = `renewal-token-${String(this.sequence).padStart(32, "0")}`;
    return { value, hash: this.hash(value) };
  }
  hash(value: string): string {
    return createHash("sha256").update(value, "utf8").digest("hex");
  }
}

export class FederatedIdentityIds implements FederatedIdentityIdGenerator {
  private sequence = 0;
  next(): FederatedIdentityId {
    this.sequence += 1;
    return FederatedIdentityId.from(`federated-${this.sequence}`);
  }
}

export class DeterministicFederatedVerifier implements FederatedIdentityTokenVerifier {
  readonly provider: FederatedIdentityProvider;
  private readonly credentials = new Map<string, Omit<VerifiedFederatedCredential, "provider" | "nonceHash">>();

  constructor(provider: string) {
    this.provider = FederatedIdentityProvider.from(provider);
  }

  accept(
    identityToken: string,
    input: {
      readonly subject: string;
      readonly email?: string | null;
      readonly emailVerified?: boolean | null;
      readonly emailPrivate?: boolean | null;
      readonly expiresAt?: Date;
    },
  ): void {
    this.credentials.set(identityToken, {
      providerSubject: FederatedProviderSubject.from(input.subject),
      metadata: {
        email: input.email ?? null,
        emailVerified: input.emailVerified ?? null,
        emailPrivate: input.emailPrivate ?? null,
      },
      expiresAt: input.expiresAt ?? new Date("2026-01-01T01:00:00.000Z"),
    });
  }

  async verify(input: FederatedCredentialInput): Promise<VerifiedFederatedCredential> {
    const credential = this.credentials.get(input.identityToken);
    if (credential === undefined) throw new FederatedAuthenticationError("INVALID_SIGNATURE");
    return {
      provider: this.provider,
      ...credential,
      nonceHash: createHash("sha256").update(input.nonce).digest("base64url"),
    };
  }
}

export class DeterministicAppleVerifier extends DeterministicFederatedVerifier {
  constructor() { super("apple"); }
}

export class DeterministicGoogleVerifier extends DeterministicFederatedVerifier {
  constructor() { super("google"); }
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

export class RecordingIdentityEmailService implements IdentityEmailService {
  readonly enabled = true;
  readonly messages: IdentityEmailMessage[] = [];

  async send(message: IdentityEmailMessage): Promise<"sent"> {
    this.messages.push(message);
    return "sent";
  }
}

export function buildTestServices(): {
  services: IdentityServices;
  clock: MutableClock;
  identities: InMemoryHumanIdentityRepository;
  credentials: InMemoryEmailCredentialRepository;
  sessions: InMemorySessionRepository;
  federatedIdentities: InMemoryFederatedIdentityRepository;
  federatedNonces: InMemoryFederatedAuthenticationNonceRepository;
  appleVerifier: DeterministicAppleVerifier;
  googleVerifier: DeterministicGoogleVerifier;
  controlPlaneRepository: InMemoryControlPlaneRepository;
  workforceAdministration: WorkforceAdministration;
  platformAdministrationProvisioning: PlatformAdministrationProvisioning;
  emails: RecordingIdentityEmailService;
} {
  const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
  const identities = new InMemoryHumanIdentityRepository();
  const credentials = new InMemoryEmailCredentialRepository();
  const sessions = new InMemorySessionRepository();
  const federatedIdentities = new InMemoryFederatedIdentityRepository();
  const federatedNonces = new InMemoryFederatedAuthenticationNonceRepository();
  const appleVerifier = new DeterministicAppleVerifier();
  const googleVerifier = new DeterministicGoogleVerifier();
  const serial = new SerialExecutor();
  const emailChallenges = new InMemoryEmailActionChallengeRepository();
  const securityAttempts = new InMemoryIdentitySecurityAttemptRepository();
  const emails = new RecordingIdentityEmailService();
  const passwords = new DeterministicPasswords();
  const identityIds = new IdentityIds();
  const createIdentity = new CreateHumanIdentity(
    identities,
    identityIds,
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
  const renewalTokens = new RenewalTokens();
  const createSession = new CreateSession(
    sessions,
    new SessionIds(),
    clock,
    3600,
    renewalTokens,
    86_400,
  );
  const validateSession = new ValidateSession(sessions, clock);
  const emailPasswordSecurity = new EmailPasswordSecurity(
    credentials,
    sessions,
    validateSession,
    emailChallenges,
    securityAttempts,
    emails,
    [{ id: "coco-web", displayName: "Coco the Llama", baseUrl: "https://cocothellama.com" }],
    new SecureEmailActionTokenGenerator(),
    new BaselinePasswordPolicy(),
    passwords,
    clock,
    {
      defaultAppId: "coco-web",
      verificationTtlSeconds: 86_400,
      passwordResetTtlSeconds: 3_600,
      rateLimitWindowSeconds: 900,
      rateLimitMaximumAttempts: 5,
      rateLimitSecret: "test-rate-limit-secret-with-32-characters",
    },
    (work) => serial.execute(work),
  );
  const federatedVerifiers = new FederatedIdentityTokenVerifiers([appleVerifier, googleVerifier]);
  const authenticateFederated = new AuthenticateFederated(
    federatedVerifiers,
    federatedIdentities,
    federatedNonces,
    identities,
    identityIds,
    new FederatedIdentityIds(),
    createSession,
    clock,
    (work) => serial.execute(work),
  );
  const resolveFederatedIdentity = new ResolveFederatedIdentity(
    federatedVerifiers,
    federatedIdentities,
    federatedNonces,
    clock,
    (work) => serial.execute(work),
  );
  const controlPlaneRepository = new InMemoryControlPlaneRepository();
  const federatedAuthenticationMethods = new ManageFederatedAuthenticationMethods(
    new FederatedIdentityTokenVerifiers([appleVerifier, googleVerifier]),
    federatedIdentities,
    federatedNonces,
    identities,
    credentials,
    sessions,
    controlPlaneRepository,
    new FederatedIdentityIds(),
    clock,
    (work) => serial.execute(work),
  );
  const controlPlane = new ControlPlane(
    controlPlaneRepository,
    identities,
    passwords,
    clock,
  );
  const workforceAdministration = new WorkforceAdministration(
    controlPlaneRepository,
    identities,
    credentials,
    federatedIdentities,
    clock,
  );
  const principals = new AdministrationPrincipals(controlPlaneRepository, identities, controlPlane);
  let tenantSequence = 0;
  const administration = {
    platform: new PlatformAdministration(
      principals,
      workforceAdministration,
      controlPlaneRepository,
      identities,
      credentials,
      clock,
      undefined,
      () => `tenant-${++tenantSequence}`,
    ),
    tenantTeam: new TenantTeamAdministration(principals, workforceAdministration, controlPlaneRepository),
  };
  const platformAdministrationProvisioning = new PlatformAdministrationProvisioning(
    controlPlaneRepository,
    identities,
    clock,
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
    authenticateFederated,
    resolveFederatedIdentity,
    federatedAuthenticationMethods,
    logout: new Logout(sessions),
    renewSession: new RenewSession(
      sessions,
      createSession,
      renewalTokens,
      clock,
      (work) => serial.execute(work),
    ),
    validateSession,
    emailPasswordSecurity,
    controlPlane,
    administration,
  };
  return {
    services,
    clock,
    identities,
    credentials,
    sessions,
    federatedIdentities,
    federatedNonces,
    appleVerifier,
    googleVerifier,
    controlPlaneRepository,
    workforceAdministration,
    platformAdministrationProvisioning,
    emails,
  };
}
