import { createHash } from "node:crypto";

import type { PasswordHasher, PasswordVerifier } from "../../src/authentication/credentials/ports/password-operations.js";
import {
  InMemoryFederatedAuthenticationNonceRepository,
  InMemoryFederatedIdentityRepository,
} from "../../src/authentication/federated/adapters/in-memory-federated-identity-repository.js";
import { AuthenticateFederated } from "../../src/authentication/federated/application/authenticate-federated.js";
import { ManageFederatedAuthenticationMethods } from "../../src/authentication/federated/application/manage-federated-authentication-methods.js";
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

export class FederatedIdentityIds implements FederatedIdentityIdGenerator {
  private sequence = 0;
  next(): FederatedIdentityId {
    this.sequence += 1;
    return FederatedIdentityId.from(`federated-${this.sequence}`);
  }
}

export class DeterministicAppleVerifier implements FederatedIdentityTokenVerifier {
  readonly provider = FederatedIdentityProvider.from("apple");
  private readonly credentials = new Map<string, Omit<VerifiedFederatedCredential, "provider" | "nonceHash">>();

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
  federatedIdentities: InMemoryFederatedIdentityRepository;
  federatedNonces: InMemoryFederatedAuthenticationNonceRepository;
  appleVerifier: DeterministicAppleVerifier;
  controlPlaneRepository: InMemoryControlPlaneRepository;
  workforceAdministration: WorkforceAdministration;
  platformAdministrationProvisioning: PlatformAdministrationProvisioning;
} {
  const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
  const identities = new InMemoryHumanIdentityRepository();
  const credentials = new InMemoryEmailCredentialRepository();
  const sessions = new InMemorySessionRepository();
  const federatedIdentities = new InMemoryFederatedIdentityRepository();
  const federatedNonces = new InMemoryFederatedAuthenticationNonceRepository();
  const appleVerifier = new DeterministicAppleVerifier();
  const serial = new SerialExecutor();
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
  const createSession = new CreateSession(
    sessions,
    new SessionIds(),
    clock,
    3600,
  );
  const authenticateFederated = new AuthenticateFederated(
    new FederatedIdentityTokenVerifiers([appleVerifier]),
    federatedIdentities,
    federatedNonces,
    identities,
    identityIds,
    new FederatedIdentityIds(),
    createSession,
    clock,
    (work) => serial.execute(work),
  );
  const controlPlaneRepository = new InMemoryControlPlaneRepository();
  const federatedAuthenticationMethods = new ManageFederatedAuthenticationMethods(
    new FederatedIdentityTokenVerifiers([appleVerifier]),
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
    federatedAuthenticationMethods,
    logout: new Logout(sessions),
    validateSession: new ValidateSession(sessions, clock),
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
    controlPlaneRepository,
    workforceAdministration,
    platformAdministrationProvisioning,
  };
}
