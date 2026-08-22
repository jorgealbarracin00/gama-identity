import { HumanIdentity } from "../../../identity/domain/human-identity.js";
import type { HumanIdentityIdGenerator } from "../../../identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../../identity/ports/human-identity-repository.js";
import type { CreateSession, SessionMetadata } from "../../../sessions/application/use-cases.js";
import type { Clock } from "../../../shared/clock.js";
import {
  FederatedIdentity,
  FederatedIdentityProvider,
} from "../domain/federated-identity.js";
import type { FederatedIdentityIdGenerator } from "../domain/federated-identity-id.js";
import type {
  FederatedAuthenticationNonceRepository,
  FederatedIdentityRepository,
} from "../ports/federated-identity-repository.js";
import {
  FederatedAuthenticationError,
  FederatedIdentitySubjectConflictError,
} from "./errors.js";
import type {
  FederatedCredentialInput,
  VerifiedFederatedCredential,
} from "./token-verifier.js";
import { FederatedIdentityTokenVerifiers } from "./token-verifier.js";

export interface FederatedAuthenticationInput extends FederatedCredentialInput {
  readonly provider: string;
}

export interface FederatedAuthenticationResult {
  readonly created: boolean;
  readonly humanIdentityId: string;
  readonly providerEmail: string | null;
  readonly session: SessionMetadata;
}

export class AuthenticateFederated {
  constructor(
    private readonly verifiers: FederatedIdentityTokenVerifiers,
    private readonly federatedIdentities: FederatedIdentityRepository,
    private readonly nonces: FederatedAuthenticationNonceRepository,
    private readonly humanIdentities: HumanIdentityRepository,
    private readonly humanIdentityIds: HumanIdentityIdGenerator,
    private readonly federatedIdentityIds: FederatedIdentityIdGenerator,
    private readonly createSession: CreateSession,
    private readonly clock: Clock,
    private readonly atomically: <T>(work: () => Promise<T>) => Promise<T>,
  ) {}

  async execute(input: FederatedAuthenticationInput): Promise<FederatedAuthenticationResult> {
    let provider: FederatedIdentityProvider;
    try {
      provider = FederatedIdentityProvider.from(input.provider);
    } catch {
      throw new FederatedAuthenticationError("PROVIDER_UNSUPPORTED");
    }
    const verified = await this.verifiers.verify(provider, input);
    try {
      return await this.atomically(() => this.complete(verified));
    } catch (error) {
      if (!(error instanceof FederatedIdentitySubjectConflictError)) throw error;
      // A different nonce may complete the same first sign-in concurrently. The
      // losing transaction is rolled back, then resolves the winner's identity.
      return this.atomically(() => this.complete(verified, false));
    }
  }

  private async complete(
    verified: VerifiedFederatedCredential,
    allowCreate = true,
  ): Promise<FederatedAuthenticationResult> {
    const consumed = await this.nonces.consume(
      verified.provider,
      verified.nonceHash,
      verified.expiresAt,
      this.clock.now(),
    );
    if (!consumed) throw new FederatedAuthenticationError("CREDENTIAL_REPLAYED");

    const existing = await this.federatedIdentities.findByProviderSubject(
      verified.provider,
      verified.providerSubject,
    );
    if (existing !== null) {
      if (existing.status !== "active") {
        throw new FederatedAuthenticationError("FEDERATED_IDENTITY_UNAVAILABLE");
      }
      const identity = await this.humanIdentities.findById(existing.humanIdentityId);
      if (identity === null || identity.status !== "active") {
        throw new FederatedAuthenticationError("IDENTITY_UNAVAILABLE");
      }
      existing.recordVerifiedMetadata(verified.metadata, this.clock);
      await this.federatedIdentities.save(existing);
      return {
        created: false,
        humanIdentityId: identity.id.value,
        providerEmail: existing.providerEmail,
        session: await this.createSession.execute(identity.id),
      };
    }
    if (!allowCreate) {
      throw new FederatedAuthenticationError("FEDERATED_IDENTITY_CONFLICT");
    }

    const humanIdentity = HumanIdentity.create(this.humanIdentityIds, this.clock);
    await this.humanIdentities.save(humanIdentity);
    const federatedIdentity = FederatedIdentity.create(
      this.federatedIdentityIds,
      humanIdentity.id,
      verified.provider,
      verified.providerSubject,
      verified.metadata,
      this.clock,
    );
    await this.federatedIdentities.save(federatedIdentity);
    return {
      created: true,
      humanIdentityId: humanIdentity.id.value,
      providerEmail: federatedIdentity.providerEmail,
      session: await this.createSession.execute(humanIdentity.id),
    };
  }
}
