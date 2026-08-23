import {
  FederatedIdentityHumanProviderConflictError,
  FederatedIdentitySubjectConflictError,
} from "../application/errors.js";
import type {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
} from "../domain/federated-identity.js";
import type {
  FederatedAuthenticationNonceRepository,
  FederatedIdentityRepository,
} from "../ports/federated-identity-repository.js";
import type { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";

export class InMemoryFederatedIdentityRepository implements FederatedIdentityRepository {
  private readonly identities = new Map<string, FederatedIdentity>();

  get count(): number { return this.identities.size; }

  async save(identity: FederatedIdentity): Promise<void> {
    const conflicting = await this.findByProviderSubject(
      identity.provider,
      identity.providerSubject,
    );
    if (conflicting !== null && !conflicting.id.equals(identity.id)) {
      throw new FederatedIdentitySubjectConflictError();
    }
    if (identity.status === "active") {
      const providerConflict = await this.findActiveByHumanIdentityAndProvider(
        identity.humanIdentityId,
        identity.provider,
      );
      if (providerConflict !== null && !providerConflict.id.equals(identity.id)) {
        throw new FederatedIdentityHumanProviderConflictError();
      }
    }
    this.identities.set(identity.id.value, identity.copy());
  }

  async findByProviderSubject(
    provider: FederatedIdentityProvider,
    providerSubject: FederatedProviderSubject,
  ): Promise<FederatedIdentity | null> {
    for (const identity of this.identities.values()) {
      if (
        identity.provider.equals(provider) &&
        identity.providerSubject.equals(providerSubject)
      ) return identity.copy();
    }
    return null;
  }

  async listByHumanIdentityId(humanIdentityId: HumanIdentityId): Promise<readonly FederatedIdentity[]> {
    return [...this.identities.values()]
      .filter((identity) => identity.humanIdentityId.equals(humanIdentityId))
      .map((identity) => identity.copy());
  }

  async listActiveByVerifiedProviderEmail(email: string): Promise<readonly FederatedIdentity[]> {
    const comparableEmail = email.toLocaleLowerCase("en-US");
    return [...this.identities.values()]
      .filter((identity) =>
        identity.status === "active" &&
        identity.providerEmailVerified === true &&
        identity.providerEmail?.toLocaleLowerCase("en-US") === comparableEmail
      )
      .map((identity) => identity.copy());
  }

  async findActiveByHumanIdentityAndProvider(
    humanIdentityId: HumanIdentityId,
    provider: FederatedIdentityProvider,
  ): Promise<FederatedIdentity | null> {
    for (const identity of this.identities.values()) {
      if (
        identity.status === "active" &&
        identity.humanIdentityId.equals(humanIdentityId) &&
        identity.provider.equals(provider)
      ) return identity.copy();
    }
    return null;
  }

  async lockProviderSubject(
    _provider: FederatedIdentityProvider,
    _providerSubject: FederatedProviderSubject,
  ): Promise<void> {}

  async lockHumanProvider(
    _humanIdentityId: HumanIdentityId,
    _provider: FederatedIdentityProvider,
  ): Promise<void> {}
}

export class InMemoryFederatedAuthenticationNonceRepository
implements FederatedAuthenticationNonceRepository {
  private readonly nonces = new Set<string>();

  async consume(
    provider: FederatedIdentityProvider,
    nonceHash: string,
    _expiresAt: Date,
    _consumedAt: Date,
  ): Promise<boolean> {
    const key = `${provider.value}:${nonceHash}`;
    if (this.nonces.has(key)) return false;
    this.nonces.add(key);
    return true;
  }
}
