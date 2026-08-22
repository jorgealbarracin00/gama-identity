import { FederatedIdentitySubjectConflictError } from "../application/errors.js";
import type {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
} from "../domain/federated-identity.js";
import type {
  FederatedAuthenticationNonceRepository,
  FederatedIdentityRepository,
} from "../ports/federated-identity-repository.js";

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
