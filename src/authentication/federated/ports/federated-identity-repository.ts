import type {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
} from "../domain/federated-identity.js";

export interface FederatedIdentityRepository {
  save(identity: FederatedIdentity): Promise<void>;
  findByProviderSubject(
    provider: FederatedIdentityProvider,
    providerSubject: FederatedProviderSubject,
  ): Promise<FederatedIdentity | null>;
}

export interface FederatedAuthenticationNonceRepository {
  /** Atomically consumes a verified, hashed provider nonce exactly once. */
  consume(
    provider: FederatedIdentityProvider,
    nonceHash: string,
    expiresAt: Date,
    consumedAt: Date,
  ): Promise<boolean>;
}
