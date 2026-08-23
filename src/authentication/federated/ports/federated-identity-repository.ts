import type {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
} from "../domain/federated-identity.js";
import type { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";

export interface FederatedIdentityRepository {
  save(identity: FederatedIdentity): Promise<void>;
  findByProviderSubject(
    provider: FederatedIdentityProvider,
    providerSubject: FederatedProviderSubject,
  ): Promise<FederatedIdentity | null>;
  listByHumanIdentityId(humanIdentityId: HumanIdentityId): Promise<readonly FederatedIdentity[]>;
  /**
   * Administrative discovery only: returns active relationships whose
   * provider asserted and verified the supplied email. Provider subjects are
   * deliberately not projected by this lookup.
   */
  listActiveByVerifiedProviderEmail(email: string): Promise<readonly FederatedIdentity[]>;
  findActiveByHumanIdentityAndProvider(
    humanIdentityId: HumanIdentityId,
    provider: FederatedIdentityProvider,
  ): Promise<FederatedIdentity | null>;
  /** Serializes sign-in/link/unlink decisions for one verified provider subject. */
  lockProviderSubject(
    provider: FederatedIdentityProvider,
    providerSubject: FederatedProviderSubject,
  ): Promise<void>;
  /** Serializes the zero-or-one active provider relationship for a Human. */
  lockHumanProvider(
    humanIdentityId: HumanIdentityId,
    provider: FederatedIdentityProvider,
  ): Promise<void>;
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
