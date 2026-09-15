import type { Clock } from "../../../shared/clock.js";
import { FederatedIdentityProvider } from "../domain/federated-identity.js";
import type {
  FederatedAuthenticationNonceRepository,
  FederatedIdentityRepository,
} from "../ports/federated-identity-repository.js";
import { FederatedAuthenticationError } from "./errors.js";
import type { FederatedCredentialInput } from "./token-verifier.js";
import { FederatedIdentityTokenVerifiers } from "./token-verifier.js";

export interface FederatedIdentityResolutionInput extends FederatedCredentialInput {
  readonly provider: string;
}

export type FederatedIdentityResolutionOutcome = "EXISTING" | "UNLINKED";

export interface FederatedIdentityResolutionResult {
  readonly outcome: FederatedIdentityResolutionOutcome;
}

/**
 * Verifies a provider credential and reports only whether its exact external
 * identity already has a GAMA relationship. The consumed nonce is the sole
 * write performed by this use case.
 */
export class ResolveFederatedIdentity {
  constructor(
    private readonly verifiers: FederatedIdentityTokenVerifiers,
    private readonly federatedIdentities: FederatedIdentityRepository,
    private readonly nonces: FederatedAuthenticationNonceRepository,
    private readonly clock: Clock,
    private readonly atomically: <T>(work: () => Promise<T>) => Promise<T>,
  ) {}

  async execute(
    input: FederatedIdentityResolutionInput,
  ): Promise<FederatedIdentityResolutionResult> {
    let provider: FederatedIdentityProvider;
    try {
      provider = FederatedIdentityProvider.from(input.provider);
    } catch {
      throw new FederatedAuthenticationError("PROVIDER_UNSUPPORTED");
    }

    const verified = await this.verifiers.verify(provider, input);
    return this.atomically(async () => {
      const consumed = await this.nonces.consume(
        verified.provider,
        verified.nonceHash,
        verified.expiresAt,
        this.clock.now(),
      );
      if (!consumed) {
        throw new FederatedAuthenticationError("CREDENTIAL_REPLAYED");
      }

      await this.federatedIdentities.lockProviderSubject(
        verified.provider,
        verified.providerSubject,
      );
      const existing = await this.federatedIdentities.findByProviderSubject(
        verified.provider,
        verified.providerSubject,
      );

      return { outcome: existing === null ? "UNLINKED" : "EXISTING" };
    });
  }
}
