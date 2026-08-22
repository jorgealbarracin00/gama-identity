import type {
  FederatedIdentityProvider,
  FederatedProviderMetadata,
  FederatedProviderSubject,
} from "../domain/federated-identity.js";
import { FederatedAuthenticationError } from "./errors.js";

export interface FederatedCredentialInput {
  readonly identityToken: string;
  readonly nonce: string;
}

export interface VerifiedFederatedCredential {
  readonly provider: FederatedIdentityProvider;
  readonly providerSubject: FederatedProviderSubject;
  readonly metadata: FederatedProviderMetadata;
  readonly nonceHash: string;
  readonly expiresAt: Date;
}

export interface FederatedIdentityTokenVerifier {
  readonly provider: FederatedIdentityProvider;
  verify(input: FederatedCredentialInput): Promise<VerifiedFederatedCredential>;
}

export class FederatedIdentityTokenVerifiers {
  private readonly verifiers: ReadonlyMap<string, FederatedIdentityTokenVerifier>;

  constructor(verifiers: readonly FederatedIdentityTokenVerifier[]) {
    this.verifiers = new Map(verifiers.map((verifier) => [verifier.provider.value, verifier]));
  }

  async verify(
    provider: FederatedIdentityProvider,
    input: FederatedCredentialInput,
  ): Promise<VerifiedFederatedCredential> {
    const verifier = this.verifiers.get(provider.value);
    if (verifier === undefined) {
      throw new FederatedAuthenticationError("PROVIDER_UNSUPPORTED");
    }
    return verifier.verify(input);
  }
}

export class UnavailableFederatedIdentityTokenVerifier
implements FederatedIdentityTokenVerifier {
  constructor(readonly provider: FederatedIdentityProvider) {}

  async verify(_input: FederatedCredentialInput): Promise<VerifiedFederatedCredential> {
    throw new FederatedAuthenticationError("VERIFICATION_UNAVAILABLE");
  }
}
