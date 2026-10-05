import type { FederatedIdentityRepository } from "../ports/federated-identity-repository.js";
import { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";
import { APPLE_FEDERATED_PROVIDER } from "../adapters/apple-identity-token-verifier.js";
import type { FederatedIdentityTokenVerifier } from "./token-verifier.js";
import { AppError } from "../../../shared/errors.js";

export interface AppleDeletionProof { readonly authorizationCode: string; readonly nonce: string; }
export interface AppleRevocationRecord {
  operationId: string; principalId: string; clientId: string; encryptedToken: string | null; completedAt: string | null;
}
export interface AppleRevocationStore {
  find(operationId: string): Promise<AppleRevocationRecord | null>;
  save(record: AppleRevocationRecord): Promise<void>;
  complete(operationId: string): Promise<void>;
}
export interface ProductAppleTokens {
  exchange(code: string): Promise<{ identityToken: string; refreshToken: string }>;
  revoke(token: string): Promise<void>;
  encrypt(token: string, context: string): string;
  decrypt(token: string, context: string): string;
}

/** Revokes one Apple app grant. Never unlinks/deletes the shared GAMA Human. */
export class ProductAppleRevocation {
  constructor(private readonly clientId: string, private readonly identities: FederatedIdentityRepository,
    private readonly verifier: FederatedIdentityTokenVerifier, private readonly store: AppleRevocationStore,
    private readonly tokens: ProductAppleTokens) {}

  async execute(principalId: string, operationId: string, proof?: AppleDeletionProof): Promise<void> {
    let record = await this.store.find(operationId);
    if (record && (record.principalId !== principalId || record.clientId !== this.clientId)) {
      throw new AppError("Deletion request does not match this account", "DELETION_CONFLICT", 409);
    }
    if (record?.completedAt) return;
    const identity = await this.identities.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(principalId), APPLE_FEDERATED_PROVIDER);
    if (!record && !identity) return; // Password/Google-only Humans have no Apple authorization.
    const context = `${principalId}:${this.clientId}:${operationId}`;
    if (!record) {
      if (!proof) throw new AppError("Confirm your Apple account to finish deletion", "APPLE_REAUTH_REQUIRED", 409);
      const grant = await this.tokens.exchange(proof.authorizationCode);
      const verified = await this.verifier.verify({ identityToken: grant.identityToken, nonce: proof.nonce });
      if (!identity || verified.providerSubject.value !== identity.providerSubject.value) {
        throw new AppError("Use the Apple account linked to Grocery Master", "APPLE_REAUTH_REQUIRED", 409);
      }
      record = { operationId, principalId, clientId: this.clientId,
        encryptedToken: this.tokens.encrypt(grant.refreshToken, context), completedAt: null };
      await this.store.save(record); // Durable before contacting revoke; retry survives process loss.
      record = await this.store.find(operationId);
      if (!record) throw new AppError("Deletion could not be saved", "APPLE_REVOCATION_UNAVAILABLE", 503);
    }
    if (record.completedAt) return;
    if (!record.encryptedToken) throw new AppError("Deletion grant unavailable", "APPLE_REAUTH_REQUIRED", 409);
    await this.tokens.revoke(this.tokens.decrypt(record.encryptedToken, context));
    await this.store.complete(operationId); // Erase Apple credential, retain idempotency receipt.
  }
}
