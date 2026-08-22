import { FederatedIdentitySubjectConflictError } from "../../authentication/federated/application/errors.js";
import {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
  type FederatedIdentityStatus,
} from "../../authentication/federated/domain/federated-identity.js";
import { FederatedIdentityId } from "../../authentication/federated/domain/federated-identity-id.js";
import type {
  FederatedAuthenticationNonceRepository,
  FederatedIdentityRepository,
} from "../../authentication/federated/ports/federated-identity-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { DatabaseQuery } from "./database.js";

interface FederatedIdentityRow {
  readonly id: string;
  readonly human_identity_id: string;
  readonly provider: string;
  readonly provider_subject: string;
  readonly provider_email: string | null;
  readonly provider_email_verified: boolean | null;
  readonly provider_email_private: boolean | null;
  readonly status: FederatedIdentityStatus;
  readonly created_at: Date;
  readonly updated_at: Date;
}

interface PostgresError {
  readonly code?: string;
  readonly constraint?: string;
}

export class PostgresFederatedIdentityRepository implements FederatedIdentityRepository {
  constructor(private readonly database: DatabaseQuery) {}

  async save(identity: FederatedIdentity): Promise<void> {
    const snapshot = identity.snapshot();
    try {
      await this.database.query(
        `INSERT INTO federated_identities (
           id, human_identity_id, provider, provider_subject,
           provider_email, provider_email_verified, provider_email_private,
           status, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (id) DO UPDATE SET
           provider_email = EXCLUDED.provider_email,
           provider_email_verified = EXCLUDED.provider_email_verified,
           provider_email_private = EXCLUDED.provider_email_private,
           status = EXCLUDED.status,
           updated_at = EXCLUDED.updated_at`,
        [
          snapshot.id.value,
          snapshot.humanIdentityId.value,
          snapshot.provider.value,
          snapshot.providerSubject.value,
          snapshot.providerEmail,
          snapshot.providerEmailVerified,
          snapshot.providerEmailPrivate,
          snapshot.status,
          snapshot.createdAt,
          snapshot.updatedAt,
        ],
      );
    } catch (error) {
      const postgresError = error as PostgresError;
      if (
        postgresError.code === "23505" &&
        postgresError.constraint === "federated_identities_provider_provider_subject_key"
      ) {
        throw new FederatedIdentitySubjectConflictError();
      }
      throw error;
    }
  }

  async findByProviderSubject(
    provider: FederatedIdentityProvider,
    providerSubject: FederatedProviderSubject,
  ): Promise<FederatedIdentity | null> {
    const result = await this.database.query<FederatedIdentityRow>(
      `SELECT id, human_identity_id, provider, provider_subject,
              provider_email, provider_email_verified, provider_email_private,
              status, created_at, updated_at
       FROM federated_identities
       WHERE provider = $1 AND provider_subject = $2`,
      [provider.value, providerSubject.value],
    );
    const row = result.rows[0];
    return row === undefined ? null : FederatedIdentity.reconstitute({
      id: FederatedIdentityId.from(row.id),
      humanIdentityId: HumanIdentityId.from(row.human_identity_id),
      provider: FederatedIdentityProvider.from(row.provider),
      providerSubject: FederatedProviderSubject.from(row.provider_subject),
      providerEmail: row.provider_email,
      providerEmailVerified: row.provider_email_verified,
      providerEmailPrivate: row.provider_email_private,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  }
}

export class PostgresFederatedAuthenticationNonceRepository
implements FederatedAuthenticationNonceRepository {
  constructor(private readonly database: DatabaseQuery) {}

  async consume(
    provider: FederatedIdentityProvider,
    nonceHash: string,
    expiresAt: Date,
    consumedAt: Date,
  ): Promise<boolean> {
    const result = await this.database.query(
      `INSERT INTO federated_authentication_nonces (
         provider, nonce_hash, expires_at, consumed_at
       ) VALUES ($1, $2, $3, $4)
       ON CONFLICT (provider, nonce_hash) DO NOTHING
       RETURNING provider`,
      [provider.value, nonceHash, expiresAt, consumedAt],
    );
    return result.rowCount === 1;
  }
}
