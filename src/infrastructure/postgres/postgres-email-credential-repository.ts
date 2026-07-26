import {
  EmailCredential,
  type EmailCredentialStatus,
} from "../../authentication/credentials/domain/email-credential.js";
import { EmailCredentialId } from "../../authentication/credentials/domain/email-credential-id.js";
import { EmailAlreadyInUseError } from "../../authentication/credentials/domain/errors.js";
import { NormalizedEmail } from "../../authentication/credentials/domain/email.js";
import { PasswordHash } from "../../authentication/credentials/domain/password.js";
import type { EmailCredentialRepository } from "../../authentication/credentials/ports/email-credential-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { DatabaseQuery } from "./database.js";

interface CredentialRow {
  id: string;
  human_identity_id: string;
  normalized_email: string;
  password_hash: string;
  status: EmailCredentialStatus;
  created_at: Date;
  updated_at: Date;
}

interface PostgresError {
  readonly code?: string;
  readonly constraint?: string;
}

export class PostgresEmailCredentialRepository
  implements EmailCredentialRepository
{
  constructor(private readonly database: DatabaseQuery) {}

  async save(credential: EmailCredential): Promise<void> {
    const snapshot = credential.snapshotForPersistence();
    try {
      await this.database.query(
        `INSERT INTO credentials (
           id, human_identity_id, normalized_email, password_hash,
           status, created_at, updated_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO UPDATE SET
           password_hash = EXCLUDED.password_hash,
           status = EXCLUDED.status,
           updated_at = EXCLUDED.updated_at`,
        [
          snapshot.id.value,
          snapshot.humanIdentityId.value,
          snapshot.email.value,
          snapshot.passwordHash.value,
          snapshot.status,
          snapshot.createdAt,
          snapshot.updatedAt,
        ],
      );
    } catch (error) {
      const postgresError = error as PostgresError;
      if (
        postgresError.code === "23505" &&
        postgresError.constraint ===
          "credentials_non_retired_email_unique"
      ) {
        throw new EmailAlreadyInUseError();
      }
      throw error;
    }
  }

  async findById(id: EmailCredentialId): Promise<EmailCredential | null> {
    const result = await this.database.query<CredentialRow>(
      `${selectCredential} WHERE id = $1`,
      [id.value],
    );
    return toCredential(result.rows[0]);
  }

  async findByNormalizedEmail(
    email: NormalizedEmail,
  ): Promise<EmailCredential | null> {
    const result = await this.database.query<CredentialRow>(
      `${selectCredential}
       WHERE normalized_email = $1 AND status <> 'retired'`,
      [email.value],
    );
    return toCredential(result.rows[0]);
  }

  async remove(id: EmailCredentialId): Promise<void> {
    await this.database.query("DELETE FROM credentials WHERE id = $1", [
      id.value,
    ]);
  }
}

const selectCredential = `
  SELECT id, human_identity_id, normalized_email, password_hash,
         status, created_at, updated_at
  FROM credentials
`;

function toCredential(row: CredentialRow | undefined): EmailCredential | null {
  return row === undefined
    ? null
    : EmailCredential.reconstitute({
        id: EmailCredentialId.from(row.id),
        humanIdentityId: HumanIdentityId.from(row.human_identity_id),
        email: NormalizedEmail.from(row.normalized_email),
        passwordHash: PasswordHash.from(row.password_hash),
        status: row.status,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      });
}
