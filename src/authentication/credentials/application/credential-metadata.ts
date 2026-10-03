import type {
  EmailCredential,
  EmailCredentialStatus,
} from "../domain/email-credential.js";

export interface EmailCredentialMetadata {
  readonly id: string;
  readonly humanIdentityId: string;
  readonly email: string;
  readonly status: EmailCredentialStatus;
  readonly emailVerified: boolean;
  readonly emailVerifiedAt: Date | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export function toEmailCredentialMetadata(
  credential: EmailCredential,
): EmailCredentialMetadata {
  return {
    id: credential.id.value,
    humanIdentityId: credential.humanIdentityId.value,
    email: credential.email.value,
    status: credential.status,
    emailVerified: credential.emailVerified,
    emailVerifiedAt: credential.emailVerifiedAt,
    createdAt: credential.createdAt,
    updatedAt: credential.updatedAt,
  };
}
