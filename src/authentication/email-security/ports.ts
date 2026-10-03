import type { EmailCredentialId } from "../credentials/domain/email-credential-id.js";

export type EmailActionPurpose = "verify_email" | "reset_password";
export type IdentitySecurityAction =
  | "registration"
  | "verify_email"
  | "resend_verification"
  | "forgot_password"
  | "reset_password";

export interface EmailActionChallenge {
  readonly id: string;
  readonly credentialId: EmailCredentialId;
  readonly appId: string;
  readonly purpose: EmailActionPurpose;
  readonly tokenHash: string;
  readonly expiresAt: Date;
  readonly consumedAt: Date | null;
  readonly createdAt: Date;
}

export interface EmailActionChallengeRepository {
  replaceActive(challenge: EmailActionChallenge): Promise<void>;
  findByTokenHashForUpdate(
    tokenHash: string,
    purpose: EmailActionPurpose,
  ): Promise<EmailActionChallenge | null>;
  consumeActiveForCredential(
    credentialId: EmailCredentialId,
    purpose: EmailActionPurpose,
    consumedAt: Date,
  ): Promise<void>;
  deleteStale(olderThan: Date): Promise<void>;
}

export interface SecurityAttemptInput {
  readonly action: IdentitySecurityAction;
  readonly subjectHash: string;
  readonly ipHash: string;
  readonly occurredAt: Date;
  readonly windowSeconds: number;
  readonly maximumAttempts: number;
}

export interface IdentitySecurityAttemptRepository {
  consume(input: SecurityAttemptInput): Promise<boolean>;
  deleteOlderThan(olderThan: Date): Promise<void>;
}

export interface IdentityEmailMessage {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
  readonly html: string;
}

export type IdentityEmailDelivery = "sent" | "disabled" | "failed";

export interface IdentityEmailService {
  readonly enabled: boolean;
  send(message: IdentityEmailMessage): Promise<IdentityEmailDelivery>;
}

export interface EmailActionTokenGenerator {
  next(): {
    readonly id: string;
    readonly value: string;
    readonly hash: string;
  };
  hash(value: string): string;
}

export interface TrustedIdentityApp {
  readonly id: string;
  readonly displayName: string;
  readonly baseUrl: string;
}
