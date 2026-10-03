import { createHash, randomBytes, randomUUID } from "node:crypto";

import type {
  EmailActionChallenge,
  EmailActionChallengeRepository,
  EmailActionPurpose,
  EmailActionTokenGenerator,
  IdentityEmailDelivery,
  IdentityEmailMessage,
  IdentityEmailService,
  IdentitySecurityAttemptRepository,
  SecurityAttemptInput,
} from "./ports.js";
import type { EmailCredentialId } from "../credentials/domain/email-credential-id.js";

export class SecureEmailActionTokenGenerator implements EmailActionTokenGenerator {
  next(): { readonly id: string; readonly value: string; readonly hash: string } {
    const value = randomBytes(32).toString("base64url");
    return { id: randomUUID(), value, hash: this.hash(value) };
  }

  hash(value: string): string {
    return createHash("sha256").update(value, "utf8").digest("base64url");
  }
}

export class InMemoryEmailActionChallengeRepository
implements EmailActionChallengeRepository {
  private readonly challenges = new Map<string, EmailActionChallenge>();

  async replaceActive(challenge: EmailActionChallenge): Promise<void> {
    for (const [id, existing] of this.challenges) {
      if (
        existing.consumedAt === null &&
        existing.credentialId.equals(challenge.credentialId) &&
        existing.purpose === challenge.purpose
      ) {
        this.challenges.set(id, copyChallenge({ ...existing, consumedAt: challenge.createdAt }));
      }
    }
    this.challenges.set(challenge.id, copyChallenge(challenge));
  }

  async findByTokenHashForUpdate(
    tokenHash: string,
    purpose: EmailActionPurpose,
  ): Promise<EmailActionChallenge | null> {
    for (const challenge of this.challenges.values()) {
      if (challenge.tokenHash === tokenHash && challenge.purpose === purpose) {
        return copyChallenge(challenge);
      }
    }
    return null;
  }

  async consumeActiveForCredential(
    credentialId: EmailCredentialId,
    purpose: EmailActionPurpose,
    consumedAt: Date,
  ): Promise<void> {
    for (const [id, challenge] of this.challenges) {
      if (
        challenge.consumedAt === null &&
        challenge.credentialId.equals(credentialId) &&
        challenge.purpose === purpose
      ) {
        this.challenges.set(id, copyChallenge({ ...challenge, consumedAt }));
      }
    }
  }

  async deleteStale(olderThan: Date): Promise<void> {
    for (const [id, challenge] of this.challenges) {
      if (
        challenge.expiresAt.getTime() < olderThan.getTime() ||
        (challenge.consumedAt?.getTime() ?? Number.POSITIVE_INFINITY) < olderThan.getTime()
      ) {
        this.challenges.delete(id);
      }
    }
  }
}

export class InMemoryIdentitySecurityAttemptRepository
implements IdentitySecurityAttemptRepository {
  private readonly attempts: SecurityAttemptInput[] = [];

  async consume(input: SecurityAttemptInput): Promise<boolean> {
    const threshold = input.occurredAt.getTime() - input.windowSeconds * 1_000;
    const matching = this.attempts.filter((attempt) =>
      attempt.action === input.action &&
      attempt.occurredAt.getTime() >= threshold &&
      (attempt.subjectHash === input.subjectHash || attempt.ipHash === input.ipHash));
    if (matching.length >= input.maximumAttempts) return false;
    this.attempts.push({ ...input, occurredAt: new Date(input.occurredAt) });
    return true;
  }

  async deleteOlderThan(olderThan: Date): Promise<void> {
    const retained = this.attempts.filter((attempt) => attempt.occurredAt >= olderThan);
    this.attempts.splice(0, this.attempts.length, ...retained);
  }
}

export class DisabledIdentityEmailService implements IdentityEmailService {
  readonly enabled = false;
  async send(_message: IdentityEmailMessage): Promise<"disabled"> {
    return "disabled";
  }
}

export class ResendIdentityEmailService implements IdentityEmailService {
  readonly enabled = true;
  constructor(
    private readonly apiKey: string,
    private readonly from: string,
    private readonly fetchImplementation: typeof fetch = fetch,
  ) {}

  async send(message: IdentityEmailMessage): Promise<IdentityEmailDelivery> {
    try {
      const response = await this.fetchImplementation("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ from: this.from, ...message }),
      });
      return response.ok ? "sent" : "failed";
    } catch {
      return "failed";
    }
  }
}

function copyChallenge(challenge: EmailActionChallenge): EmailActionChallenge {
  return {
    ...challenge,
    createdAt: new Date(challenge.createdAt),
    expiresAt: new Date(challenge.expiresAt),
    consumedAt: challenge.consumedAt === null ? null : new Date(challenge.consumedAt),
  };
}
