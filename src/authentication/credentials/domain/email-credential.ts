import type { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";
import type { Clock } from "../../../shared/clock.js";
import {
  CredentialUnavailableForAuthenticationError,
  InvalidEmailCredentialTransitionError,
  RetiredEmailCredentialMutationError,
} from "./errors.js";
import type { NormalizedEmail } from "./email.js";
import {
  type EmailCredentialIdGenerator,
  EmailCredentialId,
} from "./email-credential-id.js";
import type { PasswordHash } from "./password.js";
import type { PasswordVerifier } from "../ports/password-operations.js";

export type EmailCredentialStatus = "active" | "disabled" | "retired";

export interface EmailCredentialSnapshot {
  readonly id: EmailCredentialId;
  readonly humanIdentityId: HumanIdentityId;
  readonly email: NormalizedEmail;
  readonly passwordHash: PasswordHash;
  readonly status: EmailCredentialStatus;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export class EmailCredential {
  private constructor(
    private readonly credentialId: EmailCredentialId,
    private readonly ownerId: HumanIdentityId,
    private readonly normalizedEmail: NormalizedEmail,
    private passwordDigest: PasswordHash,
    private lifecycleStatus: EmailCredentialStatus,
    private readonly creationTime: Date,
    private lastUpdatedTime: Date,
  ) {}

  static create(
    idGenerator: EmailCredentialIdGenerator,
    humanIdentityId: HumanIdentityId,
    email: NormalizedEmail,
    passwordHash: PasswordHash,
    clock: Clock,
  ): EmailCredential {
    const now = clock.now();

    return new EmailCredential(
      idGenerator.next(),
      humanIdentityId,
      email,
      passwordHash,
      "active",
      new Date(now.getTime()),
      new Date(now.getTime()),
    );
  }

  static reconstitute(snapshot: EmailCredentialSnapshot): EmailCredential {
    return new EmailCredential(
      snapshot.id,
      snapshot.humanIdentityId,
      snapshot.email,
      snapshot.passwordHash,
      snapshot.status,
      new Date(snapshot.createdAt),
      new Date(snapshot.updatedAt),
    );
  }

  get id(): EmailCredentialId {
    return this.credentialId;
  }

  get humanIdentityId(): HumanIdentityId {
    return this.ownerId;
  }

  get email(): NormalizedEmail {
    return this.normalizedEmail;
  }

  get status(): EmailCredentialStatus {
    return this.lifecycleStatus;
  }

  get createdAt(): Date {
    return new Date(this.creationTime.getTime());
  }

  get updatedAt(): Date {
    return new Date(this.lastUpdatedTime.getTime());
  }

  disable(clock: Clock): void {
    if (this.lifecycleStatus === "disabled") {
      return;
    }

    if (this.lifecycleStatus === "retired") {
      throw new InvalidEmailCredentialTransitionError("retired", "disabled");
    }

    this.transitionTo("disabled", clock);
  }

  enable(clock: Clock): void {
    if (this.lifecycleStatus === "active") {
      return;
    }

    if (this.lifecycleStatus === "retired") {
      throw new InvalidEmailCredentialTransitionError("retired", "active");
    }

    this.transitionTo("active", clock);
  }

  retire(clock: Clock): void {
    if (this.lifecycleStatus === "retired") {
      return;
    }

    this.transitionTo("retired", clock);
  }

  replacePassword(passwordHash: PasswordHash, clock: Clock): void {
    if (this.lifecycleStatus === "retired") {
      throw new RetiredEmailCredentialMutationError();
    }

    const now = clock.now();
    this.passwordDigest = passwordHash;
    this.lastUpdatedTime = new Date(now.getTime());
  }

  isEligibleForAuthentication(): boolean {
    return this.lifecycleStatus === "active";
  }

  assertEligibleForAuthentication(): void {
    if (!this.isEligibleForAuthentication()) {
      throw new CredentialUnavailableForAuthenticationError(
        this.lifecycleStatus,
      );
    }
  }

  async verifyPassword(
    plaintextPassword: string,
    verifier: PasswordVerifier,
  ): Promise<boolean> {
    this.assertEligibleForAuthentication();
    return verifier.verify(plaintextPassword, this.passwordDigest);
  }

  copy(): EmailCredential {
    return new EmailCredential(
      this.credentialId,
      this.ownerId,
      this.normalizedEmail,
      this.passwordDigest,
      this.lifecycleStatus,
      this.createdAt,
      this.updatedAt,
    );
  }

  snapshotForPersistence(): EmailCredentialSnapshot {
    return {
      id: this.credentialId,
      humanIdentityId: this.ownerId,
      email: this.normalizedEmail,
      passwordHash: this.passwordDigest,
      status: this.lifecycleStatus,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }

  private transitionTo(status: EmailCredentialStatus, clock: Clock): void {
    const now = clock.now();
    this.lifecycleStatus = status;
    this.lastUpdatedTime = new Date(now.getTime());
  }
}
