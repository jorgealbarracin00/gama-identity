import type { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";
import type { Clock } from "../../../shared/clock.js";
import type {
  FederatedIdentityId,
  FederatedIdentityIdGenerator,
} from "./federated-identity-id.js";

const providerPattern = /^[a-z][a-z0-9_-]{0,31}$/;
const maximumProviderSubjectLength = 1024;
const maximumProviderEmailLength = 320;

export class FederatedIdentityProvider {
  private constructor(readonly value: string) {}

  static from(value: string): FederatedIdentityProvider {
    if (!providerPattern.test(value)) {
      throw new Error("Federated Identity provider is invalid");
    }
    return new FederatedIdentityProvider(value);
  }

  equals(other: FederatedIdentityProvider): boolean {
    return this.value === other.value;
  }
}

export class FederatedProviderSubject {
  private constructor(readonly value: string) {}

  static from(value: string): FederatedProviderSubject {
    if (
      value.trim().length === 0 ||
      value.length > maximumProviderSubjectLength
    ) {
      throw new Error("Federated Identity subject is invalid");
    }
    return new FederatedProviderSubject(value);
  }

  equals(other: FederatedProviderSubject): boolean {
    return this.value === other.value;
  }
}

export interface FederatedProviderMetadata {
  readonly email: string | null;
  readonly emailVerified: boolean | null;
  readonly emailPrivate: boolean | null;
}

export type FederatedIdentityStatus = "active" | "disabled" | "retired";

export interface FederatedIdentitySnapshot {
  readonly id: FederatedIdentityId;
  readonly humanIdentityId: HumanIdentityId;
  readonly provider: FederatedIdentityProvider;
  readonly providerSubject: FederatedProviderSubject;
  readonly providerEmail: string | null;
  readonly providerEmailVerified: boolean | null;
  readonly providerEmailPrivate: boolean | null;
  readonly status: FederatedIdentityStatus;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export class FederatedIdentity {
  private constructor(
    private readonly federatedIdentityId: FederatedIdentityId,
    private ownerId: HumanIdentityId,
    private readonly identityProvider: FederatedIdentityProvider,
    private readonly subject: FederatedProviderSubject,
    private email: string | null,
    private emailVerified: boolean | null,
    private emailPrivate: boolean | null,
    private lifecycleStatus: FederatedIdentityStatus,
    private readonly creationTime: Date,
    private lastUpdatedTime: Date,
  ) {}

  static create(
    idGenerator: FederatedIdentityIdGenerator,
    humanIdentityId: HumanIdentityId,
    provider: FederatedIdentityProvider,
    providerSubject: FederatedProviderSubject,
    metadata: FederatedProviderMetadata,
    clock: Clock,
  ): FederatedIdentity {
    const now = clock.now();
    validateProviderEmail(metadata.email);
    return new FederatedIdentity(
      idGenerator.next(),
      humanIdentityId,
      provider,
      providerSubject,
      metadata.email,
      metadata.emailVerified,
      metadata.emailPrivate,
      "active",
      new Date(now),
      new Date(now),
    );
  }

  static reconstitute(snapshot: FederatedIdentitySnapshot): FederatedIdentity {
    validateProviderEmail(snapshot.providerEmail);
    return new FederatedIdentity(
      snapshot.id,
      snapshot.humanIdentityId,
      snapshot.provider,
      snapshot.providerSubject,
      snapshot.providerEmail,
      snapshot.providerEmailVerified,
      snapshot.providerEmailPrivate,
      snapshot.status,
      new Date(snapshot.createdAt),
      new Date(snapshot.updatedAt),
    );
  }

  get id(): FederatedIdentityId { return this.federatedIdentityId; }
  get humanIdentityId(): HumanIdentityId { return this.ownerId; }
  get provider(): FederatedIdentityProvider { return this.identityProvider; }
  get providerSubject(): FederatedProviderSubject { return this.subject; }
  get providerEmail(): string | null { return this.email; }
  get providerEmailVerified(): boolean | null { return this.emailVerified; }
  get providerEmailPrivate(): boolean | null { return this.emailPrivate; }
  get status(): FederatedIdentityStatus { return this.lifecycleStatus; }
  get createdAt(): Date { return new Date(this.creationTime); }
  get updatedAt(): Date { return new Date(this.lastUpdatedTime); }

  recordVerifiedMetadata(metadata: FederatedProviderMetadata, clock: Clock): void {
    if (metadata.email === null) return;
    validateProviderEmail(metadata.email);
    this.email = metadata.email;
    this.emailVerified = metadata.emailVerified;
    this.emailPrivate = metadata.emailPrivate;
    this.lastUpdatedTime = new Date(clock.now());
  }

  reassignTo(humanIdentityId: HumanIdentityId, clock: Clock): void {
    if (this.ownerId.equals(humanIdentityId)) return;
    this.ownerId = humanIdentityId;
    this.lastUpdatedTime = new Date(clock.now());
  }

  activate(clock: Clock): void {
    if (this.lifecycleStatus === "active") return;
    this.lifecycleStatus = "active";
    this.lastUpdatedTime = new Date(clock.now());
  }

  disable(clock: Clock): void {
    if (this.lifecycleStatus === "disabled") return;
    this.lifecycleStatus = "disabled";
    this.lastUpdatedTime = new Date(clock.now());
  }

  snapshot(): FederatedIdentitySnapshot {
    return {
      id: this.id,
      humanIdentityId: this.humanIdentityId,
      provider: this.provider,
      providerSubject: this.providerSubject,
      providerEmail: this.providerEmail,
      providerEmailVerified: this.providerEmailVerified,
      providerEmailPrivate: this.providerEmailPrivate,
      status: this.status,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }

  copy(): FederatedIdentity {
    return FederatedIdentity.reconstitute(this.snapshot());
  }
}

function validateProviderEmail(email: string | null): void {
  if (email !== null && (email.length === 0 || email.length > maximumProviderEmailLength)) {
    throw new Error("Federated provider email metadata is invalid");
  }
}
