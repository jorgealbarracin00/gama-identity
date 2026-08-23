import { randomUUID } from "node:crypto";

import type { EmailCredentialRepository } from "../../credentials/ports/email-credential-repository.js";
import type { ControlPlaneRepository } from "../../../control-plane/ports/control-plane-repository.js";
import type { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../../identity/ports/human-identity-repository.js";
import type { Session } from "../../../sessions/domain/session.js";
import type { SessionId } from "../../../sessions/domain/session-id.js";
import type { SessionRepository } from "../../../sessions/ports/session-repository.js";
import type { Clock } from "../../../shared/clock.js";
import {
  FederatedIdentity,
  FederatedIdentityProvider,
  type FederatedProviderMetadata,
} from "../domain/federated-identity.js";
import type { FederatedIdentityIdGenerator } from "../domain/federated-identity-id.js";
import type {
  FederatedAuthenticationNonceRepository,
  FederatedIdentityRepository,
} from "../ports/federated-identity-repository.js";
import {
  FederatedAuthenticationError,
  FederatedIdentityHumanProviderConflictError,
} from "./errors.js";
import type { FederatedCredentialInput, VerifiedFederatedCredential } from "./token-verifier.js";
import { FederatedIdentityTokenVerifiers } from "./token-verifier.js";

export type FederatedAuthenticationMethodErrorCode =
  | "SESSION_INVALID"
  | "SESSION_EXPIRED"
  | "SESSION_REVOKED"
  | "IDENTITY_UNAVAILABLE"
  | "FEDERATED_IDENTITY_LINK_CONFLICT"
  | "FEDERATED_IDENTITY_RECONCILIATION_REQUIRED"
  | "LAST_AUTHENTICATION_METHOD";

export class FederatedAuthenticationMethodError extends Error {
  constructor(readonly code: FederatedAuthenticationMethodErrorCode) {
    super(code);
    this.name = "FederatedAuthenticationMethodError";
  }
}

export interface AuthenticationMethodsProjection {
  readonly humanIdentityId: string;
  readonly emailPassword: {
    readonly connected: boolean;
    readonly email: string | null;
  };
  readonly federated: readonly {
    readonly provider: string;
    readonly email: string | null;
    readonly emailPrivate: boolean | null;
  }[];
}

export interface FederatedLinkInput extends FederatedCredentialInput {
  readonly provider: string;
}

export interface FederatedLinkResult {
  readonly outcome: "linked" | "already_linked" | "reconciled";
  readonly humanIdentityId: string;
  readonly methods: AuthenticationMethodsProjection;
}

export interface FederatedUnlinkResult {
  readonly outcome: "unlinked" | "already_unlinked";
  readonly humanIdentityId: string;
  readonly methods: AuthenticationMethodsProjection;
}

export class ManageFederatedAuthenticationMethods {
  constructor(
    private readonly verifiers: FederatedIdentityTokenVerifiers,
    private readonly federatedIdentities: FederatedIdentityRepository,
    private readonly nonces: FederatedAuthenticationNonceRepository,
    private readonly humanIdentities: HumanIdentityRepository,
    private readonly credentials: EmailCredentialRepository,
    private readonly sessions: SessionRepository,
    private readonly controlPlane: ControlPlaneRepository,
    private readonly federatedIdentityIds: FederatedIdentityIdGenerator,
    private readonly clock: Clock,
    private readonly atomically: <T>(work: () => Promise<T>) => Promise<T>,
  ) {}

  async list(sessionId: SessionId): Promise<AuthenticationMethodsProjection> {
    return this.atomically(async () => {
      const session = await this.authenticatedSession(sessionId);
      return this.project(session.humanIdentityId);
    });
  }

  async link(sessionId: SessionId, input: FederatedLinkInput): Promise<FederatedLinkResult> {
    // Reject an unusable caller session before asking an external provider verifier
    // to do work. The session is checked again in the mutation transaction.
    await this.atomically(() => this.authenticatedSession(sessionId));

    let provider: FederatedIdentityProvider;
    try {
      provider = FederatedIdentityProvider.from(input.provider);
    } catch {
      throw new FederatedAuthenticationError("PROVIDER_UNSUPPORTED");
    }
    const verified = await this.verifiers.verify(provider, input);

    try {
      return await this.atomically(() => this.completeLink(sessionId, verified));
    } catch (error) {
      if (error instanceof FederatedIdentityHumanProviderConflictError) {
        throw new FederatedAuthenticationMethodError("FEDERATED_IDENTITY_LINK_CONFLICT");
      }
      throw error;
    }
  }

  async unlink(sessionId: SessionId, providerValue: string): Promise<FederatedUnlinkResult> {
    let provider: FederatedIdentityProvider;
    try {
      provider = FederatedIdentityProvider.from(providerValue);
    } catch {
      throw new FederatedAuthenticationError("PROVIDER_UNSUPPORTED");
    }

    return this.atomically(async () => {
      const session = await this.authenticatedSession(sessionId);
      await this.federatedIdentities.lockHumanProvider(session.humanIdentityId, provider);
      let relationship = await this.federatedIdentities.findActiveByHumanIdentityAndProvider(
        session.humanIdentityId,
        provider,
      );
      if (relationship === null) {
        return {
          outcome: "already_unlinked",
          humanIdentityId: session.humanIdentityId.value,
          methods: await this.project(session.humanIdentityId),
        };
      }

      await this.federatedIdentities.lockProviderSubject(provider, relationship.providerSubject);
      relationship = await this.federatedIdentities.findActiveByHumanIdentityAndProvider(
        session.humanIdentityId,
        provider,
      );
      if (relationship === null) {
        return {
          outcome: "already_unlinked",
          humanIdentityId: session.humanIdentityId.value,
          methods: await this.project(session.humanIdentityId),
        };
      }

      const activeCredential = (await this.credentials.listByHumanIdentityId(session.humanIdentityId))
        .some((credential) => credential.status === "active");
      const activeOtherFederated = (await this.federatedIdentities.listByHumanIdentityId(session.humanIdentityId))
        .some((candidate) => candidate.status === "active" && !candidate.id.equals(relationship!.id));
      if (!activeCredential && !activeOtherFederated) {
        throw new FederatedAuthenticationMethodError("LAST_AUTHENTICATION_METHOD");
      }

      relationship.disable(this.clock);
      await this.federatedIdentities.save(relationship);
      await this.appendAudit(
        "authentication.method.unlinked",
        session.humanIdentityId.value,
        `federated-identity:${relationship.id.value}`,
        { provider: provider.value, outcome: "unlinked" },
      );
      return {
        outcome: "unlinked",
        humanIdentityId: session.humanIdentityId.value,
        methods: await this.project(session.humanIdentityId),
      };
    });
  }

  private async completeLink(
    sessionId: SessionId,
    verified: VerifiedFederatedCredential,
  ): Promise<FederatedLinkResult> {
    const session = await this.authenticatedSession(sessionId);
    const targetHumanIdentityId = session.humanIdentityId;
    const consumed = await this.nonces.consume(
      verified.provider,
      verified.nonceHash,
      verified.expiresAt,
      this.clock.now(),
    );
    if (!consumed) throw new FederatedAuthenticationError("CREDENTIAL_REPLAYED");

    await this.federatedIdentities.lockHumanProvider(targetHumanIdentityId, verified.provider);
    await this.federatedIdentities.lockProviderSubject(verified.provider, verified.providerSubject);

    const targetRelationship = await this.federatedIdentities.findActiveByHumanIdentityAndProvider(
      targetHumanIdentityId,
      verified.provider,
    );
    const subjectRelationship = await this.federatedIdentities.findByProviderSubject(
      verified.provider,
      verified.providerSubject,
    );

    if (
      targetRelationship !== null &&
      (subjectRelationship === null || !targetRelationship.id.equals(subjectRelationship.id))
    ) {
      throw new FederatedAuthenticationMethodError("FEDERATED_IDENTITY_LINK_CONFLICT");
    }

    if (subjectRelationship === null) {
      const relationship = FederatedIdentity.create(
        this.federatedIdentityIds,
        targetHumanIdentityId,
        verified.provider,
        verified.providerSubject,
        verified.metadata,
        this.clock,
      );
      await this.federatedIdentities.save(relationship);
      await this.appendLinkedAudit(targetHumanIdentityId, relationship.id.value, verified.provider.value, "linked");
      return this.linkResult("linked", targetHumanIdentityId);
    }

    if (subjectRelationship.humanIdentityId.equals(targetHumanIdentityId)) {
      if (subjectRelationship.status === "retired") {
        throw new FederatedAuthenticationMethodError("FEDERATED_IDENTITY_LINK_CONFLICT");
      }
      const outcome = subjectRelationship.status === "active" ? "already_linked" : "linked";
      subjectRelationship.recordVerifiedMetadata(verified.metadata, this.clock);
      subjectRelationship.activate(this.clock);
      await this.federatedIdentities.save(subjectRelationship);
      if (outcome === "linked") {
        await this.appendLinkedAudit(targetHumanIdentityId, subjectRelationship.id.value, verified.provider.value, outcome);
      }
      return this.linkResult(outcome, targetHumanIdentityId);
    }

    if (targetRelationship !== null) {
      throw new FederatedAuthenticationMethodError("FEDERATED_IDENTITY_LINK_CONFLICT");
    }

    await this.reconcilePristineFederatedOnlyHuman(
      targetHumanIdentityId,
      subjectRelationship,
      verified.metadata,
    );
    await this.appendLinkedAudit(targetHumanIdentityId, subjectRelationship.id.value, verified.provider.value, "reconciled");
    return this.linkResult("reconciled", targetHumanIdentityId);
  }

  private async reconcilePristineFederatedOnlyHuman(
    targetHumanIdentityId: HumanIdentityId,
    relationship: FederatedIdentity,
    verifiedMetadata: FederatedProviderMetadata,
  ): Promise<void> {
    const sourceHumanIdentityId = relationship.humanIdentityId;
    const sourceHuman = await this.humanIdentities.findById(sourceHumanIdentityId);
    if (sourceHuman?.status !== "active") {
      throw new FederatedAuthenticationMethodError("FEDERATED_IDENTITY_RECONCILIATION_REQUIRED");
    }

    const [credentials, federated, sessions, platformMembership, memberships, entitlements] = await Promise.all([
      this.credentials.listByHumanIdentityId(sourceHumanIdentityId),
      this.federatedIdentities.listByHumanIdentityId(sourceHumanIdentityId),
      this.sessions.listByHumanIdentityId(sourceHumanIdentityId),
      this.controlPlane.findPlatformAdministrationMembership(sourceHumanIdentityId.value),
      this.controlPlane.listMembershipsForHuman(sourceHumanIdentityId.value),
      this.controlPlane.listEntitlementsForHumanAcrossTenants(sourceHumanIdentityId.value),
    ]);
    const hasLiveSession = sessions.some((candidate) =>
      candidate.status === "active" && candidate.expiresAt.getTime() > this.clock.now().getTime());
    const isOnlyRelationship = federated.length === 1 && federated[0]?.id.equals(relationship.id) === true;
    if (
      credentials.length !== 0 ||
      !isOnlyRelationship ||
      hasLiveSession ||
      platformMembership !== null ||
      memberships.length !== 0 ||
      entitlements.length !== 0
    ) {
      throw new FederatedAuthenticationMethodError("FEDERATED_IDENTITY_RECONCILIATION_REQUIRED");
    }

    for (const sourceSession of sessions) await this.sessions.revoke(sourceSession.id);
    relationship.reassignTo(targetHumanIdentityId, this.clock);
    relationship.recordVerifiedMetadata(verifiedMetadata, this.clock);
    relationship.activate(this.clock);
    await this.federatedIdentities.save(relationship);
    sourceHuman.retire(this.clock);
    await this.humanIdentities.save(sourceHuman);
    await this.appendAudit(
      "authentication.identity.reconciled",
      targetHumanIdentityId.value,
      `human:${sourceHumanIdentityId.value}`,
      {
        provider: relationship.provider.value,
        outcome: "retired_pristine_federated_only_duplicate",
        sourceHumanIdentityId: sourceHumanIdentityId.value,
        targetHumanIdentityId: targetHumanIdentityId.value,
      },
    );
  }

  private async authenticatedSession(sessionId: SessionId): Promise<Session> {
    const session = await this.sessions.findById(sessionId);
    if (session === null) throw new FederatedAuthenticationMethodError("SESSION_INVALID");
    if (session.status === "revoked") throw new FederatedAuthenticationMethodError("SESSION_REVOKED");
    if (!session.validate(this.clock)) {
      await this.sessions.save(session);
      throw new FederatedAuthenticationMethodError("SESSION_EXPIRED");
    }
    const humanIdentity = await this.humanIdentities.findById(session.humanIdentityId);
    if (humanIdentity?.status !== "active") {
      throw new FederatedAuthenticationMethodError("IDENTITY_UNAVAILABLE");
    }
    session.touch(this.clock);
    await this.sessions.save(session);
    return session;
  }

  private async project(humanIdentityId: HumanIdentityId): Promise<AuthenticationMethodsProjection> {
    const [credentials, federated] = await Promise.all([
      this.credentials.listByHumanIdentityId(humanIdentityId),
      this.federatedIdentities.listByHumanIdentityId(humanIdentityId),
    ]);
    const activeCredential = credentials.find((credential) => credential.status === "active") ?? null;
    return {
      humanIdentityId: humanIdentityId.value,
      emailPassword: {
        connected: activeCredential !== null,
        email: activeCredential?.email.value ?? null,
      },
      federated: federated
        .filter((relationship) => relationship.status === "active")
        .sort((left, right) => left.provider.value.localeCompare(right.provider.value))
        .map((relationship) => ({
          provider: relationship.provider.value,
          email: relationship.providerEmail,
          emailPrivate: relationship.providerEmailPrivate,
        })),
    };
  }

  private async linkResult(
    outcome: FederatedLinkResult["outcome"],
    humanIdentityId: HumanIdentityId,
  ): Promise<FederatedLinkResult> {
    return { outcome, humanIdentityId: humanIdentityId.value, methods: await this.project(humanIdentityId) };
  }

  private appendLinkedAudit(
    humanIdentityId: HumanIdentityId,
    federatedIdentityId: string,
    provider: string,
    outcome: string,
  ): Promise<void> {
    return this.appendAudit(
      "authentication.method.linked",
      humanIdentityId.value,
      `federated-identity:${federatedIdentityId}`,
      { provider, outcome },
    );
  }

  private appendAudit(
    eventType: string,
    actorHumanIdentityId: string,
    subjectReference: string,
    eventData: Readonly<Record<string, string>>,
  ): Promise<void> {
    return this.controlPlane.appendAudit({
      id: randomUUID(),
      eventType,
      actorReference: `human:${actorHumanIdentityId}`,
      subjectReference,
      eventData,
      occurredAt: this.clock.now(),
    });
  }
}
