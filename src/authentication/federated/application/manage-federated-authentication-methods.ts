import type { GoogleLinkObserver } from "../../../control-plane/application/google-recovery-verification.js";
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
  | "LAST_AUTHENTICATION_METHOD"
  | "REAUTHENTICATION_REQUIRED";

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

/** Scoped web linking may only add proof to an approved existing account. */
export interface FederatedLinkPolicy {
  readonly allowedPrincipalIds: ReadonlySet<string>;
  readonly allowReconciliation: false;
}

export interface FederatedLinkResult {
  readonly outcome: "linked" | "already_linked" | "reconciled";
  readonly humanIdentityId: string;
  readonly methods: AuthenticationMethodsProjection;
}

export interface FederatedUnlinkResult {
  readonly reauthenticationRequired: boolean;
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
    private readonly linkPolicy?: FederatedLinkPolicy,
    private readonly observation?: GoogleLinkObserver,
  ) {}

  async preflightLink(sessionId: SessionId): Promise<HumanIdentityId> {
    return this.atomically(async () =>
      (await this.authenticatedSession(sessionId, true)).humanIdentityId);
  }

  async list(sessionId: SessionId): Promise<AuthenticationMethodsProjection> {
    return this.atomically(async () => {
      const session = await this.authenticatedSession(sessionId);
      return this.project(session.humanIdentityId);
    });
  }

  async link(
    sessionId: SessionId,
    input: FederatedLinkInput,
    expectedHumanIdentityId?: HumanIdentityId,
  ): Promise<FederatedLinkResult> {
    // Reject an unusable caller session before asking an external provider verifier
    // to do work. The session is checked again in the mutation transaction.
    const actor = await this.atomically(() => this.authenticatedSession(sessionId, true, expectedHumanIdentityId));

    let provider: FederatedIdentityProvider;
    try {
      provider = FederatedIdentityProvider.from(input.provider);
    } catch {
      throw new FederatedAuthenticationError("PROVIDER_UNSUPPORTED");
    }
    const verified = await this.verifiers.verify(provider, input);
    // The observation transaction commits evidence before the unchanged conflict
    // is emitted. It must never fall through into linking for an armed case.
    if (await this.observation?.observe(sessionId, verified)) {
      throw new FederatedAuthenticationMethodError("FEDERATED_IDENTITY_LINK_CONFLICT");
    }

    // Consume verified proof in its own transaction. A conflict must not roll
    // replay protection back along with the declined relationship mutation.
    await this.atomically(async () => {
      await this.authenticatedSession(sessionId,true,expectedHumanIdentityId);
      if (!await this.nonces.consume(verified.provider,verified.nonceHash,verified.expiresAt,this.clock.now())) {
        throw new FederatedAuthenticationError("CREDENTIAL_REPLAYED");
      }
    });
    try {
      return await this.atomically(() => this.completeLink(sessionId, verified, expectedHumanIdentityId));
    } catch (error) {
      if (error instanceof FederatedIdentityHumanProviderConflictError ||
        error instanceof FederatedAuthenticationMethodError && error.code === "FEDERATED_IDENTITY_LINK_CONFLICT") {
        await this.atomically(() => this.appendAudit("authentication.method.link_conflict",actor.humanIdentityId.value,
          `human-identity:${actor.humanIdentityId.value}`,{provider:provider.value}));
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
      const session = await this.authenticatedSession(sessionId, true);
      await this.federatedIdentities.lockHumanProvider(session.humanIdentityId, provider);
      let relationship = await this.federatedIdentities.findActiveByHumanIdentityAndProvider(
        session.humanIdentityId,
        provider,
      );
      if (relationship === null) {
        return {
          outcome: "already_unlinked",
          reauthenticationRequired: false,
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
          reauthenticationRequired: false,
          humanIdentityId: session.humanIdentityId.value,
          methods: await this.project(session.humanIdentityId),
        };
      }

      const activeCredential = (await this.credentials.listByHumanIdentityId(session.humanIdentityId))
        .some((credential) => credential.status === "active" && credential.emailVerified);
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
      let reauthenticationRequired=false;
      for (const candidate of await this.sessions.listByHumanIdentityId(session.humanIdentityId)) {
        if (candidate.authenticationMethod === provider.value || candidate.authenticationMethod === null) {
          await this.sessions.revoke(candidate.id);
          if (candidate.id.equals(sessionId)) reauthenticationRequired=true;
        }
      }
      return {
        outcome: "unlinked",
        reauthenticationRequired,
        humanIdentityId: session.humanIdentityId.value,
        methods: await this.project(session.humanIdentityId),
      };
    });
  }

  private async completeLink(
    sessionId: SessionId,
    verified: VerifiedFederatedCredential,
    expectedHumanIdentityId?: HumanIdentityId,
  ): Promise<FederatedLinkResult> {
    const session = await this.authenticatedSession(sessionId, true, expectedHumanIdentityId);
    const targetHumanIdentityId = session.humanIdentityId;
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

    // A proved provider owned by another Human is a conflict, even if that
    // account looks disposable. Explicit Connect never transfers or retires.
    // Verified, separately confirmed transfer is handled by identity recovery.
    throw new FederatedAuthenticationMethodError("FEDERATED_IDENTITY_LINK_CONFLICT");
  }

  private async authenticatedSession(
    sessionId: SessionId,
    forLink = false,
    expectedHumanIdentityId?: HumanIdentityId,
  ): Promise<Session> {
    const scopedLink = forLink && this.linkPolicy !== undefined;
    let session = await this.sessions.findById(sessionId);
    if (forLink && session) {
      // Acquire Human before session/provider locks. Different sessions cannot
      // concurrently remove each other's last remaining authentication method.
      await this.humanIdentities.lockForAccountManagement?.(session.humanIdentityId);
      session = await this.sessions.findByIdForUpdate(sessionId);
    }
    if (session === null) throw new FederatedAuthenticationMethodError("SESSION_INVALID");
    if (scopedLink && !this.linkPolicy!.allowedPrincipalIds.has(session.humanIdentityId.value)) {
      throw new FederatedAuthenticationMethodError("IDENTITY_UNAVAILABLE");
    }
    if (expectedHumanIdentityId !== undefined && !session.humanIdentityId.equals(expectedHumanIdentityId)) {
      throw new FederatedAuthenticationMethodError("SESSION_INVALID");
    }
    if (session.status === "revoked") throw new FederatedAuthenticationMethodError("SESSION_REVOKED");
    if (!session.validate(this.clock)) {
      if (!scopedLink) await this.sessions.save(session);
      throw new FederatedAuthenticationMethodError("SESSION_EXPIRED");
    }
    if (forLink) {
      const age=this.clock.now().getTime()-session.authenticatedAt.getTime();
      if (age<0 || age>300000) throw new FederatedAuthenticationMethodError("REAUTHENTICATION_REQUIRED");
    }
    const humanIdentity = await this.humanIdentities.findById(session.humanIdentityId);
    if (humanIdentity?.status !== "active") {
      throw new FederatedAuthenticationMethodError("IDENTITY_UNAVAILABLE");
    }
    // Scoped linking preserves the caller's session and holds its row lock
    // until the final mutation commits; it cannot overwrite a concurrent revoke.
    if (!scopedLink) {
      session.touch(this.clock);
      await this.sessions.save(session);
    }
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
