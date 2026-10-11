import { createHash, randomUUID } from "node:crypto";
import { AdministrationAuthorizationError } from "./administration-principals.js";
import type { AdministrationPrincipals } from "./administration-principals.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import { capabilitiesForTenantWorkforceRole } from "../models.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { EmailCredentialRepository } from "../../authentication/credentials/ports/email-credential-repository.js";
import type { FederatedIdentityRepository, FederatedAuthenticationNonceRepository } from "../../authentication/federated/ports/federated-identity-repository.js";
import type { VerifiedFederatedCredential } from "../../authentication/federated/application/token-verifier.js";
import type { SessionRepository } from "../../sessions/ports/session-repository.js";
import type { SessionId } from "../../sessions/domain/session-id.js";
import type { Clock } from "../../shared/clock.js";
import { AppError } from "../../shared/errors.js";

export interface GoogleVerificationScope { readonly target: string; readonly source: string; readonly appId: "cashcast-preview" }
export interface ObservationCase {
  id: string; sourceHumanIdentityId: string; targetHumanIdentityId: string; appId: string; state: "awaiting_proof" | "reviewed" | "cancelled";
  createdAt: string; expiresAt: string; observedAt: string | null;
  matched: boolean | null; relationshipId: string | null; reviewDigest: string;
}
export interface VerificationStore {
  latestForUpdate(): Promise<ObservationCase | null>;
  save(value: ObservationCase): Promise<void>;
  extras(human: string): Promise<{ provisioningReferences: number; emailChallenges: number; appleRevocationReferences: number }>;
}
export interface GoogleLinkObserver {
  observe(session: SessionId, verified: VerifiedFederatedCredential): Promise<boolean>;
}
/** No mutation repository for Human, credential, relationship or session is called by this service. */
export class GoogleRecoveryVerification implements GoogleLinkObserver {
  constructor(private readonly scope: GoogleVerificationScope, private readonly principals: AdministrationPrincipals,
    private readonly humans: Pick<HumanIdentityRepository, "findById">, private readonly credentials: Pick<EmailCredentialRepository, "listByHumanIdentityId">,
    private readonly federated: Pick<FederatedIdentityRepository, "listByHumanIdentityId" | "findByProviderSubject" | "lockProviderSubject">, private readonly sessions: Pick<SessionRepository, "findById" | "listByHumanIdentityId">,
    private readonly nonces: FederatedAuthenticationNonceRepository, private readonly control: Pick<ControlPlaneRepository, "appendAudit" | "findPlatformAdministrationMembership" | "listMembershipsForHuman" | "listEntitlementsForHumanAcrossTenants">,
    private readonly store: VerificationStore, private readonly clock: Clock,
    private readonly atomically: <T>(work: () => Promise<T>) => Promise<T>,
    private readonly appAvailable = true) {}

  private async caller(sessionId: SessionId, fresh = false) {
    const session = await this.sessions.findById(sessionId);
    if (!session || session.status !== "active" || session.expiresAt <= this.clock.now())
      throw new AppError("A live administrator session is required", "SESSION_INVALID", 401);
    try { await this.principals.platform(session.humanIdentityId.value); }
    catch (error) {
      if (error instanceof AdministrationAuthorizationError) throw new AppError("Platform administration authority is required", "NOT_PLATFORM_ADMIN", 403);
      throw error;
    }
    if (session.humanIdentityId.value !== this.scope.target)
      throw new AppError("This verification is restricted to the primary identity", "RECOVERY_SCOPE_FORBIDDEN", 403);
    const age = this.clock.now().getTime() - session.authenticatedAt.getTime();
    if (fresh && (age < 0 || age > 300_000))
      throw new AppError("Sign in again through Apple or Email before verification", "RECOVERY_REAUTHENTICATION_REQUIRED", 403);
    return session;
  }

  private async inventory(id: string) {
    const humanId = HumanIdentityId.from(id);
    const [human, credentials, methods, sessions, platform, memberships, entitlements, extras] = await Promise.all([
      this.humans.findById(humanId), this.credentials.listByHumanIdentityId(humanId),
      this.federated.listByHumanIdentityId(humanId), this.sessions.listByHumanIdentityId(humanId),
      this.control.findPlatformAdministrationMembership(id), this.control.listMembershipsForHuman(id),
      this.control.listEntitlementsForHumanAcrossTenants(id), this.store.extras(id),
    ]);
    const now = this.clock.now();
    return {
      humanIdentityId: id, status: human?.status ?? "missing",
      authenticationMethods: [
        ...credentials.map(c => ({ method: "email_password", status: c.status, createdAt: c.createdAt.toISOString(), updatedAt: c.updatedAt.toISOString() })),
        ...methods.map(m => ({ method: m.provider.value, status: m.status, createdAt: m.createdAt.toISOString(), updatedAt: m.updatedAt.toISOString() })),
      ].sort((a,b) => a.method.localeCompare(b.method) || a.createdAt.localeCompare(b.createdAt)),
      platformMembership: platform ? { role: platform.platformRole, status: platform.status } : null,
      tenantMemberships: memberships.map(m => ({ tenantId: m.tenantId, role: m.tenantRole, status: m.status,
        capabilities: m.status === "active" ? capabilitiesForTenantWorkforceRole(m.tenantRole) : [] })).sort((a,b) => a.tenantId.localeCompare(b.tenantId)),
      productAssociations: entitlements.map(e => ({ tenantId: e.tenantId, productId: e.productId, status: e.status }))
        .sort((a,b) => (a.tenantId+a.productId).localeCompare(b.tenantId+b.productId)),
      sessions: {
        total: sessions.length, activeAccess: sessions.filter(s => s.status === "active" && s.expiresAt > now).length,
        renewalEligible: sessions.filter(s => s.canRenew(this.clock) === "available").length,
        revoked: sessions.filter(s => s.status === "revoked").length,
        expiredAccess: sessions.filter(s => s.status !== "revoked" && s.expiresAt <= now).length,
        newestAuthenticationAt: sessions.length ? new Date(Math.max(...sessions.map(s => s.authenticatedAt.getTime()))).toISOString() : null,
      }, extras,
      externalProductDependencies: "unknown" as const,
    };
  }
  private async snapshot() {
    const [source, target] = await Promise.all([this.inventory(this.scope.source), this.inventory(this.scope.target)]);
    const blockers = ["EXTERNAL_PRODUCT_DEPENDENCIES_UNVERIFIED", "PRODUCTION_RECOVERY_DISABLED"];
    if (!this.appAvailable) blockers.push("REGISTERED_GOOGLE_FLOW_UNAVAILABLE");
    if (source.status !== "active" || target.status !== "active") blockers.push("IDENTITY_NOT_ACTIVE");
    if (source.authenticationMethods.length !== 1 || source.authenticationMethods[0]?.method !== "google" || source.authenticationMethods[0]?.status !== "active") blockers.push("SOURCE_NOT_GOOGLE_ONLY");
    if (source.platformMembership || source.tenantMemberships.length || source.productAssociations.length) blockers.push("SOURCE_AUTHORITY_OR_PRODUCT_ASSOCIATION");
    if (Object.values(source.extras).some(n => n !== 0)) blockers.push("SOURCE_OTHER_DEPENDENCIES");
    if (source.sessions.activeAccess || source.sessions.renewalEligible) blockers.push("SOURCE_SESSIONS_REQUIRE_SEPARATE_APPROVAL");
    if (!target.authenticationMethods.some(m => m.method === "apple" && m.status === "active") ||
        !target.authenticationMethods.some(m => m.method === "email_password" && m.status === "active")) blockers.push("PRIMARY_APPLE_OR_EMAIL_UNAVAILABLE");
    if (target.authenticationMethods.some(m => m.method === "google" && m.status === "active")) blockers.push("PRIMARY_GOOGLE_ALREADY_PRESENT");
    const digest = createHash("sha256").update(JSON.stringify({ source, target })).digest("hex");
    return { source, target, blockers, reviewDigest: digest };
  }
  private async audit(eventType: string, caseId: string | null, data: Record<string,string>) {
    await this.control.appendAudit({ id: randomUUID(), eventType,
      actorReference: `human:${this.scope.target}`, subjectReference: caseId ? `google-verification:${caseId}` : "google-verification",
      eventData: { ...this.scope, ...data }, occurredAt: this.clock.now() });
  }
  async administer(sessionId: SessionId, input: { mode: "inspect" | "prepare" | "cancel" | "approve"; caseId?: string }) {
    return this.atomically(async () => {
      await this.caller(sessionId, input.mode === "prepare");
      if (input.mode === "approve") throw new AppError("Account-changing recovery is disabled", "RECOVERY_DISABLED", 403);
      let observation = await this.store.latestForUpdate();
      const snapshot = await this.snapshot();
      if (input.mode === "prepare") {
        if (!this.appAvailable || snapshot.source.status !== "active" || snapshot.target.status !== "active" ||
            snapshot.blockers.includes("PRIMARY_APPLE_OR_EMAIL_UNAVAILABLE") || snapshot.blockers.includes("PRIMARY_GOOGLE_ALREADY_PRESENT"))
          throw new AppError("The reviewed identities are not available for verification", "RECOVERY_PRECONDITION_FAILED", 409);
        // Reuse an open case; never silently re-arm or overwrite a successful proof.
        if (!observation || observation.state === "cancelled") {
          observation = { id: randomUUID(), sourceHumanIdentityId: this.scope.source, targetHumanIdentityId: this.scope.target, appId: this.scope.appId, state: "awaiting_proof", createdAt: this.clock.now().toISOString(),
            expiresAt: new Date(this.clock.now().getTime()+900_000).toISOString(), observedAt: null, matched: null,
            relationshipId: null, reviewDigest: snapshot.reviewDigest };
          await this.store.save(observation);
        }
      } else if (input.mode === "cancel") {
        if (!observation || input.caseId !== observation.id) throw new AppError("Verification case is unavailable", "RECOVERY_CASE_INVALID", 409);
        observation = { ...observation, state: "cancelled" };
        await this.store.save(observation);
      }
      await this.audit(`platform.google-verification.${input.mode}`, observation?.id ?? null, { reviewDigest: snapshot.reviewDigest });
      const freshProof = observation?.observedAt !== null && observation?.observedAt !== undefined &&
        this.clock.now().getTime()-Date.parse(observation.observedAt) <= 300_000 && Date.parse(observation.expiresAt) > this.clock.now().getTime() && observation.state === "reviewed";
      const evidenceCurrent = observation?.reviewDigest === snapshot.reviewDigest;
      if (observation?.state === "reviewed" && !evidenceCurrent) snapshot.blockers.push("REVIEW_CHANGED_SINCE_PROOF");
      return { ...snapshot, observation, controlsVerified: !!freshProof && evidenceCurrent && observation?.matched === true && snapshot.source.status === "active",
        productionRecoveryEnabled: false as const, historicalConflictSubjectConfirmed: false as const };
    });
  }
  async observe(sessionId: SessionId, verified: VerifiedFederatedCredential): Promise<boolean> {
    if (verified.provider.value !== "google") return false;
    const session = await this.sessions.findById(sessionId);
    if (session?.humanIdentityId.value !== this.scope.target) return false;
    return this.atomically(async () => {
      const observation = await this.store.latestForUpdate();
      if (!observation || observation.state === "cancelled") return false;
      await this.caller(sessionId, true);
      if (Date.parse(observation.expiresAt) <= this.clock.now().getTime())
        throw new AppError("Cancel the expired verification and prepare a new case", "RECOVERY_CASE_EXPIRED", 409);
      if (verified.expiresAt <= this.clock.now()) throw new AppError("Google proof expired", "RECOVERY_PROOF_EXPIRED", 401);
      const snapshot = await this.snapshot();
      if (snapshot.blockers.includes("PRIMARY_APPLE_OR_EMAIL_UNAVAILABLE") || snapshot.blockers.includes("PRIMARY_GOOGLE_ALREADY_PRESENT"))
        throw new AppError("Primary authentication methods changed", "RECOVERY_PRECONDITION_FAILED", 409);
      const consumed = await this.nonces.consume(verified.provider, verified.nonceHash, verified.expiresAt, this.clock.now());
      if (!consumed) throw new AppError("Google proof was already used", "CREDENTIAL_REPLAYED", 401);
      await this.federated.lockProviderSubject(verified.provider, verified.providerSubject);
      const relationship = await this.federated.findByProviderSubject(verified.provider, verified.providerSubject);
      const matched = relationship?.humanIdentityId.value === this.scope.source && relationship.status === "active" && snapshot.source.status === "active";
      const next: ObservationCase = { ...observation, state: "reviewed", observedAt: this.clock.now().toISOString(),
        matched, relationshipId: matched ? relationship!.id.value : null, reviewDigest: snapshot.reviewDigest };
      await this.store.save(next);
      await this.audit("platform.google-verification.proof-observed", next.id, { matched: String(matched), reviewDigest: snapshot.reviewDigest });
      return true;
    });
  }
}
