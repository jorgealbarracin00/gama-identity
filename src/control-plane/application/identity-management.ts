import { continuityBlockers } from "./human-continuity.js";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { ControlPlane } from "./control-plane.js";
import type { Config } from "../../config/env.js";
import { AppError } from "../../shared/errors.js";
import type { Clock } from "../../shared/clock.js";
import type { PostgresDatabase } from "../../infrastructure/postgres/database.js";
import type { PostgresControlCentreRepository } from "../../infrastructure/postgres/postgres-control-centre-repository.js";
import type { AdministrationPrincipals } from "./administration-principals.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { SessionRepository } from "../../sessions/ports/session-repository.js";
import { SessionId } from "../../sessions/domain/session-id.js";
import type {
  FederatedIdentityRepository,
  FederatedAuthenticationNonceRepository,
} from "../../authentication/federated/ports/federated-identity-repository.js";
import { FederatedIdentityProvider } from "../../authentication/federated/domain/federated-identity.js";
import type { FederatedIdentityTokenVerifiers } from "../../authentication/federated/application/token-verifier.js";

export type Purpose = "production" | "test" | "unknown";
export type LifecycleAction = "suspend" | "reactivate" | "retire";
export const digest = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
function reject(code: string, message: string): never {
  throw new AppError(message, code, 409);
}
/** Not a production feature flag. Activation requires a separately reviewed implementation. */
export function syntheticManagementEnabled(
  config: Pick<Config, "NODE_ENV" | "DATABASE_URL" | "REPOSITORY_MODE">,
): boolean {
  try {
    const u = new URL(config.DATABASE_URL ?? "");
    return (
      config.NODE_ENV === "test" &&
      config.REPOSITORY_MODE === "postgres" &&
      ["postgres:", "postgresql:"].includes(u.protocol) &&
      // pg permits query host/port overrides. Reject all query options so this
      // test-only safety gate and the actual connection select the same target.
      u.search === "" && u.hash === "" &&
      ["127.0.0.1", "localhost"].includes(u.hostname) &&
      /^\/[a-z0-9_]+_management_test$/.test(u.pathname)
    );
  } catch {
    return false;
  }
}
export function activityClassification(last: string | null, now: Date) {
  // Session history has no completeness guarantee. Absence or an old observation proves neither inactivity nor abandonment.
  return last !== null &&
    Date.parse(last) <= now.getTime() &&
    Date.parse(last) >= now.getTime() - 30 * 86400000
    ? "recently_active"
    : "unknown";
}
export function potentialTestAlias(email: string | null): boolean {
  return /^jorgealbarracin\+[^@\s]+@gmail\.com$/i.test(email ?? "");
}
interface RecoveryCase {
  id: string;
  actor_human_identity_id: string;
  source_human_identity_id: string;
  target_human_identity_id: string;
  provider: string;
  nonce: string;
  relationship_id: string | null;
  state: string;
  transfer_policy?: "verified_empty_source" | "retain_records";
  created_at: Date;
  expires_at: Date;
  proof_expires_at: Date | null;
  review_digest: string | null;
}

export class IdentityManagement {
  constructor(
    private readonly db: PostgresDatabase,
    private readonly centre: PostgresControlCentreRepository,
    private readonly principals: AdministrationPrincipals,
    private readonly plane: ControlPlaneRepository,
    private readonly humans: HumanIdentityRepository,
    private readonly sessions: SessionRepository,
    private readonly federated: FederatedIdentityRepository,
    private readonly nonces: FederatedAuthenticationNonceRepository,
    private readonly verifiers: FederatedIdentityTokenVerifiers,
    private readonly clock: Clock,
    readonly executionEnabled: boolean,
    private readonly controlPlane: ControlPlane,
    private readonly requiredProducts: readonly string[] = [],
    readonly administrationEnabled = false,
    readonly recoveryEnabled = false,
  ) {}
  private gate() {
    if (!this.executionEnabled)
      throw new AppError(
        "Account changes remain disabled in this release",
        "IDENTITY_MANAGEMENT_DISABLED",
        403,
      );
  }
  private gateRecovery() { if (!this.recoveryEnabled) this.gate(); }
  private gateAdministrative() {
    if (!this.administrationEnabled) this.gate();
  }
  private async owner(token: SessionId, fresh = false) {
    const s = await this.sessions.findById(token);
    const now = this.clock.now();
    if (
      !s ||
      s.status !== "active" ||
      s.expiresAt <= now ||
      (await this.humans.findById(s.humanIdentityId))?.status !== "active"
    )
      throw new AppError("Sign in to continue", "SESSION_INVALID", 401);
    if (
      fresh &&
      (now.getTime() - s.authenticatedAt.getTime() < 0 ||
        now.getTime() - s.authenticatedAt.getTime() > 300000)
    )
      throw new AppError(
        "Fresh sign-in is required",
        "REAUTHENTICATION_REQUIRED",
        403,
      );
    return s;
  }
  private async admin(token: SessionId, fresh = false) {
    const s = await this.owner(token, fresh);
    return this.principals.platform(s.humanIdentityId.value);
  }
  private async audit(
    actor: string,
    type: string,
    subject: string,
    data: Record<string, string> = {},
  ) {
    await this.plane.appendAudit({
      id: randomUUID(),
      eventType: type,
      actorReference: `human-identity:${actor}`,
      subjectReference: subject,
      eventData: data,
      occurredAt: this.clock.now(),
    });
  }
  private async metadata(id: string) {
    const human = await this.centre.human(id);
    if (!human) throw new AppError("Human not found", "HUMAN_NOT_FOUND", 404);
    const r = await this.db.query<{
      purpose: Purpose;
      reason: string;
      revision: number;
      actor_human_identity_id: string;
      updated_at: Date;
    }>(
      "SELECT purpose,reason,revision,actor_human_identity_id,updated_at FROM human_purposes WHERE human_identity_id=$1",
      [id],
    );
    return {
      human,
      purpose: r.rows[0]?.purpose ?? "unknown",
      classificationReason: r.rows[0]?.reason ?? null,
      classificationRevision: r.rows[0]?.revision ?? 0,
      classifiedBy: r.rows[0]?.actor_human_identity_id ?? null,
      classifiedAt: r.rows[0]?.updated_at.toISOString() ?? null,
      activity: activityClassification(human.lastActivityAt, this.clock.now()),
      lifecycle: human.status,
      potentialTestCandidate: human.authenticationMethods.some((m) =>
        potentialTestAlias(m.email),
      ),
    };
  }
  private async assess(id: string, ignoreCase: string | null = null) {
    const m = await this.metadata(id),
      counts = await this.centre.dependencyCounts(id, this.clock.now());
    const reports = await this.db.query<{
      productId: string;
      state: string;
      counts: Record<string, number> | null;
      observedAt: string | null;
    }>(
      `WITH products AS (SELECT id FROM registered_products UNION SELECT unnest($3::text[]) AS id) SELECT p.id AS "productId", CASE WHEN i.product_id IS NULL THEN 'not_supported' WHEN r.human_identity_id IS NULL OR r.inspector_revision<>i.revision OR r.expires_at<=$2 OR r.observed_at>$2 THEN 'not_verified' ELSE 'verified' END AS state,r.counts,r.observed_at::text AS "observedAt" FROM products p LEFT JOIN product_dependency_inspectors i ON i.product_id=p.id LEFT JOIN product_dependency_reports r ON r.product_id=p.id AND r.human_identity_id=$1 ORDER BY p.id`,
      [id, this.clock.now(), this.requiredProducts],
    );
    // No product registry is also incomplete coverage, not evidence of an empty platform.
    const unknown =
      reports.rows.length === 0 ||
      reports.rows.some((r) => r.state !== "verified");
    const externalPresent = reports.rows.some(
      (r) =>
        r.state === "verified" &&
        Object.values(r.counts ?? {}).some((n) => n > 0),
    );
    const protectedIdentity =
      m.human.platformRole !== null ||
      m.human.memberships.some((x) => x.role === "owner") ||
      reports.rows.some(
        (r) =>
          r.state === "verified" &&
          ((r.counts?.ownership ?? 0) > 0 || (r.counts?.retention ?? 0) > 0),
      );
    const pending = await this.db.query<{ count: number }>(
      `SELECT ((SELECT count(*) FROM identity_management_cases WHERE (source_human_identity_id=$1 OR target_human_identity_id=$1) AND state IN ('awaiting_proof','verified') AND expires_at>$2 AND ($3::uuid IS NULL OR id<>$3))+(SELECT count(*) FROM identity_recovery_requests WHERE (source_human_identity_id=$1 OR target_human_identity_id=$1) AND state='review_required')+(SELECT count(*) FROM identity_recovery_compensations c JOIN identity_management_operations o ON o.id=c.original_request_id WHERE (o.result->>'sourceHumanIdentityId'=$1 OR o.result->>'targetHumanIdentityId'=$1) AND c.state IN ('awaiting_proof','verified') AND c.expires_at>$2 AND ($3::uuid IS NULL OR c.id<>$3)))::int AS count`,
      [id, this.clock.now(), ignoreCase],
    );
    const pendingRecoveryReferences = pending.rows[0]!.count;
    const relationshipsPresent =
      pendingRecoveryReferences > 0 ||
      m.human.memberships.length > 0 ||
      m.human.products.length > 0 ||
      counts.provisioningReferences > 0 ||
      counts.emailChallenges > 0 ||
      counts.appleRevocationReferences > 0 ||
      externalPresent;
    const sessionRows = await this.db.query<{
      reference: string;
      status: string;
      authenticatedAt: string;
      expiresAt: string;
      renewable: boolean;
    }>(
      `SELECT left(md5(id),12) AS reference,status,authenticated_at::text AS "authenticatedAt",expires_at::text AS "expiresAt",(status<>'revoked' AND renewal_expires_at>$2 AND renewal_token_hash IS NOT NULL) AS renewable FROM sessions WHERE human_identity_id=$1 ORDER BY created_at,id LIMIT 100`,
      [id, this.clock.now()],
    );
    // Read-only opaque references are not bearer/session IDs. Count covers all sessions even when display is bounded.
    const nonRevoked = await this.db.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM sessions WHERE human_identity_id=$1 AND status<>'revoked'",
      [id],
    );
    const localCounts = (await this.db.query<{credentials:number; providers:number; roles:number; memberships:number; owners:number; participation:number; entitlements:number}>(
      `SELECT (SELECT count(*) FROM credentials WHERE human_identity_id=$1)::int credentials,
       (SELECT count(*) FROM federated_identities WHERE human_identity_id=$1)::int providers,
       (SELECT count(*) FROM platform_administration_memberships WHERE human_identity_id=$1)::int roles,
       (SELECT count(*) FROM tenant_memberships WHERE human_identity_id=$1)::int memberships,
       (SELECT count(*) FROM tenant_memberships WHERE human_identity_id=$1 AND tenant_role='owner')::int owners,
       (SELECT count(*) FROM human_product_participations WHERE human_identity_id=$1)::int participation,
       (SELECT count(*) FROM product_entitlements WHERE human_identity_id=$1)::int entitlements`, [id]
    )).rows[0]!;
    const central = (key:string, count:number) => ({category:key, status:count>0?'dependencies_present':'verified_clear', count, authority:'gama_identity'});
    const external = (key:string, reportKey:string) => ({category:key,
      status:unknown?'unknown':reports.rows.some(r=>(r.counts?.[reportKey]??0)>0)?'dependencies_present':'verified_clear',
      count:unknown?null:reports.rows.reduce((n,r)=>n+(r.counts?.[reportKey]??0),0), authority:'authenticated_product_inspectors'});
    const categories = [central('credentials',localCounts.credentials),central('authentication_providers',localCounts.providers),
      central('active_sessions',counts.activeSessions),central('renewable_sessions',counts.renewableSessions),
      central('platform_roles',localCounts.roles),central('business_ownership',localCounts.owners),central('business_memberships',localCounts.memberships),
      central('product_participation',localCounts.participation),central('product_entitlements',localCounts.entitlements),
      central('pending_recovery',pendingRecoveryReferences),central('identity_challenges',counts.emailChallenges+counts.appleRevocationReferences),
      central('provisioning_operations',counts.provisioningReferences),external('subscriptions','subscriptions'),external('product_local_data','localAccounts'),
      external('product_permissions','permissions'),external('product_ownership','ownership'),external('background_jobs','backgroundJobs'),
      external('pending_product_operations','pendingOperations'),external('other_product_references','externalReferences'),external('retention_obligations','retention')];
    const result = {
      ...m,
      counts,
      categories,
      protectedStatus: protectedIdentity ? 'blocked' : 'verified_clear',
      nonRevokedSessionCount: nonRevoked.rows[0]!.count,
      sessions: sessionRows.rows,
      sessionDisplayTruncated: counts.totalSessions > 100,
      products: reports.rows,
      unknownCoverage: unknown,
      protectedIdentity,
      relationshipsPresent,
      pendingRecoveryReferences,
      outcome: protectedIdentity
        ? "protected_identity"
        : unknown
          ? "assessment_incomplete"
          : relationshipsPresent ||
              counts.activeSessions > 0 ||
              counts.renewableSessions > 0
            ? "dependencies_present"
            : "no_blocking_dependencies_found",
      deletionAuthorization: false,
      activityCoverage: "incomplete_session_history",
      pendingAndExternalReferences:
        counts.emailChallenges +
        counts.appleRevocationReferences +
        counts.provisioningReferences,
    };
    return {
      ...result,
      reviewDigest: digest({
        ...result,
        sessions: sessionRows.rows.map((s) => ({
          reference: s.reference,
          status: s.status,
          authenticatedAt: s.authenticatedAt,
          expiresAt: s.expiresAt,
          renewable: s.renewable,
        })),
      }),
    };
  }
  async inspect(token: SessionId, id: string) {
    return this.db.withTransaction(async () => {
      const a = await this.admin(token);
      const assessment = await this.assess(id);
      const deleted = this.administrationEnabled && (await this.db.query("SELECT 1 FROM identity_management_operations WHERE kind='human.delete' AND result->>'humanIdentityId'=$1 LIMIT 1",[id])).rows.length>0;
      await this.audit(a.humanIdentityId, "human.management.inspected", id);
      return {
        ...assessment,
        executionEnabled: (this.executionEnabled || this.administrationEnabled) && !deleted,
        permanentDeletionEnabled: false,
      };
    });
  }
  async classify(
    token: SessionId,
    input: {
      humanIdentityId: string;
      purpose: Purpose;
      reason: string;
      expectedRevision: number;
      requestId: string;
    },
  ) {
    await this.admin(token, true);
    this.gateAdministrative();
    return this.db.withIdentityManagementTransaction(async () => {
      const a = await this.admin(token, true);
      const intent = digest(input);
      const previous = await this.previous(
        input.requestId,
        a.humanIdentityId,
        "classify",
        intent,
      );
      if (previous) return previous;
      const m = await this.metadata(input.humanIdentityId);
      if (this.administrationEnabled && (await this.db.query("SELECT 1 FROM identity_management_operations WHERE kind='human.delete' AND result->>'humanIdentityId'=$1 LIMIT 1",[input.humanIdentityId])).rows.length) reject("HUMAN_DEIDENTIFIED","Deleted accounts cannot be reclassified");
      if (m.classificationRevision !== input.expectedRevision)
        reject(
          "CLASSIFICATION_CONFLICT",
          "Classification changed. Reload before saving.",
        );
      await this.db.query(
        `INSERT INTO human_purposes(human_identity_id,purpose,reason,actor_human_identity_id,revision,updated_at) VALUES($1,$2,$3,$4,1,$5) ON CONFLICT(human_identity_id) DO UPDATE SET purpose=EXCLUDED.purpose,reason=EXCLUDED.reason,actor_human_identity_id=EXCLUDED.actor_human_identity_id,revision=human_purposes.revision+1,updated_at=EXCLUDED.updated_at`,
        [
          input.humanIdentityId,
          input.purpose,
          input.reason,
          a.humanIdentityId,
          this.clock.now(),
        ],
      );
      const result = {
        humanIdentityId: input.humanIdentityId,
        purpose: input.purpose,
        revision: input.expectedRevision + 1,
      };
      await this.audit(
        a.humanIdentityId,
        "human.purpose.changed",
        input.humanIdentityId,
        { purpose: input.purpose, reason: input.reason },
      );
      await this.record(
        input.requestId,
        a.humanIdentityId,
        "classify",
        intent,
        result,
      );
      return result;
    });
  }
  private async previous(
    id: string,
    actor: string,
    kind: string,
    intent: string,
  ) {
    const r = await this.db.query<{
      actor_human_identity_id: string;
      kind: string;
      intent_digest: string;
      result: Record<string, unknown>;
    }>(
      "SELECT actor_human_identity_id,kind,intent_digest,result FROM identity_management_operations WHERE id=$1",
      [id],
    );
    const x = r.rows[0];
    if (!x) return null;
    if (
      x.actor_human_identity_id !== actor ||
      x.kind !== kind ||
      x.intent_digest !== intent
    )
      reject(
        "IDEMPOTENCY_CONFLICT",
        "Request identifier is already bound to a different operation.",
      );
    return x.result;
  }
  private async record(
    id: string,
    actor: string,
    kind: string,
    intent: string,
    result: unknown,
  ) {
    await this.db.query(
      "INSERT INTO identity_management_operations(id,actor_human_identity_id,kind,intent_digest,result,created_at) VALUES($1,$2,$3,$4,$5,$6)",
      [id, actor, kind, intent, result, this.clock.now()],
    );
  }
  private async lifecycleEligibility(id: string, action: LifecycleAction) {
    const assessment = await this.assess(id);
    const blockers: string[] = [];
    if (this.administrationEnabled) {
      if (action !== "reactivate") blockers.push(...await continuityBlockers(this.db,id));
    } else {
    if (assessment.protectedIdentity) blockers.push("PROTECTED_IDENTITY");
    if (assessment.unknownCoverage) blockers.push("DEPENDENCIES_NOT_VERIFIED");
    if (assessment.relationshipsPresent)
      blockers.push("RELATIONSHIPS_REQUIRE_REVIEW");
    if (assessment.purpose !== "test")
      blockers.push("OWNER_CONSENT_REQUIRED_OR_CONFIRMED_TEST");
    }
    if (action === "reactivate" && assessment.lifecycle !== "suspended")
      blockers.push("NOT_SUSPENDED");
    if (action !== "reactivate" && assessment.lifecycle === "retired")
      blockers.push("RETIRED_IS_TERMINAL");
    return {
      assessment,
      action,
      blockers,
      eligible: blockers.length === 0,
      affectedSessionCount:
        action === "reactivate" ? 0 : assessment.nonRevokedSessionCount,
      sessionPolicy:
        action === "reactivate"
          ? "No old session is restored; fresh sign-in required"
          : "Revoke every non-revoked session belonging only to this Human",
      retirementPolicy:
        "Retirement retains all records and is terminal under the existing Human domain policy",
      executionEnabled: this.executionEnabled || this.administrationEnabled,
    };
  }
  async previewLifecycle(
    token: SessionId,
    ids: string[],
    action: LifecycleAction,
  ) {
    return this.db.withTransaction(async () => {
      const a = await this.admin(token);
      const accounts = await Promise.all(
        ids.map((id) => this.lifecycleEligibility(id, action)),
      );
      await this.audit(a.humanIdentityId, "human.lifecycle.previewed", "bulk", {
        count: String(ids.length),
        action,
      });
      return {
        accounts,
        executionEnabled: this.executionEnabled || this.administrationEnabled,
        permanentDeletionEnabled: false,
      };
    });
  }
  async lifecycle(
    token: SessionId,
    input: {
      humanIdentityId: string;
      action: LifecycleAction;
      reviewDigest: string;
      requestId: string;
      confirmation: string;
      revokeSessions: boolean;
    },
  ) {
    await this.admin(token, true);
    this.gateAdministrative();
    return this.db.withIdentityManagementTransaction(async () => {
      const a = await this.admin(token, true),
        intent = digest(input);
      const prev = await this.previous(
        input.requestId,
        a.humanIdentityId,
        "lifecycle",
        intent,
      );
      if (prev) return prev;
      const p = await this.lifecycleEligibility(
        input.humanIdentityId,
        input.action,
      );
      if (!p.eligible) reject("LIFECYCLE_BLOCKED", p.blockers.join(", "));
      if (p.assessment.reviewDigest !== input.reviewDigest)
        reject("REVIEW_CHANGED", "Evidence changed. Refresh the preview.");
      if (
        input.confirmation !== `${input.action} ${input.humanIdentityId}` ||
        (input.action !== "reactivate" && !input.revokeSessions)
      )
        reject(
          "CONFIRMATION_REQUIRED",
          "Confirm the exact Human and session impact.",
        );
      const h = (await this.humans.findById(
        HumanIdentityId.from(input.humanIdentityId),
      ))!;
      if (input.action === "suspend") h.suspend(this.clock);
      else if (input.action === "reactivate") h.reactivate(this.clock);
      else h.retire(this.clock);
      await this.humans.save(h);
      if (input.action !== "reactivate")
        await this.sessions.revokeByHumanIdentityId(h.id);
      const result = {
        humanIdentityId: h.id.value,
        status: h.status,
        requestId: input.requestId,
      };
      await this.audit(
        a.humanIdentityId,
        `human.${input.action}.completed`,
        h.id.value,
        { requestId: input.requestId, sessionPolicy: p.sessionPolicy },
      );
      await this.record(
        input.requestId,
        a.humanIdentityId,
        "lifecycle",
        intent,
        result,
      );
      return result;
    });
  }
  async bulk(
    token: SessionId,
    items: Parameters<IdentityManagement["lifecycle"]>[1][],
    confirmation: string,
  ) {
    this.gateAdministrative();
    await this.admin(token, true);
    if (confirmation !== `review ${items.length} identities`)
      reject("CONFIRMATION_REQUIRED", "Confirm the selected count.");
    const results = [];
    for (const item of items) {
      try {
        results.push({
          humanIdentityId: item.humanIdentityId,
          state: "completed",
          result: await this.lifecycle(token, item),
        });
      } catch (error) {
        results.push({
          humanIdentityId: item.humanIdentityId,
          state: "blocked",
          code: error instanceof AppError ? error.code : "OPERATION_FAILED",
        });
      }
    }
    return { results };
  }
  async registerInspector(
    token: SessionId,
    productId: string,
    workloadId: string,
  ) {
    await this.admin(token, true);
    this.gateAdministrative();
    return this.db.withIdentityManagementTransaction(async () => {
      const a = await this.admin(token, true);
      const w = await this.plane.findWorkload(workloadId);
      if (!w || w.productId !== productId || w.status !== "active")
        reject(
          "INSPECTOR_INVALID",
          "An active workload belonging to this product is required.",
        );
      await this.db.query(
        "INSERT INTO product_dependency_inspectors(product_id,workload_id,coverage,revision) VALUES($1,$2,'complete',1) ON CONFLICT(product_id) DO UPDATE SET workload_id=EXCLUDED.workload_id,revision=product_dependency_inspectors.revision+1",
        [productId, workloadId],
      );
      await this.audit(
        a.humanIdentityId,
        "dependency.inspector.registered",
        productId,
        { workloadId },
      );
      return { productId, workloadId };
    });
  }
  async reportDependencies(
    workloadId: string,
    secret: string,
    input: {
      humanIdentityId: string;
      counts: Record<string, number>;
      evidenceReference: string;
      observedAt: string;
    },
  ) {
    this.gateAdministrative();
    return this.db.withTransaction(async () => {
      const w = await this.controlPlane.authenticateWorkload(
        workloadId,
        secret,
        "identity.dependencies.report",
      );
      if (!w)
        throw new AppError(
          "Product authorization is required",
          "WORKLOAD_INVALID",
          401,
        );
      const r = await this.db.query<{ revision: number; workload_id: string }>(
        "SELECT revision,workload_id FROM product_dependency_inspectors WHERE product_id=$1",
        [w.productId],
      );
      const inspector = r.rows[0];
      if (!inspector || inspector.workload_id !== workloadId)
        throw new AppError(
          "This workload has no dependency inspection authority",
          "INSPECTOR_NOT_AUTHORIZED",
          403,
        );
      await this.metadata(input.humanIdentityId);
      const now = this.clock.now(),
        observed = new Date(input.observedAt);
      if (
        !Number.isFinite(observed.getTime()) ||
        observed > now ||
        observed.getTime() < now.getTime() - 60000
      )
        reject("EVIDENCE_STALE", "Report a current product snapshot.");
      const saved = await this.db.query(
        "INSERT INTO product_dependency_reports(product_id,human_identity_id,inspector_revision,counts,evidence_reference,observed_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(product_id,human_identity_id) DO UPDATE SET inspector_revision=EXCLUDED.inspector_revision,counts=EXCLUDED.counts,evidence_reference=EXCLUDED.evidence_reference,observed_at=EXCLUDED.observed_at,expires_at=EXCLUDED.expires_at WHERE product_dependency_reports.observed_at<=EXCLUDED.observed_at",
        [
          w.productId,
          input.humanIdentityId,
          inspector.revision,
          input.counts,
          input.evidenceReference,
          observed,
          new Date(observed.getTime() + 60000),
        ],
      );
      if (saved.rowCount !== 1)
        reject("EVIDENCE_STALE", "A newer report exists.");
      await this.plane.appendAudit({
        id: randomUUID(),
        eventType: "dependency.report.received",
        actorReference: `product-workload:${workloadId}`,
        subjectReference: input.humanIdentityId,
        productId: w.productId,
        eventData: {
          coverage: "complete",
          evidenceReference: input.evidenceReference,
        },
        occurredAt: now,
      });
      return { recorded: true };
    });
  }
  async prepareRecovery(token: SessionId, source: string, target: string, transferPolicy: "verified_empty_source" | "retain_records" = "verified_empty_source") {
    await this.admin(token, true);
    this.gateRecovery();
    return this.db.withIdentityManagementTransaction(async () => {
      const a = await this.admin(token, true);
      if (source === target)
        reject("PAIR_INVALID", "Select two different Humans.");
      await this.metadata(source);
      await this.metadata(target);
      const id = randomUUID(),
        nonce = randomBytes(32).toString("base64url"),
        now = this.clock.now();
      const superseded = await this.db.query<{ id: string }>(
        "UPDATE identity_management_cases SET state='cancelled' WHERE actor_human_identity_id=$1 AND source_human_identity_id=$2 AND target_human_identity_id=$3 AND provider='google' AND state IN ('awaiting_proof','verified') RETURNING id",
        [a.humanIdentityId, source, target],
      );
      await this.auditSupersededCases(a.humanIdentityId, "recovery", superseded.rows, id);
      await this.db.query(
        `INSERT INTO identity_management_cases(id,actor_human_identity_id,source_human_identity_id,target_human_identity_id,provider,nonce,state,created_at,expires_at,transfer_policy) VALUES($1,$2,$3,$4,'google',$5,'awaiting_proof',$6,$7,$8)`,
        [
          id,
          a.humanIdentityId,
          source,
          target,
          nonce,
          now,
          new Date(now.getTime() + 900000),
          transferPolicy,
        ],
      );
      await this.audit(a.humanIdentityId, "recovery.control.requested", id, {
        source,
        target,
      });
      return {
        caseId: id,
        nonce,
        provider: "google",
        expiresAt: new Date(now.getTime() + 900000).toISOString(),
        nextAction:
          "Freshly sign in to both Humans through supported authentication, then verify Google with this nonce.",
      };
    });
  }
  private async case(id: string, actor: string) {
    const r = await this.db.query<RecoveryCase>(
      "SELECT * FROM identity_management_cases WHERE id=$1 FOR UPDATE",
      [id],
    );
    const c = r.rows[0];
    if (!c || c.actor_human_identity_id !== actor)
      throw new AppError("Recovery case not found", "RECOVERY_NOT_FOUND", 404);
    return c;
  }
  async authorizeOwnerAuthentication(token: SessionId, caseId?: string, kind: "recovery" | "compensation" = "recovery"): Promise<string> {
    const actor = await this.admin(token);
    this.gateRecovery();
    if (!caseId) return actor.humanIdentityId;
    const now = this.clock.now();
    if (kind === "compensation") {
      const c = await this.compensation(caseId, actor.humanIdentityId);
      if (c.state !== "awaiting_proof" || c.expires_at <= now)
        reject("CONTROL_INVALID", "Start a new compensation verification before authenticating its primary.");
      return (await this.transferReceipt(c.original_request_id, actor.humanIdentityId)).targetHumanIdentityId;
    }
    const c = await this.case(caseId, actor.humanIdentityId);
    if (c.state !== "awaiting_proof" || c.expires_at <= now)
      reject("CONTROL_INVALID", "Start a new recovery verification before authenticating its primary.");
    return c.target_human_identity_id;
  }
  async authenticateExistingOwnerApple<T>(token: SessionId, input: {caseId?: string; kind?: "recovery" | "compensation"}, work: (expectedHumanIdentityId: string) => Promise<T>): Promise<T> {
    await this.admin(token); this.gateRecovery();
    return this.db.withIdentityManagementTransaction(async () => {
      const actor = await this.admin(token);
      const expected = await this.authorizeOwnerAuthentication(token, input.caseId, input.kind);
      const result = await work(expected);
      await this.audit(actor.humanIdentityId, "recovery.owner.apple.authenticated", input.caseId ?? expected, {
        ownerHumanIdentityId: expected,
        scope: input.caseId ? input.kind ?? "recovery" : "administrator_step_up",
      });
      return result;
    });
  }
  private async auditSupersededCases(actor: string, kind: "recovery" | "compensation", cases: readonly { id: string }[], replacementId: string) {
    for (const previous of cases) {
      const handoffs = await this.db.query(
        "UPDATE identity_management_google_handoffs SET state='cancelled',code_verifier=NULL WHERE case_id=$1 AND case_kind=$2 AND actor_id=$3 AND state IN ('awaiting_callback','processing','verified') RETURNING id",
        [previous.id, kind, actor],
      );
      await this.audit(actor, kind === "recovery" ? "recovery.control.superseded" : "recovery.compensation.superseded", previous.id, {
        replacementCaseId: replacementId,
        cancelledHandoffCount: String(handoffs.rowCount ?? 0),
        history: "retained",
      });
    }
  }
  async proveRecovery(
    token: SessionId,
    input: {
      caseId: string;
      sourceSession: string;
      targetSession: string;
      identityToken: string;
    },
  ) {
    await this.admin(token, true);
    this.gateRecovery();
    // Verify using configured issuer, signature and audience policy. Never accept caller-supplied subject or "verified" boolean.
    const actor = await this.admin(token, true);
    const loaded = await this.db.withTransaction(() =>
      this.case(input.caseId, actor.humanIdentityId),
    );
    let verified;
    try {
      verified = await this.verifiers.verify(
        FederatedIdentityProvider.from("google"),
        { identityToken: input.identityToken, nonce: loaded.nonce },
      );
    } catch {
      throw new AppError(
        "Google ownership could not be verified",
        "OWNERSHIP_INVALID",
        403,
      );
    }
    return this.db.withIdentityManagementTransaction(async () => {
      const a = await this.admin(token, true),
        c = await this.case(input.caseId, a.humanIdentityId),
        now = this.clock.now();
      if (
        c.state !== "awaiting_proof" ||
        c.expires_at <= now ||
        verified.expiresAt <= now
      )
        reject("PROOF_EXPIRED_OR_USED", "Start a new recovery verification.");
      const source = await this.owner(
          SessionId.from(input.sourceSession),
          true,
        ),
        target = await this.owner(SessionId.from(input.targetSession), true);
      if (
        source.humanIdentityId.value !== c.source_human_identity_id ||
        target.humanIdentityId.value !== c.target_human_identity_id ||
        source.authenticatedAt < c.created_at ||
        target.authenticatedAt < c.created_at
      )
        reject(
          "CONTROL_INVALID",
          "Fresh sign-in to each selected Human after preparation is required.",
        );
      await this.federated.lockProviderSubject(
        verified.provider,
        verified.providerSubject,
      );
      const relationship = await this.federated.findByProviderSubject(
        verified.provider,
        verified.providerSubject,
      );
      if (
        !relationship ||
        relationship.status !== "active" ||
        relationship.humanIdentityId.value !== c.source_human_identity_id
      )
        reject(
          "SUBJECT_CONFLICT",
          "The verified Google account does not belong to the selected source.",
        );
      if (
        !(await this.nonces.consume(
          verified.provider,
          verified.nonceHash,
          verified.expiresAt,
          now,
        ))
      )
        reject("PROOF_REPLAY", "Use a fresh Google verification.");
      const until = new Date(
        Math.min(
          now.getTime() + 300000,
          verified.expiresAt.getTime(),
          c.expires_at.getTime(),
        ),
      );
      for (const s of [source, target]) {
        const r = await this.db.query(
          "INSERT INTO identity_management_control_proofs(session_hash,case_id,human_identity_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
          [digest(s.id.value), c.id, s.humanIdentityId.value, until],
        );
        if (r.rowCount !== 1)
          reject(
            "CONTROL_REPLAY",
            "Fresh account-control proof is required for this case.",
          );
      }
      await this.db.query(
        "UPDATE identity_management_cases SET state='verified',relationship_id=$2,proof_expires_at=$3 WHERE id=$1",
        [c.id, relationship.id.value, until],
      );
      await this.audit(a.humanIdentityId, "recovery.control.verified", c.id, {
        source: c.source_human_identity_id,
        target: c.target_human_identity_id,
        provider: "google",
        subjectMatch: "true",
      });
      return {
        caseId: c.id,
        controlVerified: true,
        providerSubjectMatched: true,
        expiresAt: until.toISOString(),
      };
    });
  }
  /** Recheck a claimed browser handoff inside the same exclusive proof transaction after network verification. */
  private async assertCurrentHandoff(id:string,caseId:string,actor:string,target:string,kind:'recovery'|'compensation') {
    const current=await this.db.query("SELECT 1 FROM identity_management_google_handoffs WHERE id=$1 AND case_id=$2 AND actor_id=$3 AND target_id=$4 AND case_kind=$5 AND state='processing' AND expires_at>$6 FOR UPDATE",[id,caseId,actor,target,kind,this.clock.now()]);
    if (!current.rows.length) reject('HANDOFF_EXPIRED_OR_USED','Start a new browser verification.');
  }
  /** Fresh Google OIDC proof controls the exact existing source; no source session or Human is created. */
  async proveNativeRecovery(token: SessionId, input: {caseId:string; targetSession:string; identityToken:string}, handoffId?: string) {
    await this.admin(token, true); this.gateRecovery();
    const actor = await this.admin(token, true);
    const loaded = await this.db.withTransaction(()=>this.case(input.caseId,actor.humanIdentityId));
    let verified;
    try { verified = await this.verifiers.verify(FederatedIdentityProvider.from('google'),{identityToken:input.identityToken,nonce:loaded.nonce}); }
    catch { throw new AppError('Google ownership could not be verified','OWNERSHIP_INVALID',403); }
    return this.db.withIdentityManagementTransaction(async()=>{
      const a=await this.admin(token,true), c=await this.case(input.caseId,a.humanIdentityId), now=this.clock.now();
      if(c.state!=='awaiting_proof'||c.expires_at<=now||verified.expiresAt<=now) reject('PROOF_EXPIRED_OR_USED','Start a new recovery verification.');
      if (handoffId) await this.assertCurrentHandoff(handoffId,c.id,a.humanIdentityId,c.target_human_identity_id,'recovery');
      const target=await this.owner(SessionId.from(input.targetSession),true);
      if(!['email_password','apple'].includes(target.authenticationMethod ?? 'unknown')) reject('PRIMARY_METHOD_REQUIRED','Fresh Apple or Email sign-in to the primary is required.');
      if(target.humanIdentityId.value!==c.target_human_identity_id||target.authenticatedAt<c.created_at) reject('CONTROL_INVALID','Fresh sign-in to the selected primary after preparation is required.');
      await this.federated.lockProviderSubject(verified.provider,verified.providerSubject);
      const relationship=await this.federated.findByProviderSubject(verified.provider,verified.providerSubject);
      if(!relationship||relationship.status!=='active'||relationship.humanIdentityId.value!==c.source_human_identity_id) reject('SUBJECT_CONFLICT','The verified Google account does not belong to the selected source.');
      if((await this.humans.findById(relationship.humanIdentityId))?.status!=='active') reject('HUMAN_NOT_ACTIVE','The selected source is not active.');
      if(!await this.nonces.consume(verified.provider,verified.nonceHash,verified.expiresAt,now)) reject('PROOF_REPLAY','Use a fresh Google verification.');
      const until=new Date(Math.min(now.getTime()+300000,verified.expiresAt.getTime(),c.expires_at.getTime()));
      for(const proof of [{hash:digest(target.id.value),human:c.target_human_identity_id,kind:'session'},
        {hash:digest({caseId:c.id,nonceHash:verified.nonceHash,relationshipId:relationship.id.value}),human:c.source_human_identity_id,kind:'provider'}]) {
        const r=await this.db.query('INSERT INTO identity_management_control_proofs(session_hash,case_id,human_identity_id,expires_at,proof_kind) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[proof.hash,c.id,proof.human,until,proof.kind]);
        if(r.rowCount!==1) reject('CONTROL_REPLAY','Fresh account-control proof is required for this case.');
      }
      await this.db.query("UPDATE identity_management_cases SET state='verified',relationship_id=$2,proof_expires_at=$3 WHERE id=$1",[c.id,relationship.id.value,until]);
      await this.audit(a.humanIdentityId,'recovery.control.verified',c.id,{source:c.source_human_identity_id,target:c.target_human_identity_id,provider:'google',subjectMatch:'true',sourceControl:'fresh_provider_proof'});
      return {caseId:c.id,controlVerified:true,providerSubjectMatched:true,expiresAt:until.toISOString()};
    });
  }
  private async recoveryPreview(c: RecoveryCase) {
    const now = this.clock.now();
    const source = await this.assess(c.source_human_identity_id, c.id),
      target = await this.assess(c.target_human_identity_id, c.id),
      blockers: string[] = [];
    if (
      c.state !== "verified" ||
      !c.proof_expires_at ||
      c.proof_expires_at <= now ||
      c.expires_at <= now
    )
      blockers.push("FRESH_CONTROL_REQUIRED");
    // A saved verification does not outlive the exact owner-control evidence.
    // Keep Preview aligned with execution so revoked/expired sessions never appear ready.
    if (c.state === "verified") {
      const relationship = await this.federated.findActiveByHumanIdentityAndProvider(
        HumanIdentityId.from(c.source_human_identity_id), FederatedIdentityProvider.from("google"),
      );
      if (!relationship || relationship.id.value !== c.relationship_id)
        blockers.push("RELATIONSHIP_CHANGED");
      const proofs = await this.db.query<{
        human_identity_id: string;
        session_hash: string;
        proof_kind: string;
        expires_at: Date;
      }>(
        "SELECT human_identity_id,session_hash,proof_kind,expires_at FROM identity_management_control_proofs WHERE case_id=$1",
        [c.id],
      );
      for (const id of [c.source_human_identity_id, c.target_human_identity_id]) {
        const proof = proofs.rows.find((p) => p.human_identity_id === id);
        if (!proof || proof.expires_at <= now) {
          if (!blockers.includes("CONTROL_EXPIRED")) blockers.push("CONTROL_EXPIRED");
          continue;
        }
        if (proof.proof_kind === "provider") {
          if (id !== c.source_human_identity_id || !c.relationship_id) {
            blockers.push("CONTROL_INVALID");
            continue;
          }
          continue;
        }
        if (proof.proof_kind !== "session") {
          blockers.push("CONTROL_INVALID");
          continue;
        }
        const ownerSessions = await this.sessions.listByHumanIdentityId(HumanIdentityId.from(id));
        if (!ownerSessions.some((s) => digest(s.id.value) === proof.session_hash && s.status === "active" && s.expiresAt > now)) {
          if (!blockers.includes("CONTROL_REVOKED")) blockers.push("CONTROL_REVOKED");
        }
      }
    }
    if (source.lifecycle !== "active" || target.lifecycle !== "active")
      blockers.push("HUMAN_NOT_ACTIVE");
    const retaining = c.transfer_policy === "retain_records";
    const methods = source.human.authenticationMethods.filter(x=>x.status === "active");
    const sourceWillLoseSignIn = !methods.some(x=>x.method !== "google");
    if (!retaining) {
      if (source.protectedIdentity) blockers.push("PROTECTED_SOURCE");
      if (source.relationshipsPresent) blockers.push("SOURCE_DEPENDENCIES_PRESENT");
      if (source.unknownCoverage) blockers.push("SOURCE_DEPENDENCIES_UNKNOWN");
      if (methods.length !== 1 || methods[0]?.method !== "google") blockers.push("SOURCE_NOT_GOOGLE_ONLY");
      if (source.human.authenticationMethods.length !== 1) blockers.push("SOURCE_AUTHENTICATION_HISTORY");
    } else if (sourceWillLoseSignIn) {
      blockers.push(...await continuityBlockers(this.db,c.source_human_identity_id));
      if (source.products.some(p=>p.state === "verified" && (p.counts?.ownership ?? 0)>0)) blockers.push("EXTERNAL_OWNERSHIP_CONTINUITY_REQUIRED");
    }
    if (target.human.authenticationMethods.some(x=>x.method === "google" && (!retaining || x.status === "active"))) blockers.push("TARGET_GOOGLE_RELATIONSHIP_EXISTS");
    const targetMethods = target.human.authenticationMethods.filter(
      (x) => x.status === "active",
    );
    if (
      !targetMethods.some(
        (x) => x.method === "apple" || x.method === "email_password",
      )
    )
      blockers.push("TARGET_ACCESS_UNVERIFIED");
    const sessionImpact = source.sessions.map((s) => ({
      reference: s.reference,
      status: s.status,
      renewable: s.renewable,
    }));
    const reviewDigest = digest({
      caseId: c.id,
      relationship: c.relationship_id,
      source: source.reviewDigest,
      target: target.reviewDigest,
      proofExpiresAt: c.proof_expires_at,
      transferPolicy: c.transfer_policy ?? "verified_empty_source",
    });
    return {
      caseId: c.id,
      source,
      target,
      blockers,
      reviewDigest,
      proofExpiresAt: c.proof_expires_at?.toISOString(),
      executionEnabled: this.executionEnabled || this.recoveryEnabled,
      sessionImpact,
      sourceWillLoseSignIn,
      sourceDataPolicy: retaining ? "retain_records" : "verified_empty_source",
      plannedChanges: [
        "Move the verified Google relationship to the selected primary, retaining relationship ID and creation history",
        "Revoke every non-revoked source session; no target sessions are revoked",
        "Preserve both Humans, Apple, Email, application data, roles and entitlements",
      ],
    };
  }
  async previewRecovery(token: SessionId, id: string) {
    return this.db.withTransaction(async () => {
      const a = await this.admin(token);
      const c = await this.case(id, a.humanIdentityId);
      const p = await this.recoveryPreview(c);
      await this.audit(a.humanIdentityId, "recovery.execution.previewed", id);
      return p;
    });
  }
  async executeRecovery(
    token: SessionId,
    input: {
      caseId: string;
      requestId: string;
      reviewDigest: string;
      confirmation: string;
      revokeSourceSessions: boolean;
      acceptSourceLossOfAccess: boolean;
    },
  ) {
    await this.admin(token, true);
    this.gateRecovery();
    return this.db.withIdentityManagementTransaction(async () => {
      const a = await this.admin(token, true),
        intent = digest(input);
      const prev = await this.previous(
        input.requestId,
        a.humanIdentityId,
        "google_transfer",
        intent,
      );
      if (prev) return prev;
      const c = await this.case(input.caseId, a.humanIdentityId);
      const p = await this.recoveryPreview(c);
      if (p.blockers.length) reject("RECOVERY_BLOCKED", p.blockers.join(", "));
      if (p.reviewDigest !== input.reviewDigest)
        reject("REVIEW_CHANGED", "Evidence changed. Refresh the preview.");
      if (
        input.confirmation !==
          `transfer google ${c.source_human_identity_id} to ${c.target_human_identity_id}` ||
        !input.revokeSourceSessions ||
        !input.acceptSourceLossOfAccess
      )
        reject(
          "CONFIRMATION_REQUIRED",
          "Explicit source session revocation and loss of source sign-in consent are required.",
        );
      const proofs = await this.db.query<{
        human_identity_id: string;
        session_hash: string;
        proof_kind: string;
        expires_at: Date;
      }>(
        "SELECT human_identity_id,session_hash,proof_kind,expires_at FROM identity_management_control_proofs WHERE case_id=$1",
        [c.id],
      );
      for (const id of [
        c.source_human_identity_id,
        c.target_human_identity_id,
      ]) {
        const proof = proofs.rows.find((x) => x.human_identity_id === id);
        if (!proof || proof.expires_at <= this.clock.now())
          reject("CONTROL_EXPIRED", "Verify control again.");
        if (proof.proof_kind === 'provider') {
          if (id !== c.source_human_identity_id || !c.relationship_id) reject('CONTROL_INVALID','Provider proof is valid only for the exact source relationship.');
          continue; // The relationship ID, current source ownership and provider lock are checked below.
        }
        const sessions = await this.sessions.listByHumanIdentityId(
          HumanIdentityId.from(id),
        );
        if (
          !sessions.some(
            (s) =>
              digest(s.id.value) === proof.session_hash &&
              s.status === "active" &&
              s.expiresAt > this.clock.now(),
          )
        )
          reject(
            "CONTROL_REVOKED",
            "Account-control session is no longer valid.",
          );
      }
      const provider = FederatedIdentityProvider.from("google");
      await this.federated.lockHumanProvider(
        HumanIdentityId.from(c.source_human_identity_id),
        provider,
      );
      await this.federated.lockHumanProvider(
        HumanIdentityId.from(c.target_human_identity_id),
        provider,
      );
      const relationship =
        await this.federated.findActiveByHumanIdentityAndProvider(
          HumanIdentityId.from(c.source_human_identity_id),
          provider,
        );
      if (!relationship || relationship.id.value !== c.relationship_id)
        reject("RELATIONSHIP_CHANGED", "Authentication ownership changed.");
      await this.federated.lockProviderSubject(
        provider,
        relationship.providerSubject,
      );
      relationship.disable(this.clock);
      await this.federated.save(relationship);
      relationship.reassignTo(
        HumanIdentityId.from(c.target_human_identity_id),
        this.clock,
      );
      relationship.activate(this.clock);
      await this.federated.save(relationship);
      await this.sessions.revokeByHumanIdentityId(
        HumanIdentityId.from(c.source_human_identity_id),
      );
      await this.db.query(
        "UPDATE identity_management_cases SET state='completed' WHERE id=$1",
        [c.id],
      );
      const ownerAfter =
        await this.federated.findActiveByHumanIdentityAndProvider(
          HumanIdentityId.from(c.target_human_identity_id),
          provider,
        );
      if (
        ownerAfter?.id.value !== c.relationship_id ||
        (
          await this.sessions.listByHumanIdentityId(
            HumanIdentityId.from(c.source_human_identity_id),
          )
        ).some((s) => s.status !== "revoked")
      )
        reject(
          "POSTCONDITION_FAILED",
          "Recovery verification failed; no changes were committed.",
        );
      const revision = (await this.db.query<{write_revision:string}>("SELECT write_revision::text FROM federated_identities WHERE id=$1",[c.relationship_id])).rows[0]!.write_revision;
      const result = {
        caseId: c.id,
        requestId: input.requestId,
        relationshipId: c.relationship_id,
        relationshipRevision: revision,
        compensationPolicy: 'Separate receipt-bound verification and approval; revoke current owner sessions; never restore old sessions',
        compensationAvailable: true,
        sourceHumanIdentityId: c.source_human_identity_id,
        targetHumanIdentityId: c.target_human_identity_id,
        provider: "google",
        state: "completed",
      };
      await this.audit(a.humanIdentityId, "recovery.google.transferred", c.id, {
        source: c.source_human_identity_id,
        target: c.target_human_identity_id,
        requestId: input.requestId,
        sourceSessions: "revoked",
        records: "retained",
      });
      await this.record(
        input.requestId,
        a.humanIdentityId,
        "google_transfer",
        intent,
        result,
      );
      return result;
    });
  }
  private async transferReceipt(id:string,actor:string) {
    const r=await this.db.query<{kind:string;actor_human_identity_id:string;result:{caseId:string;requestId:string;sourceHumanIdentityId:string;targetHumanIdentityId:string;provider:string;state:string;relationshipId?:string;relationshipRevision?:string}}>(
      'SELECT kind,actor_human_identity_id,result FROM identity_management_operations WHERE id=$1',[id]);
    const row=r.rows[0];
    if(!row||row.actor_human_identity_id!==actor||row.kind!=='google_transfer'||row.result.state!=='completed') throw new AppError('Recovery receipt not found','RECEIPT_NOT_FOUND',404);
    if(!row.result.relationshipId||!row.result.relationshipRevision) reject('COMPENSATION_UNSUPPORTED','This receipt lacks a verified post-transfer relationship revision. Separate recovery review is required.');
    return row.result;
  }
  private async compensation(id:string,actor:string) {
    const r=await this.db.query<{id:string;original_request_id:string;actor_human_identity_id:string;nonce:string;state:string;created_at:Date;expires_at:Date;proof_expires_at:Date|null;target_session_hash:string|null}>(
      'SELECT * FROM identity_recovery_compensations WHERE id=$1 FOR UPDATE',[id]);
    const c=r.rows[0];
    if(!c||c.actor_human_identity_id!==actor) throw new AppError('Compensation request not found','COMPENSATION_NOT_FOUND',404);
    return c;
  }
  async prepareCompensation(token:SessionId,originalRequestId:string) {
    await this.admin(token,true); this.gateRecovery();
    return this.db.withIdentityManagementTransaction(async()=>{
      const a=await this.admin(token,true),receipt=await this.transferReceipt(originalRequestId,a.humanIdentityId),now=this.clock.now();
      if((await this.db.query("SELECT 1 FROM identity_recovery_compensations WHERE original_request_id=$1 AND state='completed'",[originalRequestId])).rows.length) reject('COMPENSATION_EXISTS','Review the existing compensation request.');
      const caseId=randomUUID(),nonce=randomBytes(32).toString('base64url'),expiresAt=new Date(now.getTime()+900000);
      const superseded=await this.db.query<{id:string}>("UPDATE identity_recovery_compensations SET state='cancelled' WHERE original_request_id=$1 AND actor_human_identity_id=$2 AND state IN ('awaiting_proof','verified') RETURNING id",[originalRequestId,a.humanIdentityId]);
      await this.auditSupersededCases(a.humanIdentityId,'compensation',superseded.rows,caseId);
      await this.db.query("INSERT INTO identity_recovery_compensations(id,original_request_id,actor_human_identity_id,nonce,state,created_at,expires_at) VALUES($1,$2,$3,$4,'awaiting_proof',$5,$6)",[caseId,originalRequestId,a.humanIdentityId,nonce,now,expiresAt]);
      await this.audit(a.humanIdentityId,'recovery.compensation.requested',caseId,{originalRequestId});
      return {caseId,originalRequestId,nonce,expiresAt:expiresAt.toISOString(),sourceHumanIdentityId:receipt.sourceHumanIdentityId,targetHumanIdentityId:receipt.targetHumanIdentityId,nextAction:'Freshly authenticate the surviving primary and verify the same Google account for this receipt-bound request.'};
    });
  }
  async proveCompensation(token:SessionId,input:{caseId:string;targetSession:string;identityToken:string},handoffId?:string) {
    await this.admin(token,true);this.gateRecovery();
    const actor=await this.admin(token,true),loaded=await this.db.withTransaction(()=>this.compensation(input.caseId,actor.humanIdentityId));
    let verified;
    try { verified=await this.verifiers.verify(FederatedIdentityProvider.from('google'),{identityToken:input.identityToken,nonce:loaded.nonce}); }
    catch { throw new AppError('Fresh Google control could not be verified','OWNERSHIP_INVALID',403); }
    return this.db.withIdentityManagementTransaction(async()=>{
      const a=await this.admin(token,true),c=await this.compensation(input.caseId,a.humanIdentityId),receipt=await this.transferReceipt(c.original_request_id,a.humanIdentityId),now=this.clock.now();
      if(c.state!=='awaiting_proof'||c.expires_at<=now||verified.expiresAt<=now) reject('PROOF_EXPIRED_OR_USED','Start a new compensation verification.');
      if (handoffId) await this.assertCurrentHandoff(handoffId,c.id,a.humanIdentityId,receipt.targetHumanIdentityId,'compensation');
      const target=await this.owner(SessionId.from(input.targetSession),true);
      if(!['email_password','apple'].includes(target.authenticationMethod ?? 'unknown')) reject('PRIMARY_METHOD_REQUIRED','Compensation requires fresh Apple or Email control of the primary, separately from Google.');
      if(target.humanIdentityId.value!==receipt.targetHumanIdentityId||target.authenticatedAt<c.created_at) reject('CONTROL_INVALID','Fresh sign-in to the exact surviving primary is required.');
      await this.federated.lockProviderSubject(verified.provider,verified.providerSubject);
      const relationship=await this.federated.findByProviderSubject(verified.provider,verified.providerSubject);
      if(!relationship||relationship.id.value!==receipt.relationshipId||relationship.status!=='active'||relationship.humanIdentityId.value!==receipt.targetHumanIdentityId) reject('RELATIONSHIP_CHANGED','The Google relationship no longer matches the original receipt.');
      if(!await this.nonces.consume(verified.provider,verified.nonceHash,verified.expiresAt,now)) reject('PROOF_REPLAY','Use fresh Google verification.');
      const until=new Date(Math.min(now.getTime()+300000,verified.expiresAt.getTime(),c.expires_at.getTime()));
      const hash=digest(target.id.value);
      // Owner-session evidence is globally single-use across recovery and compensation requests.
      const inserted=await this.db.query('INSERT INTO identity_management_control_proofs(session_hash,case_id,human_identity_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[hash,receipt.caseId,receipt.targetHumanIdentityId,until]);
      if(inserted.rowCount!==1) reject('CONTROL_REPLAY','Use a new primary sign-in for compensation.');
      await this.db.query("UPDATE identity_recovery_compensations SET state='verified',proof_expires_at=$2,target_session_hash=$3 WHERE id=$1",[c.id,until,hash]);
      await this.audit(a.humanIdentityId,'recovery.compensation.control_verified',c.id,{originalRequestId:c.original_request_id,subjectMatch:'true'});
      return {caseId:c.id,controlVerified:true,providerSubjectMatched:true,expiresAt:until.toISOString()};
    });
  }
  private async compensationPreview(c:Awaited<ReturnType<IdentityManagement['compensation']>>) {
    const receipt=await this.transferReceipt(c.original_request_id,c.actor_human_identity_id),source=await this.assess(receipt.sourceHumanIdentityId,c.id),target=await this.assess(receipt.targetHumanIdentityId,c.id),blockers:string[]=[];
    if(c.state!=='verified'||!c.proof_expires_at||c.proof_expires_at<=this.clock.now()||c.expires_at<=this.clock.now()) blockers.push('FRESH_CONTROL_REQUIRED');
    if(source.lifecycle!=='active'||target.lifecycle!=='active') blockers.push('HUMAN_NOT_ACTIVE');
    if(source.protectedIdentity||source.relationshipsPresent) blockers.push('SOURCE_DEPENDENCIES_PRESENT');
    if(source.unknownCoverage) blockers.push('SOURCE_DEPENDENCIES_UNKNOWN');
    if(source.human.authenticationMethods.length) blockers.push('SOURCE_AUTHENTICATION_CHANGED');
    if(!target.human.authenticationMethods.some(m=>m.status==='active'&&(m.method==='apple'||m.method==='email_password'))) blockers.push('TARGET_REMAINING_ACCESS_REQUIRED');
    const relationship=(await this.db.query<{human_identity_id:string;provider:string;status:string;write_revision:string}>(
      'SELECT human_identity_id,provider,status,write_revision::text FROM federated_identities WHERE id=$1',[receipt.relationshipId])).rows[0];
    if(!relationship||relationship.human_identity_id!==receipt.targetHumanIdentityId||relationship.provider!=='google'||relationship.status!=='active'||relationship.write_revision!==receipt.relationshipRevision) blockers.push('RELATIONSHIP_CHANGED');
    const proofSessions=await this.sessions.listByHumanIdentityId(HumanIdentityId.from(receipt.targetHumanIdentityId));
    if(!proofSessions.some(s=>digest(s.id.value)===c.target_session_hash&&s.status==='active'&&s.expiresAt>this.clock.now())) blockers.push('CONTROL_REVOKED');
    const originalProofs=(await this.db.query('SELECT human_identity_id FROM identity_management_control_proofs WHERE case_id=$1',[receipt.caseId])).rows;
    if(!originalProofs.some(p=>p.human_identity_id===receipt.sourceHumanIdentityId)||!originalProofs.some(p=>p.human_identity_id===receipt.targetHumanIdentityId)) blockers.push('ORIGINAL_CONTROL_HISTORY_MISSING');
    return {caseId:c.id,originalRequestId:c.original_request_id,source,target,blockers,executionEnabled:this.executionEnabled || this.recoveryEnabled,proofExpiresAt:c.proof_expires_at?.toISOString(),
      affectedTargetSessionCount:target.nonRevokedSessionCount,
      plannedChanges:['Return only the receipt-bound Google relationship to its original Human','Revoke all current primary sessions because provider attribution is unavailable','Keep all previously revoked source sessions revoked; fresh authentication is required','Preserve both Humans, profiles, roles, participation, entitlements and all application data'],
      automaticRollback:false,
      reviewDigest:digest({caseId:c.id,receipt,source:source.reviewDigest,target:target.reviewDigest,proofExpiresAt:c.proof_expires_at,relationship})};
  }
  async previewCompensation(token:SessionId,caseId:string) {
    return this.db.withTransaction(async()=>{const a=await this.admin(token),c=await this.compensation(caseId,a.humanIdentityId),p=await this.compensationPreview(c);
      await this.audit(a.humanIdentityId,'recovery.compensation.previewed',caseId);return p;});
  }
  async executeCompensation(token:SessionId,input:{caseId:string;requestId:string;reviewDigest:string;confirmation:string;revokeTargetSessions:boolean;acceptFreshSignIn:boolean}) {
    await this.admin(token,true);this.gateRecovery();
    return this.db.withIdentityManagementTransaction(async()=>{
      const a=await this.admin(token,true),intent=digest(input),prev=await this.previous(input.requestId,a.humanIdentityId,'google_compensation',intent);if(prev)return prev;
      const c=await this.compensation(input.caseId,a.humanIdentityId),p=await this.compensationPreview(c),receipt=await this.transferReceipt(c.original_request_id,a.humanIdentityId);
      if(p.blockers.length)reject('COMPENSATION_BLOCKED',p.blockers.join(', '));
      if(p.reviewDigest!==input.reviewDigest)reject('REVIEW_CHANGED','Evidence changed. Refresh the preview.');
      if(input.confirmation!==`return google ${receipt.targetHumanIdentityId} to ${receipt.sourceHumanIdentityId} receipt ${c.original_request_id}`||!input.revokeTargetSessions||!input.acceptFreshSignIn)reject('CONFIRMATION_REQUIRED','Confirm the exact receipt, both Humans and primary-session invalidation.');
      const provider=FederatedIdentityProvider.from('google');
      await this.federated.lockHumanProvider(HumanIdentityId.from(receipt.targetHumanIdentityId),provider);
      await this.federated.lockHumanProvider(HumanIdentityId.from(receipt.sourceHumanIdentityId),provider);
      const relationship=await this.federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(receipt.targetHumanIdentityId),provider);
      if(!relationship||relationship.id.value!==receipt.relationshipId)reject('RELATIONSHIP_CHANGED','The Google relationship no longer matches the original receipt.');
      await this.federated.lockProviderSubject(provider,relationship.providerSubject);
      relationship.disable(this.clock);await this.federated.save(relationship);
      relationship.reassignTo(HumanIdentityId.from(receipt.sourceHumanIdentityId),this.clock);relationship.activate(this.clock);await this.federated.save(relationship);
      await this.sessions.revokeByHumanIdentityId(HumanIdentityId.from(receipt.targetHumanIdentityId));
      await this.sessions.revokeByHumanIdentityId(HumanIdentityId.from(receipt.sourceHumanIdentityId));
      const restored=await this.federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(receipt.sourceHumanIdentityId),provider);
      if(restored?.id.value!==receipt.relationshipId||(await this.sessions.listByHumanIdentityId(HumanIdentityId.from(receipt.targetHumanIdentityId))).some(s=>s.status!=='revoked')||(await this.sessions.listByHumanIdentityId(HumanIdentityId.from(receipt.sourceHumanIdentityId))).some(s=>s.status!=='revoked'))reject('POSTCONDITION_FAILED','Compensation failed verification; no changes were committed.');
      await this.db.query("UPDATE identity_recovery_compensations SET state='completed' WHERE id=$1",[c.id]);
      const result={caseId:c.id,requestId:input.requestId,originalRequestId:c.original_request_id,sourceHumanIdentityId:receipt.sourceHumanIdentityId,targetHumanIdentityId:receipt.targetHumanIdentityId,provider:'google',state:'completed',oldSessionsRestored:false};
      await this.audit(a.humanIdentityId,'recovery.google.compensated',c.id,{originalRequestId:c.original_request_id,requestId:input.requestId,sourceSessions:'remain_revoked',targetSessions:'revoked',records:'retained'});
      await this.record(input.requestId,a.humanIdentityId,'google_compensation',intent,result);return result;
    });
  }
}
