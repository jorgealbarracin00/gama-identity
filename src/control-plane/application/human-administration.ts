import { legacyHumanCapabilities, anyHumanCapability, requireHumanCapability, requireConfirmedTest, type HumanCapabilities } from "./administrative-capabilities.js";
import { randomUUID } from "node:crypto";
import type { PostgresDatabase } from "../../infrastructure/postgres/database.js";
import type { IdentityManagement } from "./identity-management.js";
import { digest } from "./identity-management.js";
import { continuityBlockers } from "./human-continuity.js";
import type { SessionRepository } from "../../sessions/ports/session-repository.js";
import { SessionId } from "../../sessions/domain/session-id.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import type { AdministrationPrincipals } from "./administration-principals.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import type { ControlPlane } from "./control-plane.js";
import type { Clock } from "../../shared/clock.js";
import { AppError } from "../../shared/errors.js";

export type AdministrativeHumanAction = "suspend" | "reactivate" | "retire" | "revoke_sessions" | "delete";
export type HumanDeletionScope = "identity_only" | "eligible_personal_data";
export interface HumanAdministrativeCommand {
  humanIdentityId: string; action: AdministrativeHumanAction; requestId: string;
  reviewDigest: string; confirmation: string; scope: HumanDeletionScope; sessionReference?: string | undefined;
}
interface CleanupTask {
  id: string; operation_id: string; human_identity_id: string; product_id: string | null;
  state: "pending" | "claimed" | "completed" | "unsupported" | "failed"; revision: number;
  claimed_workload_id: string | null; lease_expires_at: Date | null; result: Record<string, unknown> | null;
}

/** Central account deletion is deidentification, not a cascade through product stores. */
export class HumanAdministration {
  constructor(
    private readonly db: PostgresDatabase,
    private readonly management: IdentityManagement,
    private readonly sessions: SessionRepository,
    private readonly humans: HumanIdentityRepository,
    private readonly principals: AdministrationPrincipals,
    private readonly auditRepository: ControlPlaneRepository,
    private readonly plane: ControlPlane,
    private readonly clock: Clock,
    enabled: boolean,
    readonly capabilities: HumanCapabilities = legacyHumanCapabilities(enabled),
  ) {}

  get enabled() { return anyHumanCapability(this.capabilities); }
  private gate(action: keyof HumanCapabilities) { requireHumanCapability(this.capabilities, action); }
  private async administrator(token: SessionId, fresh = false) {
    const s = await this.sessions.findById(token), now = this.clock.now();
    if (!s || s.status !== "active" || s.expiresAt <= now || (await this.humans.findById(s.humanIdentityId))?.status !== "active") {
      throw new AppError("Sign in to continue", "SESSION_INVALID", 401);
    }
    const age = now.getTime() - s.authenticatedAt.getTime();
    if (fresh && (age < 0 || age > 300000)) throw new AppError("Sign in again to confirm this action", "REAUTHENTICATION_REQUIRED", 403);
    return this.principals.platform(s.humanIdentityId.value);
  }
  private async audit(actor: string, type: string, subject: string, data: Record<string, string> = {}) {
    await this.auditRepository.appendAudit({ id: randomUUID(), actorReference: `human-identity:${actor}`,
      subjectReference: `human-identity:${subject}`, eventType: type, eventData: data, occurredAt: this.clock.now() });
  }
  private async deleted(id: string) {
    return (await this.db.query("SELECT 1 FROM identity_management_operations WHERE kind='human.delete' AND result->>'humanIdentityId'=$1 LIMIT 1", [id])).rows.length > 0;
  }

  async available(token: SessionId, human: string) {
    return this.db.withTransaction(async () => {
      await this.administrator(token);
      const assessment = await this.management.inspect(token, human);
      const continuity = await continuityBlockers(this.db, human);
      const deleted = await this.deleted(human);
      return {
        humanIdentityId: human, displayName: assessment.human.displayName, status: assessment.lifecycle,
        deidentified: deleted, executionEnabled: this.enabled, capabilities: this.capabilities, bulkAvailable: this.capabilities.bulk,
        actions: (["suspend", "reactivate", "revoke_sessions", "retire", "delete"] as const).map(action => ({
          action, executionEnabled: this.capabilities[action],
          availability: !this.capabilities[action] ? "disabled" : deleted ? "unavailable_account_state" : "available_subject_to_review",
          blockers: deleted ? ["HUMAN_DEIDENTIFIED"] : action === "reactivate" ? (assessment.lifecycle === "suspended" ? [] : ["NOT_SUSPENDED"]) :
            action === "revoke_sessions" ? [] : [...continuity, ...(action !== "delete" && assessment.lifecycle === "retired" ? ["RETIRED_IS_TERMINAL"] : [])],
        })),
        classificationAvailable: this.capabilities.classification && !deleted,
        providerTransferPolicy: "Requires current verified control of both accounts, a separate recovery preview and explicit confirmation; never merges data",
        auditRetention: "Canonical tombstones and minimal operation/audit references are retained; credentials and profile data are removed",
      };
    });
  }

  async preview(token: SessionId, human: string, action: AdministrativeHumanAction, scope: HumanDeletionScope = "identity_only", sessionReference?: string) {
    return this.db.withTransaction(async () => {
      const actor = await this.administrator(token);
      const confirmedTest = (await this.db.query("SELECT 1 FROM human_purposes WHERE human_identity_id=$1 AND purpose='test'", [human])).rows.length > 0;
      const bulk = {bulkEligible: confirmedTest, bulkBlockers: confirmedTest ? [] : ["BULK_REQUIRES_CONFIRMED_TEST"], bulkExecutionEnabled: this.capabilities.bulk && this.capabilities[action]};
      if (sessionReference !== undefined && (action !== "revoke_sessions" || !/^[a-f0-9]{64}$/u.test(sessionReference))) {
        throw new AppError("Selected session is invalid", "INVALID_SESSION_REFERENCE", 400);
      }
      if (action === "suspend" || action === "reactivate" || action === "retire") {
        const p = await this.management.previewLifecycle(token, [human], action);
        const account = p.accounts[0]!;
        return { ...bulk, humanIdentityId: human, displayName: account.assessment.human.displayName, action, scope,
          blockers: account.blockers, eligible: account.eligible, executionEnabled: this.capabilities[action],
          reviewDigest: account.assessment.reviewDigest, confirmation: `${action} ${human}`,
          consequences: [account.sessionPolicy, "Existing authentication relationships and all central/product data are retained", account.retirementPolicy],
          affectedSessions: account.affectedSessionCount, externalCleanup: [] };
      }
      const a = await this.management.inspect(token, human);
      const blockers = action === "delete" ? await continuityBlockers(this.db, human) : [];
      if (await this.deleted(human)) blockers.push("HUMAN_DEIDENTIFIED");
      // An in-flight Apple token revocation is a real provider obligation. Central
      // deletion must not erase its encrypted grant or claim its work completed.
      const pendingApple = (await this.db.query<{ count: number }>("SELECT count(*)::int count FROM product_apple_revocations WHERE human_identity_id=$1 AND completed_at IS NULL", [human])).rows[0]!.count;
      if (action === "delete" && pendingApple > 0) blockers.push("PROVIDER_REVOCATION_PENDING");
      const products = a.human.products.map(p => ({ productId: p.productId, displayName: p.displayName, state: "separate_cleanup_required" }));
      const byProduct = new Map(products.map(p=>[p.productId,p]));
      for (const report of a.products) {
        if (report.state === "verified" && Object.values(report.counts ?? {}).some(n=>n>0) && !byProduct.has(report.productId)) {
          byProduct.set(report.productId,{productId:report.productId,displayName:report.productId,state:"separate_cleanup_required"});
        }
      }
      if (action === "delete" && a.products.some(p=>p.state === "verified" && (p.counts?.ownership ?? 0)>0)) blockers.push("EXTERNAL_OWNERSHIP_CONTINUITY_REQUIRED");
      const external = action === "delete" && scope === "eligible_personal_data" ? [...byProduct.values(),
        // Participation/inspector history cannot prove no unreported product data.
        ...(a.unknownCoverage ? [{ productId: null, displayName: "Unverified external data coverage", state: "unsupported_until_verified" }] : [])] : [];
      const selected = sessionReference === undefined ? undefined : await this.selectedSession(human, sessionReference);
      const stable = { human, action, scope, sessionReference, assessment: a.reviewDigest, continuity: blockers, pendingApple, external };
      await this.audit(actor.humanIdentityId, "human.administration.previewed", human, { action, scope });
      return {
        ...bulk, humanIdentityId: human, displayName: a.human.displayName, action, scope, blockers,
        eligible: blockers.length === 0, executionEnabled: this.capabilities[action], reviewDigest: digest(stable), sessionReference,
        confirmation: `${action} ${human}${action === "delete" ? ` ${scope}` : sessionReference ? ` session ${sessionReference}` : ""}`,
        affectedSessions: selected ? (selected.status === "revoked" ? 0 : 1) : a.nonRevokedSessionCount, externalCleanup: external,
        consequences: action === "revoke_sessions" ? [selected ? "Revoke only this selected GAMA session, including its renewable access" : "Revoke every central access and renewable session for this Human", "Authentication methods and all data remain; fresh sign-in is required", "External product sessions are outside this GAMA session scope"] : [
          "Revoke this Human's central sessions and remove its sign-in credentials",
          "Remove shared profile, central memberships, entitlements and personal participation references",
          "Deidentify the Human and provider relationships; retain canonical IDs, creation history and audit references",
          "Preserve businesses, catalogues, photographs, shared assets and every unrelated Human",
          scope === "identity_only" ? "External product data is retained; this operation completes only the central identity scope" : "Eligible personal product data needs separately scoped cleanup; pending or unsupported work is reported accurately",
          "Promotional eligibility is a separate product-policy decision and is not reset",
        ],
      };
    });
  }

  private async selectedSession(human: string, reference: string) {
    const records = (await this.db.query<{id:string;status:string}>("SELECT id,status FROM sessions WHERE human_identity_id=$1", [human])).rows;
    const selected = records.find(record => digest(record.id) === reference);
    if (!selected) throw new AppError("This session does not belong to the selected account", "SESSION_REFERENCE_NOT_FOUND", 404);
    return selected;
  }
  async execute(token: SessionId, input: HumanAdministrativeCommand, confirmedTestOnly = false) {
    await this.administrator(token, true); this.gate(input.action);
    if (input.sessionReference !== undefined && input.action !== "revoke_sessions") throw new AppError("Selected session scope is valid only for revocation", "INVALID_SESSION_REFERENCE", 400);
    if (input.action === "suspend" || input.action === "reactivate" || input.action === "retire") {
      const result = await this.management.lifecycle(token, { ...input, action: input.action, revokeSessions: input.action !== "reactivate" }, confirmedTestOnly);
      return { ...result, reauthenticationRequired: input.action !== "reactivate" && (await this.sessions.findById(token))?.status !== "active" };
    }
    return this.db.withIdentityManagementTransaction(async () => {
      const actor = await this.administrator(token, true), intent = digest(input), kind = `human.${input.action}`;
      const previous = (await this.db.query<{ actor_human_identity_id: string; kind: string; intent_digest: string; result: Record<string, unknown> }>(
        "SELECT actor_human_identity_id,kind,intent_digest,result FROM identity_management_operations WHERE id=$1", [input.requestId])).rows[0];
      if (previous) {
        if (previous.actor_human_identity_id !== actor.humanIdentityId || previous.kind !== kind || previous.intent_digest !== intent) {
          throw new AppError("Request identifier belongs to another action", "IDEMPOTENCY_CONFLICT", 409);
        }
        return input.action === "delete" ? this.deletionStatus(input.requestId) : previous.result;
      }
      if (confirmedTestOnly) await requireConfirmedTest(this.db, input.humanIdentityId);
      const preview = await this.preview(token, input.humanIdentityId, input.action, input.scope, input.sessionReference);
      if (!preview.eligible) throw new AppError("Resolve the listed continuity or provider obligations first", "ADMINISTRATION_BLOCKED", 409);
      if (preview.reviewDigest !== input.reviewDigest) throw new AppError("The account changed; refresh its consequences", "REVIEW_CHANGED", 409);
      if (input.confirmation !== preview.confirmation) throw new AppError("Confirm the exact reviewed action", "CONFIRMATION_REQUIRED", 409);
      const id = input.humanIdentityId, now = this.clock.now();
      if (input.sessionReference !== undefined) {
        const selected = await this.selectedSession(id, input.sessionReference);
        await this.sessions.revoke(SessionId.from(selected.id));
      } else await this.sessions.revokeByHumanIdentityId(HumanIdentityId.from(id));
      if (input.action === "delete") {
        // Keep tombstones for foreign-key/audit history; erase login authority.
        await this.db.query("DELETE FROM credentials WHERE human_identity_id=$1", [id]);
        await this.db.query(`UPDATE federated_identities SET provider_subject='deleted:'||id,provider_email=NULL,
          provider_email_verified=NULL,provider_email_private=NULL,status='retired',updated_at=$2,write_revision=write_revision+1 WHERE human_identity_id=$1`, [id, now]);
        for (const table of ["product_entitlements", "tenant_memberships", "human_product_participations", "human_profiles", "human_purposes", "product_dependency_reports", "platform_administration_memberships"]) {
          await this.db.query(`DELETE FROM ${table} WHERE human_identity_id=$1`, [id]);
        }
        await this.db.query("UPDATE identity_management_cases SET state='cancelled',nonce='',proof_expires_at=NULL WHERE state IN ('awaiting_proof','verified') AND (source_human_identity_id=$1 OR target_human_identity_id=$1 OR actor_human_identity_id=$1)", [id]);
        await this.db.query("DELETE FROM identity_management_control_proofs WHERE human_identity_id=$1", [id]);
        await this.db.query("UPDATE identity_recovery_compensations SET state='cancelled',nonce='',proof_expires_at=NULL,target_session_hash=NULL WHERE state IN ('awaiting_proof','verified') AND (actor_human_identity_id=$1 OR original_request_id IN (SELECT id FROM identity_management_operations WHERE result->>'sourceHumanIdentityId'=$1 OR result->>'targetHumanIdentityId'=$1))", [id]);
        await this.db.query("UPDATE identity_management_google_handoffs SET state='cancelled',code_verifier=NULL WHERE state IN ('awaiting_callback','processing') AND (actor_id=$1 OR target_id=$1 OR recovery_case_id IN (SELECT id FROM identity_management_cases WHERE source_human_identity_id=$1 OR target_human_identity_id=$1) OR compensation_case_id IN (SELECT id FROM identity_recovery_compensations WHERE actor_human_identity_id=$1 OR original_request_id IN (SELECT id FROM identity_management_operations WHERE result->>'sourceHumanIdentityId'=$1 OR result->>'targetHumanIdentityId'=$1)))", [id]);
        await this.db.query("UPDATE identity_recovery_requests SET state='cancelled',updated_at=$2 WHERE state='review_required' AND (source_human_identity_id=$1 OR target_human_identity_id=$1)", [id, now]);
        await this.db.query("UPDATE human_identities SET status='retired',updated_at=$2,write_revision=write_revision+1 WHERE id=$1", [id, now]);
      }
      const result = { humanIdentityId: id, requestId: input.requestId, scope: input.scope,
        status: input.action === "delete" ? "deidentified" : "sessions_revoked", centralComplete: true,
        canonicalHistoryRetained: true, reauthenticationRequired: id === actor.humanIdentityId };
      await this.db.query("INSERT INTO identity_management_operations(id,actor_human_identity_id,kind,intent_digest,result,created_at) VALUES($1,$2,$3,$4,$5,$6)", [input.requestId, actor.humanIdentityId, kind, intent, result, now]);
      if (input.action === "delete" && input.scope === "eligible_personal_data") {
        for (const item of preview.externalCleanup) {
          await this.db.query("INSERT INTO identity_deletion_tasks(id,operation_id,human_identity_id,product_id,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$6)",
            [randomUUID(), input.requestId, id, item.productId, item.productId === null ? "unsupported" : "pending", now]);
        }
      }
      await this.audit(actor.humanIdentityId, input.action === "delete" ? "human.deletion.central_completed" : "human.sessions.revoked", id, { requestId: input.requestId, scope: input.scope, history: "retained", ...(input.sessionReference ? {sessionReference:input.sessionReference,sessionScope:"selected"} : {sessionScope:"all"}) });
      return input.action === "delete" ? this.deletionStatus(input.requestId) : result;
    });
  }

  private async deletionStatus(request: string) {
    const record = (await this.db.query<{ result: Record<string, unknown> }>("SELECT result FROM identity_management_operations WHERE id=$1 AND kind='human.delete'", [request])).rows[0];
    if (!record) throw new AppError("Deletion operation not found", "OPERATION_NOT_FOUND", 404);
    const tasks = (await this.db.query<CleanupTask>("SELECT id,operation_id,human_identity_id,product_id,state,revision,claimed_workload_id,lease_expires_at,result FROM identity_deletion_tasks WHERE operation_id=$1 ORDER BY created_at,id", [request])).rows;
    const pending = tasks.some(t => t.state !== "completed");
    return { ...record.result, operationState: pending ? "pending_external_cleanup" : record.result.scope === "identity_only" ? "completed_central_scope" : "completed_supported_scope",
      externalCleanup: tasks.map(t => ({ id: t.id, productId: t.product_id, state: t.state, result: t.result })), externalDataDeletedByIdentity: false };
  }
  async status(token: SessionId, request: string) {
    return this.db.withTransaction(async () => { await this.administrator(token); return this.deletionStatus(request); });
  }
  async bulk(token: SessionId, items: HumanAdministrativeCommand[], confirmation: string) {
    await this.administrator(token, true); this.gate("bulk");
    if (confirmation !== `review ${items.length} identities`) throw new AppError("Confirm the selected count", "CONFIRMATION_REQUIRED", 409);
    const results = [];
    for (const item of items) {
      try {
        const result=await this.execute(token,item,true);
        const pending=(result as Record<string,unknown>).operationState === "pending_external_cleanup";
        results.push({humanIdentityId:item.humanIdentityId,state:pending?"pending_external_cleanup":"completed",result});
      }
      catch (error) { results.push({ humanIdentityId: item.humanIdentityId, state: "blocked", code: error instanceof AppError ? error.code : "OPERATION_FAILED" }); }
    }
    return { results };
  }

  private async workload(id: string, secret: string) {
    const workload = await this.plane.authenticateWorkload(id, secret, "human.data.cleanup");
    if (!workload) throw new AppError("A product-bound cleanup workload is required", "WORKLOAD_UNAUTHORIZED", 401);
    return workload;
  }
  async claimCleanup(workloadID: string, secret: string) {
    this.gate("delete");
    return this.db.withIdentityManagementTransaction(async () => {
      const w = await this.workload(workloadID, secret), now = this.clock.now();
      const jobs = await this.db.query<CleanupTask>(`SELECT * FROM identity_deletion_tasks WHERE product_id=$1 AND
        (state IN ('pending','failed') OR (state='claimed' AND lease_expires_at<=$2)) ORDER BY created_at,id LIMIT 10 FOR UPDATE`, [w.productId, now]);
      const tasks = [];
      for (const job of jobs.rows) {
        await this.db.query("UPDATE identity_deletion_tasks SET state='claimed',revision=revision+1,claimed_workload_id=$2,lease_expires_at=$3,updated_at=$4 WHERE id=$1", [job.id, w.workloadId, new Date(now.getTime()+300000), now]);
        tasks.push({ id: job.id, humanIdentityId: job.human_identity_id, productId: w.productId, revision: job.revision+1,
          scope: "eligible_personal_data", preserveSharedAssets: true, preservePromotionalEligibility: true });
      }
      return { tasks };
    });
  }
  async completeCleanup(workloadID: string, secret: string, input: { id: string; revision: number; state: "completed" | "unsupported" | "failed"; deletedRecords: number; retainedRecords: number }) {
    this.gate("delete");
    return this.db.withIdentityManagementTransaction(async () => {
      const w = await this.workload(workloadID, secret), now = this.clock.now();
      const job = (await this.db.query<CleanupTask>("SELECT * FROM identity_deletion_tasks WHERE id=$1 FOR UPDATE", [input.id])).rows[0];
      if (!job || job.product_id !== w.productId) throw new AppError("Cleanup task unavailable", "CLEANUP_TASK_UNAVAILABLE", 404);
      const result = { state: input.state, deletedRecords: input.deletedRecords, retainedRecords: input.retainedRecords, reportingWorkloadId: w.workloadId };
      if (job.state === input.state && job.revision === input.revision+1 && job.result && Object.keys(job.result).length===4 &&
        job.result.state===result.state && job.result.deletedRecords===result.deletedRecords && job.result.retainedRecords===result.retainedRecords && job.result.reportingWorkloadId===w.workloadId) return { state: job.state, replayed: true };
      if (job.state !== "claimed" || job.claimed_workload_id !== w.workloadId || job.revision !== input.revision || !job.lease_expires_at || job.lease_expires_at <= now) throw new AppError("Cleanup lease changed; claim the current task", "CLEANUP_REVISION_CONFLICT", 409);
      await this.db.query("UPDATE identity_deletion_tasks SET state=$2,revision=revision+1,claimed_workload_id=NULL,lease_expires_at=NULL,result=$3,updated_at=$4 WHERE id=$1", [job.id, input.state, result, now]);
      await this.auditRepository.appendAudit({ id: randomUUID(), actorReference: `workload:${w.workloadId}`, subjectReference: `deletion-task:${job.id}`,
        eventType: `human.deletion.external_${input.state}`, eventData: { deletedRecords: String(input.deletedRecords), retainedRecords: String(input.retainedRecords) }, occurredAt: now });
      return { state: input.state, replayed: false };
    });
  }
}
