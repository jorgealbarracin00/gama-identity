import type { PostgresDatabase } from "../../infrastructure/postgres/database.js";
import type { Clock } from "../../shared/clock.js";
import type { SessionId } from "../../sessions/domain/session-id.js";
import type { IdentityManagement } from "./identity-management.js";

export interface RecoveryOverviewIssue {
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  readonly action: string;
  readonly destination: "recovery";
}

const blockerExplanation: Readonly<Record<string, string>> = {
  FRESH_CONTROL_REQUIRED: "Fresh primary sign-in and Google ownership verification are missing or expired.",
  HUMAN_NOT_ACTIVE: "Both selected Humans must be active before recovery can proceed.",
  PROTECTED_SOURCE: "The source has protected platform or business responsibilities.",
  SOURCE_DEPENDENCIES_PRESENT: "Source relationships or retained resources require review.",
  SOURCE_DEPENDENCIES_UNKNOWN: "Authoritative product dependency inspection is incomplete.",
  SOURCE_NOT_GOOGLE_ONLY: "The source must own only the verified Google sign-in method for this supported workflow.",
  SOURCE_AUTHENTICATION_HISTORY: "Retained authentication history requires a separate recovery review.",
  TARGET_GOOGLE_RELATIONSHIP_EXISTS: "The primary already has a Google relationship requiring review.",
  TARGET_ACCESS_UNVERIFIED: "The primary needs an active Apple or Email sign-in method.",
  TARGET_REMAINING_ACCESS_REQUIRED: "The primary needs verified remaining Apple or Email access.",
  SOURCE_AUTHENTICATION_CHANGED: "The original source authentication state has changed.",
  RELATIONSHIP_CHANGED: "The Google relationship no longer matches the reviewed recovery receipt.",
  CONTROL_REVOKED: "An account-control session is no longer valid; verify control again.",
  CONTROL_EXPIRED: "Account-control evidence is missing or expired; verify control again.",
  CONTROL_INVALID: "Account-control evidence does not match the exact selected Human and Google relationship.",
  ORIGINAL_CONTROL_HISTORY_MISSING: "The original recovery control evidence requires review.",
};

/** Bounded, actor-owned issue summaries. Full identity/proof projections remain inside the backend. */
export async function recoveryOverviewSignals(db: PostgresDatabase, management: IdentityManagement,
  session: SessionId, actor: string, clock: Clock): Promise<RecoveryOverviewIssue[]> {
  const rows = await db.query<{id:string;kind:"recovery"|"compensation";expires_at:Date}>(`
    SELECT id,kind,expires_at FROM (
      SELECT id,'recovery'::text AS kind,created_at,expires_at FROM identity_management_cases
      WHERE actor_human_identity_id=$1 AND state IN ('awaiting_proof','verified')
      UNION ALL
      SELECT id,'compensation'::text AS kind,created_at,expires_at FROM identity_recovery_compensations
      WHERE actor_human_identity_id=$1 AND state IN ('awaiting_proof','verified')
    ) owned ORDER BY created_at DESC,id LIMIT 10`,[actor]);
  const issues: RecoveryOverviewIssue[]=[];
  for(const row of rows.rows) {
    // Public preview methods recheck current administrator authorization and all execution safeguards.
    const preview = row.kind === "compensation" ? await management.previewCompensation(session,row.id) : await management.previewRecovery(session,row.id);
    const reasons: string[]=[];
    if(!management.executionEnabled||!preview.executionEnabled) reasons.push("Production recovery execution is disabled; separate approval and activation review are required.");
    if(row.expires_at<=clock.now()) reasons.push("This recovery request has expired. Start a new ownership verification.");
    for(const blocker of preview.blockers) reasons.push(blockerExplanation[blocker]??"A server-side recovery safeguard requires a separate review.");
    const ready=reasons.length===0;
    issues.push({id:`recovery-${row.kind}-${row.id}`,title:ready?"Recovery ready for review":"Recovery blocked",
      detail:ready?"Ownership verification and current dependency safeguards are complete. Review the exact consequences before separately authorizing execution.":[...new Set(reasons)].join(" "),
      action:ready?"Review proposed recovery":"Complete recovery requirements",destination:"recovery"});
  }
  return issues;
}
