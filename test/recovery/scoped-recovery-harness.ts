// TEST ONLY. Not included by tsconfig.json, imported by no src module, and has no HTTP route.
import { randomUUID } from "node:crypto";
import type { PostgresDatabase } from "../../src/infrastructure/postgres/database.js";
import type { ApplicationRuntime } from "../../src/api/services.js";
import { scope } from "../operational/google-verification-scope.js";
import type { VerifiedFederatedCredential } from "../../src/authentication/federated/application/token-verifier.js";
import { PostgresFederatedIdentityRepository, PostgresFederatedAuthenticationNonceRepository } from "../../src/infrastructure/postgres/postgres-federated-identity-repository.js";
import { PostgresSessionRepository } from "../../src/infrastructure/postgres/postgres-session-repository.js";
import { PostgresControlPlaneRepository } from "../../src/infrastructure/postgres/postgres-control-plane-repository.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import type { Clock } from "../../src/shared/clock.js";
import type { Session } from "../../src/sessions/domain/session.js";

interface Grant { id:string; approval:string; digest:string; expires:Date; completed:boolean; reverse:boolean; relationship_id:string; forward_id:string|null }
/** Prototype uses cooperating writers behind a pair fence. Production writers are NOT wired to this fence. */
export class TestOnlyScopedRecovery {
  private readonly federated;
  private readonly sessions;
  private readonly control;
  private readonly nonces;
  constructor(private readonly db:PostgresDatabase,private readonly runtime:ApplicationRuntime,private readonly clock:Clock) {
    this.federated=new PostgresFederatedIdentityRepository(db);this.sessions=new PostgresSessionRepository(db);
    this.control=new PostgresControlPlaneRepository(db);this.nonces=new PostgresFederatedAuthenticationNonceRepository(db);
  }
  async install() { await this.db.query(`CREATE TABLE IF NOT EXISTS recovery_test_grants
    (id uuid PRIMARY KEY,approval text NOT NULL,digest text NOT NULL,expires timestamptz NOT NULL,
    completed boolean NOT NULL DEFAULT false,reverse boolean NOT NULL,relationship_id text NOT NULL,forward_id uuid)`); }
  async fence<T>(work:()=>Promise<T>) { return this.db.withTransaction(async()=>{
    await this.db.query("SELECT pg_advisory_xact_lock(710013)");return work();
  }); }
  async grant(sessionId:string, explicitApproval:string, externalDependenciesVerified:boolean, forwardId?:string) {
    return this.fence(async()=>{
      if(!explicitApproval || !externalDependenciesVerified) throw new Error("APPROVAL_OR_EXTERNAL_EVIDENCE_MISSING");
      const report=await this.runtime.services.administration.googleVerification!.administer(SessionId.from(sessionId),{mode:"inspect"});
      const observation=report.observation;
      if(!observation?.matched || !observation.relationshipId || observation.state!=="reviewed") throw new Error("CONTROL_NOT_VERIFIED");
      if(!forwardId && !report.controlsVerified) throw new Error("PROOF_EXPIRED");
      if(forwardId) {
        const completed=await this.db.query<Grant>("SELECT * FROM recovery_test_grants WHERE id=$1",[forwardId]);
        if(!completed.rows[0]?.completed || completed.rows[0].reverse) throw new Error("FORWARD_RECEIPT_REQUIRED");
      }
      const id=randomUUID();await this.db.query(`INSERT INTO recovery_test_grants
        (id,approval,digest,expires,reverse,relationship_id,forward_id) VALUES($1,$2,$3,$4,$5,$6,$7)`,
        [id,explicitApproval,report.reviewDigest,new Date(this.clock.now().getTime()+300_000),!!forwardId,observation.relationshipId,forwardId??null]);
      return id;
    });
  }
  async execute(sessionId:string,proof:VerifiedFederatedCredential,grantId:string,failAt?:"disconnect"|"sessions"|"audit") {
    return this.fence(async()=>{
      const found=await this.db.query<Grant>("SELECT * FROM recovery_test_grants WHERE id=$1 FOR UPDATE",[grantId]);const grant=found.rows[0];
      if(!grant?.approval || grant.expires<=this.clock.now()) throw new Error("GRANT_INVALID");
      const session=await this.sessions.findByIdForUpdate(SessionId.from(sessionId));
      if(!session || session.humanIdentityId.value!==scope.target || session.status!=="active" || session.expiresAt<=this.clock.now() || this.clock.now().getTime()-session.authenticatedAt.getTime()<0 || this.clock.now().getTime()-session.authenticatedAt.getTime()>300_000) throw new Error("CALLER_INVALID");
      const report=await this.runtime.services.administration.googleVerification!.administer(SessionId.from(sessionId),{mode:"inspect"});
      const duplicate=report.source;
      if(duplicate.status!=="active" || report.target.status!=="active" || duplicate.platformMembership || duplicate.tenantMemberships.length || duplicate.productAssociations.length || Object.values(duplicate.extras).some(v=>v!==0)) throw new Error("DEPENDENCIES_REQUIRE_REVIEW");
      if(!report.target.authenticationMethods.some(m=>m.method==="apple"&&m.status==="active") || !report.target.authenticationMethods.some(m=>m.method==="email_password"&&m.status==="active")) throw new Error("PRIMARY_ACCESS_CHANGED");
      if(proof.provider.value!=="google" || proof.expiresAt<=this.clock.now()) throw new Error("PROOF_INVALID");
      await this.federated.lockHumanProvider(HumanIdentityId.from(scope.source),proof.provider);
      await this.federated.lockHumanProvider(HumanIdentityId.from(scope.target),proof.provider);
      await this.federated.lockProviderSubject(proof.provider,proof.providerSubject);
      const relationship=await this.federated.findByProviderSubject(proof.provider,proof.providerSubject);
      if(!relationship || relationship.id.value!==grant.relationship_id || relationship.status!=="active") throw new Error("SUBJECT_MISMATCH");
      const from=grant.reverse?scope.target:scope.source,to=grant.reverse?scope.source:scope.target;
      if(grant.completed) {if(relationship.humanIdentityId.value!==to)throw new Error("RECEIPT_STATE_CHANGED");return "already_completed";}
      if(relationship.humanIdentityId.value!==from || grant.digest!==report.reviewDigest) throw new Error("REVIEW_CHANGED");
      if(!grant.reverse && (duplicate.authenticationMethods.length!==1 || duplicate.authenticationMethods[0]?.method!=="google")) throw new Error("SOURCE_NOT_GOOGLE_ONLY");
      if(!await this.nonces.consume(proof.provider,proof.nonceHash,proof.expiresAt,this.clock.now())) throw new Error("PROOF_REPLAYED");
      relationship.disable(this.clock);await this.federated.save(relationship);
      if(failAt==="disconnect") throw new Error("INJECTED_FAILURE");
      relationship.reassignTo(HumanIdentityId.from(to),this.clock);relationship.recordVerifiedMetadata(proof.metadata,this.clock);relationship.activate(this.clock);await this.federated.save(relationship);
      await this.sessions.revokeByHumanIdentityId(HumanIdentityId.from(from));
      if(failAt==="sessions") throw new Error("INJECTED_FAILURE");
      for(const type of ["authentication.method.unlinked","authentication.method.linked","authentication.google-recovery.completed"]) {
        if(failAt==="audit")throw new Error("INJECTED_AUDIT_FAILURE");
        await this.control.appendAudit({id:randomUUID(),eventType:type,actorReference:`human:${scope.target}`,subjectReference:`federated-identity:${relationship.id.value}`,eventData:{from,to,grantId,approvalReference:grant.approval,direction:grant.reverse?"reverse":"forward"},occurredAt:this.clock.now()});
      }
      await this.db.query("UPDATE recovery_test_grants SET completed=true WHERE id=$1",[grant.id]);
      return "completed";
    });
  }
  async saveSessionWithoutResurrection(stale:Session) {
    return this.fence(async()=>{const current=await this.sessions.findByIdForUpdate(stale.id);if(!current || current.status==="revoked" || !current.humanIdentityId.equals(stale.humanIdentityId))throw new Error("SESSION_REVOKED");await this.sessions.save(stale);});
  }
}
