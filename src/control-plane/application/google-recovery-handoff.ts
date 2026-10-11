import { createHash, randomBytes, randomUUID } from "node:crypto";
import { z } from "zod";
import type { PostgresDatabase } from "../../infrastructure/postgres/database.js";
import type { IdentityManagement } from "./identity-management.js";
import { digest } from "./identity-management.js";
import type { SessionRepository } from "../../sessions/ports/session-repository.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import { SessionId } from "../../sessions/domain/session-id.js";
import type { AdministrationPrincipals } from "./administration-principals.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import type { Clock } from "../../shared/clock.js";
import { AppError } from "../../shared/errors.js";
import { GoogleWebAuthorizationCodeExchanger } from "../../authentication/federated/adapters/google-authorization-code-exchanger.js";

export const googleRecoveryHandoffConfigSchema = z.object({
  clientId: z.string().min(1).max(300), clientSecret: z.string().min(1).max(4096),
  redirectUri: z.url().refine(value => { const u = new URL(value); return u.protocol === "https:" && u.pathname === "/authentication/recovery/google/callback" && !u.search && !u.hash && !u.username && !u.password; }),
}).strict();
export type GoogleRecoveryHandoffConfig = z.infer<typeof googleRecoveryHandoffConfigSchema>;
type HandoffRow = { case_kind: "recovery"|"compensation"; id: string; case_id: string; actor_id: string; target_id: string; admin_session_hash: string; target_session_hash: string; code_verifier: string | null; state: string; expires_at: Date };
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
function fail(code: string, message: string, status = 409): never { throw new AppError(message, code, status); }

/** OAuth browser handoff contains no provider token, raw subject or bearer in a URL or persisted row. */
export class GoogleRecoveryHandoff {
  private readonly exchanger: GoogleWebAuthorizationCodeExchanger | undefined;
  constructor(private readonly db: PostgresDatabase, private readonly management: IdentityManagement,
    private readonly sessions: SessionRepository, private readonly humans: HumanIdentityRepository,
    private readonly principals: AdministrationPrincipals, private readonly plane: ControlPlaneRepository,
    private readonly clock: Clock, private readonly config: GoogleRecoveryHandoffConfig | undefined,
    request?: typeof fetch) {
      this.exchanger = config ? new GoogleWebAuthorizationCodeExchanger({...config, ...(request ? {request} : {})}) : undefined;
  }
  private gate() {
    if (!this.management.executionEnabled) fail("IDENTITY_MANAGEMENT_DISABLED", "Production recovery verification remains disabled.", 403);
    if (!this.config || !this.exchanger) fail("GOOGLE_HANDOFF_NOT_CONFIGURED", "A dedicated registered Google callback is required before browser verification is available.", 503);
  }
  private async owner(id: SessionId) {
    const s = await this.sessions.findById(id), now = this.clock.now();
    if (!s || s.status !== "active" || s.expiresAt <= now || now.getTime() - s.authenticatedAt.getTime() < 0 || now.getTime() - s.authenticatedAt.getTime() > 300000 || (await this.humans.findById(s.humanIdentityId))?.status !== "active")
      fail("REAUTHENTICATION_REQUIRED", "Fresh sign-in through an existing method is required.", 403);
    return s;
  }
  private async audit(actor: string, eventType: string, subject: string) {
    await this.plane.appendAudit({id: randomUUID(), eventType, actorReference: `human-identity:${actor}`, subjectReference: subject, eventData: {}, occurredAt: this.clock.now()});
  }
  async start(adminToken: SessionId, input: {caseId: string; targetSession: string; kind?:"recovery"|"compensation"|undefined}) {
    const admin = await this.owner(adminToken); await this.principals.platform(admin.humanIdentityId.value); this.gate();
    return this.db.withIdentityManagementTransaction(async () => {
      const current = await this.owner(adminToken); await this.principals.platform(current.humanIdentityId.value);
      const target = await this.owner(SessionId.from(input.targetSession));
      const kind = input.kind ?? "recovery";
      const sql = kind === "recovery" ? "SELECT * FROM identity_management_cases WHERE id=$1 FOR UPDATE" : "SELECT c.*,o.result->>'targetHumanIdentityId' AS target_human_identity_id FROM identity_recovery_compensations c JOIN identity_management_operations o ON o.id=c.original_request_id WHERE c.id=$1 FOR UPDATE OF c";
      const r = await this.db.query<{actor_human_identity_id:string; target_human_identity_id:string; nonce:string; state:string; created_at:Date; expires_at:Date}>(sql, [input.caseId]), c = r.rows[0], now = this.clock.now();
      if (!c || c.actor_human_identity_id !== current.humanIdentityId.value) fail("RECOVERY_NOT_FOUND", "Recovery case not found.", 404);
      if (c.state !== "awaiting_proof" || c.expires_at <= now || target.humanIdentityId.value !== c.target_human_identity_id || target.authenticatedAt < c.created_at) fail("CONTROL_INVALID", "Freshly authenticate the selected primary after preparing this case.");
      const state = randomBytes(32).toString("base64url"), verifier = randomBytes(32).toString("base64url"), id = randomUUID(), expires = new Date(Math.min(now.getTime()+300000,c.expires_at.getTime()));
      await this.db.query("UPDATE identity_management_google_handoffs SET state='cancelled',code_verifier=NULL WHERE case_id=$1 AND case_kind=$2 AND state='awaiting_callback'", [input.caseId,kind]);
      await this.db.query("INSERT INTO identity_management_google_handoffs(id,case_id,actor_id,target_id,admin_session_hash,target_session_hash,state_digest,code_verifier,state,created_at,expires_at,case_kind,recovery_case_id,compensation_case_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'awaiting_callback',$9,$10,$11,$12,$13)", [id,input.caseId,current.humanIdentityId.value,target.humanIdentityId.value,digest(current.id.value),digest(target.id.value),hash(state),verifier,now,expires,kind,kind === "recovery" ? input.caseId : null,kind === "compensation" ? input.caseId : null]);
      const url = new URL("https://accounts.google.com/o/oauth2/v2/auth"); url.search = new URLSearchParams({client_id:this.config!.clientId,redirect_uri:this.config!.redirectUri,response_type:"code",scope:"openid email",nonce:c.nonce,state,code_challenge:createHash("sha256").update(verifier).digest("base64url"),code_challenge_method:"S256",prompt:"select_account",max_age:"0"}).toString();
      await this.audit(current.humanIdentityId.value,"recovery.google-handoff.started",id);
      return {handoffId:id,caseId:input.caseId,authorizationURL:url.toString(),callbackScheme:"gamaconsole",expiresAt:expires.toISOString()};
    });
  }
  private async referencedSession(human: string, hashed: string) {
    const sessions = await this.sessions.listByHumanIdentityId(HumanIdentityId.from(human));
    const s = sessions.find(s => digest(s.id.value) === hashed);
    if (!s) fail("CONTROL_INVALID", "Verification session is unavailable.");
    return this.owner(s.id);
  }
  async callback(input: {state:string;code?:string|undefined;error?:string|undefined}) {
    this.gate();
    const row = await this.db.withIdentityManagementTransaction(async () => {
      const result = await this.db.query<HandoffRow>("SELECT * FROM identity_management_google_handoffs WHERE state_digest=$1 FOR UPDATE", [hash(input.state)]), r = result.rows[0];
      if (!r || r.state !== "awaiting_callback" || r.expires_at <= this.clock.now()) fail("HANDOFF_EXPIRED_OR_USED", "Start a new browser verification.");
      await this.db.query("UPDATE identity_management_google_handoffs SET state='processing',code_verifier=NULL WHERE id=$1", [r.id]);
      return r;
    });
    let state = "failed";
    try {
      if (input.error || !input.code || !row.code_verifier) fail("GOOGLE_AUTHORIZATION_CANCELLED", "Google verification was not completed.");
      const admin = await this.referencedSession(row.actor_id,row.admin_session_hash); await this.principals.platform(admin.humanIdentityId.value);
      const target = await this.referencedSession(row.target_id,row.target_session_hash);
      const identityToken = await this.exchanger!.exchange({authorizationCode:input.code,codeVerifier:row.code_verifier});
      if (row.case_kind === "compensation") await this.management.proveCompensation(admin.id,{caseId:row.case_id,targetSession:target.id.value,identityToken});
      else await this.management.proveNativeRecovery(admin.id,{caseId:row.case_id,targetSession:target.id.value,identityToken});
      state = "verified";
    } catch { state = "failed"; }
    await this.db.withIdentityManagementTransaction(async () => {
      await this.db.query("UPDATE identity_management_google_handoffs SET state=$2,code_verifier=NULL WHERE id=$1 AND state='processing'", [row.id,state]);
      await this.audit(row.actor_id,state === "verified" ? "recovery.google-handoff.verified" : "recovery.google-handoff.failed",row.id);
    });
    return {handoffId:row.id,state};
  }
  async result(adminToken: SessionId, id: string) {
    const admin = await this.owner(adminToken); await this.principals.platform(admin.humanIdentityId.value); this.gate();
    return this.db.withIdentityManagementTransaction(async () => {
      const r = await this.db.query<HandoffRow>("SELECT * FROM identity_management_google_handoffs WHERE id=$1 AND actor_id=$2 FOR UPDATE",[id,admin.humanIdentityId.value]), row = r.rows[0];
      if (!row) fail("HANDOFF_NOT_FOUND","Browser verification not found.",404);
      if (row.state === "awaiting_callback" && row.expires_at <= this.clock.now()) {
        await this.db.query("UPDATE identity_management_google_handoffs SET state='failed',code_verifier=NULL WHERE id=$1", [row.id]);
        await this.audit(row.actor_id, "recovery.google-handoff.expired", row.id);
        row.state = "failed";
      }
      if (row.state === "processing") {
        // A callback may lose its response after proof committed. Reconcile only the exact case and target proof.
        const sql = row.case_kind === "compensation" ? "SELECT 1 FROM identity_recovery_compensations WHERE id=$1 AND actor_human_identity_id=$2 AND state IN ('verified','completed') AND target_session_hash=$3 AND proof_expires_at>$4" : "SELECT 1 FROM identity_management_cases c JOIN identity_management_control_proofs p ON p.case_id=c.id WHERE c.id=$1 AND c.actor_human_identity_id=$2 AND c.state IN ('verified','completed') AND p.session_hash=$3 AND p.human_identity_id=$5 AND p.proof_kind='session' AND p.expires_at>$4 AND c.proof_expires_at>$4";
        const params = row.case_kind === "compensation" ? [row.case_id,row.actor_id,row.target_session_hash,this.clock.now()] : [row.case_id,row.actor_id,row.target_session_hash,this.clock.now(),row.target_id];
        const proof = await this.db.query(sql,params);
        if (proof.rows.length) row.state = "verified";
        else if (row.expires_at <= this.clock.now()) row.state = "failed";
        if (row.state !== "processing") { await this.db.query("UPDATE identity_management_google_handoffs SET state=$2,code_verifier=NULL WHERE id=$1",[row.id,row.state]); await this.audit(row.actor_id,"recovery.google-handoff.reconciled",row.id); }
      }
      return {handoffId:row.id,caseId:row.case_id,state:row.expires_at <= this.clock.now() && row.state === "awaiting_callback" ? "expired" : row.state,expiresAt:row.expires_at.toISOString()};
    });
  }
}
