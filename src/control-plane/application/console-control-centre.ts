import { createHash, randomUUID } from "node:crypto";
import type { AdministrationPrincipals } from "./administration-principals.js";
import type { ControlPlane } from "./control-plane.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import type { SessionRepository } from "../../sessions/ports/session-repository.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { Clock } from "../../shared/clock.js";
import { SessionId } from "../../sessions/domain/session-id.js";
import { AppError } from "../../shared/errors.js";
import type { GoogleRecoveryVerification } from "./google-recovery-verification.js";
import { integrationFacts, type AssociationKind, type HumanProductAssociation, type ProductIntegration } from "./product-integration.js";
import type { RecoveryOverviewIssue } from "./recovery-overview.js";

export interface HumanDirectoryQuery { filter?: "all"|"production"|"test"|"duplicates"|"needs_review"|"inactive"|"suspended"|"retired"|undefined; query?: string|undefined; status?: string|undefined; provider?: string|undefined; productId?: string|undefined; relationship?:AssociationKind|undefined; sort?: "name"|"created"|"activity"|"id"|undefined; cursor?: string|undefined }
export interface ConsoleHuman {
  humanIdentityId: string; preferredDisplayName: string|null; displayName: string; displayNameSource: string;
  email: string|null; status: string; createdAt: string; lastActivityAt: string|null;
  authenticationMethods: {method:string;status:string;email:string|null;emailVerified:boolean|null}[];
  memberships: {tenantId:string;tenantName:string;role:string;status:string}[];
  platformRole: string|null;
  purpose?: string; activity?: string; potentialTestCandidate?: boolean; classificationRevision?: number;
  products: {productId:string;displayName:string;participationStatus:string|null;entitlements:{tenantId:string;status:string}[]}[];
}
export interface HumanDirectoryRow extends ConsoleHuman { sortKey:string }
export interface RecoveryRequest {id:string;actorHumanIdentityId:string;sourceHumanIdentityId:string;targetHumanIdentityId:string;provider:string;reviewDigest:string;state:string;createdAt:string;updatedAt:string}
export interface ControlCentreRepository {
  insertProduct(id:string,displayName:string):Promise<boolean>;
  humans(input:HumanDirectoryQuery, after:{key:string;id:string}|null):Promise<HumanDirectoryRow[]>;
  human(id:string):Promise<ConsoleHuman|null>;
  summary():Promise<{humans:number;products:number;businesses:number;knownParticipants:number;duplicateEmailGroups:number;pendingRecoveryRequests:number;pendingVerificationCases:number;testIdentities?:number;testCandidates?:number}>;
  products():Promise<{id:string;displayName:string;status:string;participants:number;entitledHumans:number;businesses:number;workloads:number;reportingWorkloads?:number}[]>;
  activity(input:{eventType?:string|undefined;cursor?:string|undefined},after:{key:string;id:string}|null):Promise<{id:string;eventType:string;actorReference:string;subjectReference:string;productId:string|null;tenantId:string|null;occurredAt:string}[]>;
  profile(id:string):Promise<{humanIdentityId:string;preferredDisplayName:string|null;revision:number}>;
  updateProfile(id:string,name:string|null,expectedRevision:number,now:Date):Promise<boolean>;
  registerParticipation(human:string,product:string,workload:string,now:Date):Promise<boolean>;
  humanProducts(human:string,relationship:AssociationKind,after:{key:string;id:string}|null):Promise<HumanProductAssociation[]>;
  humanParticipationStatus(human:string,product:string):Promise<string|null>;
  dependencyCounts(id:string,now:Date):Promise<{activeSessions:number;renewableSessions:number;totalSessions:number;provisioningReferences:number;emailChallenges:number;appleRevocationReferences:number}>;
  requests(after:{key:string;id:string}|null):Promise<RecoveryRequest[]>;
  saveRequest(value:RecoveryRequest):Promise<void>;
  requestForUpdate(id:string):Promise<RecoveryRequest|null>;
}

export function directoryFingerprint(input:HumanDirectoryQuery) { return createHash("sha256").update(JSON.stringify([input.query?.trim().toLowerCase()??"",input.status??"",input.provider??"",input.productId??"",input.sort??"created",input.filter??"all",input.relationship??"all"])).digest("hex"); }
export function pageCursor(scope:string,key:string,id:string) { return Buffer.from(JSON.stringify({scope,key,id}),"utf8").toString("base64url"); }
export function readCursor(value:string|undefined,scope:string) {
  if (!value) return null;
  try { const c:unknown=JSON.parse(Buffer.from(value,"base64url").toString("utf8"));
    if(!c || typeof c!=="object")throw new Error();
    const p=c as Record<string,unknown>;
    if(p.scope!==scope||typeof p.key!=="string"||typeof p.id!=="string"||p.key.length>320||p.id.length>200||Object.keys(p).length!==3)throw new Error();
    return {key:p.key,id:p.id};
  }catch{throw new AppError("Refresh this list after changing its filters","INVALID_CURSOR",400);}
}
export function resolvedDisplayName(preferred:string|null,email:string|null,id:string) {
  return preferred?.trim() ? {displayName:preferred.trim(),displayNameSource:"preferred"} : email ? {displayName:email,displayNameSource:"verified_email"} : {displayName:"Name unavailable",displayNameSource:"identifier"};
}

/** Authenticated bounded administration projections; no domain lifecycle/ownership writer. */
export class ConsoleControlCentre {
  constructor(private readonly repository:ControlCentreRepository,private readonly principals:AdministrationPrincipals,
    private readonly control:ControlPlaneRepository,private readonly identities:HumanIdentityRepository,
    private readonly sessions:SessionRepository,private readonly plane:ControlPlane,private readonly clock:Clock,
    private readonly atomically:<T>(work:()=>Promise<T>)=>Promise<T>,private readonly configuredApps:readonly string[],
    private readonly scopedVerification?:GoogleRecoveryVerification,
    private readonly integrations:readonly ProductIntegration[]=[],private readonly isolatedBackfillEnabled=false,
    private readonly recoverySignals?:(session:SessionId,actor:string)=>Promise<RecoveryOverviewIssue[]>) {}
  private async session(id:SessionId,fresh=false) {
    const s=await this.sessions.findById(id);
    if(!s||s.status!=="active"||s.expiresAt<=this.clock.now())throw new AppError("Sign in to continue","SESSION_INVALID",401);
    const h=await this.identities.findById(s.humanIdentityId);
    if(h?.status!=="active")throw new AppError("This identity is unavailable","IDENTITY_UNAVAILABLE",403);
    const age=this.clock.now().getTime()-s.authenticatedAt.getTime();
    if(fresh&&(age<0||age>300_000))throw new AppError("Sign in again before making this change","REAUTHENTICATION_REQUIRED",403);
    return s;
  }
  private async admin(id:SessionId,fresh=false) {const s=await this.session(id,fresh);await this.principals.platform(s.humanIdentityId.value);return s.humanIdentityId.value;}
  private async audit(actor:string,type:string,subject:string,data:Record<string,string>={}) {
    await this.control.appendAudit({id:randomUUID(),eventType:type,actorReference:`human-identity:${actor}`,subjectReference:subject,eventData:data,occurredAt:this.clock.now()});
  }
  async directory(id:SessionId,input:HumanDirectoryQuery) {
    const actor=await this.admin(id),scope=directoryFingerprint(input);
    const rows=await this.repository.humans(input,readCursor(input.cursor,scope));
    await this.audit(actor,"platform.humans.inspected","human-directory",{resultCount:String(Math.min(rows.length,50))});
    return {humans:rows.slice(0,50).map(({sortKey,...human})=>human),nextCursor:rows.length>50?pageCursor(scope,rows[49]!.sortKey,rows[49]!.humanIdentityId):null};
  }
  async detail(id:SessionId,humanId:string) {
    const actor=await this.admin(id);const human=await this.repository.human(humanId);
    if(!human)throw new AppError("Human is unavailable","IDENTITY_NOT_FOUND",404);
    const dependencies=await this.repository.dependencyCounts(humanId,this.clock.now());
    await this.audit(actor,"platform.human.inspected",humanId);
    return {human,dependencies,externalProductDependencies:"unknown",lifecycleExecutionEnabled:false};
  }
  async productDirectory(id:SessionId) {
    const actor=await this.admin(id),products=await this.repository.products();
    await this.audit(actor,"platform.products.inspected","product-directory");
    const aliases:Record<string,readonly string[]>={"coco-the-llama":["coco-web"],cashcast:["cashcast-preview"]};
    return {products:products.map(p=>({...p,authenticationConfigurationPresent:this.configuredApps.some(a=>a===p.id||aliases[p.id]?.includes(a)),participationCoverage:(p.reportingWorkloads??p.workloads)>0?"reporting_contract_available":"no_authenticated_reporting_workload",...integrationFacts(this.integrations.find(i=>i.productId===p.id))}))};
  }
  async productHumans(id:SessionId,input:{productId:string;relationship?:AssociationKind|undefined;query?:string|undefined;cursor?:string|undefined}) {
    const actor=await this.admin(id);
    if(!await this.control.findProduct(input.productId))throw new AppError("Product is unavailable","PRODUCT_NOT_FOUND",404);
    const query:HumanDirectoryQuery={productId:input.productId,relationship:input.relationship??"participation",sort:"id",query:input.query};
    const scope=directoryFingerprint(query),rows=await this.repository.humans(query,readCursor(input.cursor,scope));
    await this.audit(actor,"platform.product.humans.inspected",input.productId,{relationship:query.relationship!,resultCount:String(Math.min(rows.length,50))});
    return {humans:rows.slice(0,50).map(({sortKey,...human})=>human),nextCursor:rows.length>50?pageCursor(scope,rows[49]!.sortKey,rows[49]!.humanIdentityId):null};
  }
  async humanProducts(id:SessionId,input:{humanIdentityId:string;relationship?:AssociationKind|undefined;cursor?:string|undefined}) {
    const actor=await this.admin(id);
    if(!await this.identities.findById(HumanIdentityId.from(input.humanIdentityId)))throw new AppError("Human is unavailable","IDENTITY_NOT_FOUND",404);
    const relationship=input.relationship??"participation",scope=`human-products:${input.humanIdentityId}:${relationship}`;
    const rows=await this.repository.humanProducts(input.humanIdentityId,relationship,readCursor(input.cursor,scope));
    await this.audit(actor,"platform.human.products.inspected",input.humanIdentityId,{relationship,resultCount:String(Math.min(rows.length,50))});
    return {products:rows.slice(0,50),nextCursor:rows.length>50?pageCursor(scope,rows[49]!.productId,rows[49]!.productId):null};
  }
  async overview(id:SessionId) {
    const actor=await this.admin(id),summary=await this.repository.summary();
    const recent=await this.repository.activity({},null);
    const issues=[];
    for(const integration of this.integrations.filter(i=>i.integrationStatus==="gama_identity"&&i.participationRecording==="missing")) {
      const product=await this.control.findProduct(integration.productId);
      if(product)issues.push({id:`participation-${product.id}`,title:"Product participation needs integration",detail:`${product.displayName} uses GAMA Identity according to reviewed evidence, but participation reporting is missing. Customer usage is not yet fully represented.`,action:"Review integration",destination:"products"});
    }
    if(this.recoverySignals)issues.push(...await this.recoverySignals(id,actor));
    if((summary.testCandidates??0)>0)issues.push({id:"test-candidates",title:"Development aliases awaiting review",detail:`${summary.testCandidates} Humans match the owner's development alias family. Purpose has not been confirmed.`,action:"Review classification",destination:"test_review"});
    if((summary.testIdentities??0)>0)issues.push({id:"test-identities",title:"Confirmed test identities",detail:`${summary.testIdentities} Humans are explicitly classified as test. Dependencies and lifecycle eligibility require separate review.`,action:"Review test identities",destination:"test_identities"});
    if(summary.duplicateEmailGroups>0)issues.push({id:"possible-duplicates",title:"Possible duplicate identities",detail:`${summary.duplicateEmailGroups} repeated email groups need review. A shared email does not establish ownership.`,action:"Review identities",destination:"duplicates"});
    if(summary.pendingRecoveryRequests>0)issues.push({id:"pending-recovery",title:"Recovery reviews pending",detail:`${summary.pendingRecoveryRequests} requests require ownership verification and dependency review.`,action:"Review recovery",destination:"recovery"});
    if(summary.pendingVerificationCases>0)issues.push({id:"pending-verification",title:"Google verification pending",detail:`${summary.pendingVerificationCases} live observation cases require fresh ownership evidence.`,action:"Review verification",destination:"verification"});
    await this.audit(actor,"platform.overview.inspected","overview");
    return {summary,issues,recentActivity:recent.slice(0,8),coverage:{productLocalDependencies:"unknown",unrecordedAuthenticationFailures:"unavailable",participation:"Only explicitly registered Human participation is counted; entitlements and business membership are separate."}};
  }
  async activity(id:SessionId,input:{eventType?:string|undefined;cursor?:string|undefined}) {
    const actor=await this.admin(id),scope=`activity:${input.eventType??""}`;
    const after=readCursor(input.cursor,scope);
    if(after&&(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(after.key)||!Number.isFinite(Date.parse(after.key))))throw new AppError("Refresh this activity list","INVALID_CURSOR",400);
    const events=await this.repository.activity(input,after);
    await this.audit(actor,"platform.activity.inspected","activity");
    return {events:events.slice(0,50),nextCursor:events.length>50?pageCursor(scope,events[49]!.occurredAt,events[49]!.id):null};
  }
  async selfProfile(id:SessionId) {const s=await this.session(id);return this.repository.profile(s.humanIdentityId.value);}
  async updateSelfProfile(id:SessionId,name:string|null,revision:number) {
    return this.atomically(async()=>{const s=await this.session(id);const actor=s.humanIdentityId.value;
      const value=name?.trim()||null;
      if(value&&(value.length>120||/[\p{Cc}\p{Cf}]/u.test(value)))throw new AppError("Use a display name of up to 120 characters without control characters","INVALID_PROFILE",400);
      if(!await this.repository.updateProfile(actor,value,revision,this.clock.now()))throw new AppError("Your profile changed. Reload it before saving","PROFILE_CONFLICT",409);
      await this.audit(actor,"human.profile.updated",actor,{preferredNamePresent:String(value!==null)});
      return this.repository.profile(actor);
    });
  }
  async participate(id:SessionId,workloadId:string,secret:string) {
    return this.atomically(async()=>{const s=await this.session(id);const workload=await this.plane.authenticateWorkload(workloadId,secret,"human.participation.register");
      if(!workload)throw new AppError("Product reporting authorization is required","WORKLOAD_INVALID",401);
      this.assertParticipationApplicable(workload.productId);
      const human=s.humanIdentityId.value;
      const created=await this.repository.registerParticipation(human,workload.productId,workload.workloadId,this.clock.now());
      if(created)await this.audit(human,"human.product.participation.registered",human,{productId:workload.productId});
      return {humanIdentityId:human,productId:workload.productId,status:"active",created};
    });
  }
  private assertParticipationApplicable(productId:string) {
    const integration=this.integrations.find(i=>i.productId===productId);
    if(integration&&["cloudkit_only","login_free","other_identity"].includes(integration.integrationStatus))throw new AppError("This product does not use GAMA Human participation","PARTICIPATION_NOT_APPLICABLE",403);
  }
  /** Called only after successful server-side web authentication for this exact configured app. */
  async participateFromWebAuthentication(id:SessionId,appId:string) {
    const integration=this.integrations.find(i=>i.webAppIds.includes(appId));
    if(!integration)return null;
    return this.atomically(async()=>{
      const s=await this.session(id),workload=await this.plane.resolveWorkloadForCapability(integration.reportingWorkloadId!,"human.participation.register");
      if(!workload||workload.status!=="active"||workload.productId!==integration.productId)throw new AppError("Product participation reporting is unavailable","PARTICIPATION_REPORTING_UNAVAILABLE",503);
      const product=await this.control.findProduct(workload.productId);
      if(product?.status!=="active")throw new AppError("Product participation reporting is unavailable","PARTICIPATION_REPORTING_UNAVAILABLE",503);
      const human=s.humanIdentityId.value,created=await this.repository.registerParticipation(human,workload.productId,workload.id,this.clock.now());
      if(created)await this.audit(human,"human.product.participation.registered",human,{productId:workload.productId,source:"verified_web_authentication",appId});
      return {humanIdentityId:human,productId:workload.productId,status:"active",created};
    });
  }
  /** Preview only: the product workload must attest canonical references; email correspondence is never used. */
  async previewParticipationBackfill(id:SessionId,workloadId:string,secret:string,entries:readonly {humanIdentityId:string;evidenceReference:string}[]) {
    const actor=await this.admin(id),workload=await this.plane.authenticateWorkload(workloadId,secret,"human.participation.backfill.preview");
    if(!workload)throw new AppError("Product reporting authorization is required","WORKLOAD_INVALID",401);
    this.assertParticipationApplicable(workload.productId);
    if(entries.length>100||entries.some(e=>!e.humanIdentityId||e.humanIdentityId.length>200||!e.evidenceReference||e.evidenceReference.length>240||/[\p{Cc}\p{Cf}]/u.test(e.evidenceReference)))throw new AppError("Canonical backfill references are invalid","INVALID_REQUEST",400);
    const rows=[];
    for(const entry of entries){
      const human=await this.identities.findById(HumanIdentityId.from(entry.humanIdentityId));
      const existing=human?await this.repository.humanParticipationStatus(entry.humanIdentityId,workload.productId):null;
      rows.push({...entry,productId:workload.productId,status:human?.status!=="active"?"human_unavailable":existing==="active"?"already_recorded":existing?"inactive_requires_review":"eligible_canonical_workload_assertion"});
    }
    await this.audit(actor,"human.product.participation.backfill.previewed",workload.productId,{referenceCount:String(rows.length),source:"product_workload_canonical_assertion"});
    return {productId:workload.productId,rows,productionExecutionAvailable:false,correspondenceAuthority:"authenticated_product_workload_assertion",warning:"Only canonical product records proven by the reporting workload may be submitted. Memberships, entitlements and email matches do not establish participation."};
  }
  /** No HTTP execution route. Strict localhost synthetic test gate supplied by the runtime. */
  async simulateParticipationBackfill(id:SessionId,workloadId:string,secret:string,entries:readonly {humanIdentityId:string;evidenceReference:string}[]) {
    if(!this.isolatedBackfillEnabled)throw new AppError("Participation backfill execution remains disabled","PARTICIPATION_BACKFILL_DISABLED",403);
    return this.atomically(async()=>{
      const actor=await this.admin(id,true),preview=await this.previewParticipationBackfill(id,workloadId,secret,entries),results=[];
      for(const row of preview.rows){
        if(!["already_recorded","eligible_canonical_workload_assertion"].includes(row.status)){results.push({...row,created:false});continue;}
        const created=await this.repository.registerParticipation(row.humanIdentityId,preview.productId,workloadId,this.clock.now());
        if(created)await this.audit(actor,"human.product.participation.backfilled",row.humanIdentityId,{productId:preview.productId,evidenceReference:row.evidenceReference,environment:"isolated_synthetic"});
        results.push({...row,created});
      }
      return {productId:preview.productId,results,environment:"isolated_synthetic"};
    });
  }
  async registerProduct(id:SessionId,input:{id:string;displayName:string}) {
    return this.atomically(async()=>{const actor=await this.admin(id,true);
      const existing=await this.control.findProduct(input.id);
      if(existing){if(existing.displayName!==input.displayName)throw new AppError("This product identifier is already registered","PRODUCT_CONFLICT",409);return existing;}
      // Repository insert rather than upsert prevents concurrent replacement of registry metadata.
      const inserted=await this.repositoryRegisterProduct(input.id,input.displayName);
      if(!inserted)throw new AppError("A product registration already exists; refresh the directory","PRODUCT_CONFLICT",409);
      await this.audit(actor,"product.registered",input.id);
      return {id:input.id,displayName:input.displayName,status:"active"};
    });
  }
  private repositoryRegisterProduct(productId:string,displayName:string) { return this.repository.insertProduct(productId,displayName); }
  async recoveryPreview(id:SessionId,input:{sourceHumanIdentityId:string;targetHumanIdentityId:string;provider:string}) {
    const actor=await this.admin(id);
    if(input.sourceHumanIdentityId===input.targetHumanIdentityId)throw new AppError("Choose two different Humans","INVALID_RECOVERY_PAIR",400);
    const [source,target]=await Promise.all([this.repository.human(input.sourceHumanIdentityId),this.repository.human(input.targetHumanIdentityId)]);
    if(!source||!target)throw new AppError("An affected Human is unavailable","IDENTITY_NOT_FOUND",404);
    const [sourceDependencies,targetDependencies]=await Promise.all([this.repository.dependencyCounts(source.humanIdentityId,this.clock.now()),this.repository.dependencyCounts(target.humanIdentityId,this.clock.now())]);
    let ownershipVerified=false,ownershipVerificationAvailable=false;
    if(input.provider==="google"&&this.scopedVerification){
      try{const v=await this.scopedVerification.administer(id,{mode:"inspect"});ownershipVerificationAvailable=v.source.humanIdentityId===source.humanIdentityId&&v.target.humanIdentityId===target.humanIdentityId;ownershipVerified=v.controlsVerified&&ownershipVerificationAvailable;}
      catch(error){if(error instanceof AppError&&["RECOVERY_SCOPE_FORBIDDEN","RECOVERY_VERIFICATION_UNAVAILABLE"].includes(error.code)){}else throw error;}
    }
    const blockers=[{code:"EXECUTION_DISABLED",message:"Recovery execution has not been enabled. This is a reviewed preview, not a completed recovery.",action:"Review the execution security policy"},
      {code:"EXTERNAL_DEPENDENCIES_UNKNOWN",message:"Product-local data, subscriptions and background jobs have not been verified.",action:"Obtain evidence from each affected product"}];
    if(!ownershipVerified)blockers.push({code:"OWNERSHIP_PROOF_REQUIRED",message:"Fresh verified control of both Humans is incomplete.",action:"Complete supported ownership verification"});
    if(!ownershipVerificationAvailable)blockers.push({code:"VERIFICATION_CEREMONY_UNAVAILABLE",message:"A reusable provider ownership verification ceremony is not enabled for this case.",action:"Implement and review the provider proof policy"});
    if(source.status!=="active"||target.status!=="active")blockers.push({code:"IDENTITY_INACTIVE",message:"Both affected Humans must be active.",action:"Review identity lifecycle"});
    if(!source.authenticationMethods.some(m=>m.method===input.provider&&m.status==="active"))blockers.push({code:"SOURCE_METHOD_UNAVAILABLE",message:"The selected authentication method is not active on the source.",action:"Review authentication relationships"});
    if(target.authenticationMethods.some(m=>m.method===input.provider&&m.status==="active"))blockers.push({code:"TARGET_PROVIDER_CONFLICT",message:"The destination already has an active method for this provider.",action:"Review the conflicting method"});
    if(source.memberships.length||source.platformRole||source.products.length||source.authenticationMethods.length!==1||Object.entries(sourceDependencies).some(([k,v])=>!k.endsWith("Sessions")&&v>0))blockers.push({code:"DEPENDENCIES_PRESENT",message:"Source relationships or retained security resources require a separate review; nothing is copied automatically.",action:"Review source dependencies"});
    if(sourceDependencies.activeSessions||sourceDependencies.renewableSessions)blockers.push({code:"SESSION_REVOCATION_APPROVAL_REQUIRED",message:"Source sessions, including renewable sessions, would need separately approved revocation.",action:"Review affected session counts"});
    if(input.provider!=="google")blockers.push({code:"PROVIDER_POLICY_UNIMPLEMENTED",message:input.provider==="apple"?"Apple audience, subject scope and revocation-grant policy require implementation.":"Email recovery requires fresh credential control and verified-email policy; matching addresses are not ownership proof.",action:"Review provider-specific recovery policy"});
    const plannedChanges=["Reassign only the verified authentication relationship after separate approval","Preserve both Humans, existing application data and destination methods","Revoke source sessions only with explicit approval","Record immutable authorization and outcome audit evidence"];
    const reviewDigest=createHash("sha256").update(JSON.stringify({source,target,sourceDependencies,targetDependencies,provider:input.provider})).digest("hex");
    await this.audit(actor,"identity.recovery.previewed",`${source.humanIdentityId}:${target.humanIdentityId}`,{provider:input.provider,reviewDigest});
    return {source,target,sourceDependencies,targetDependencies,provider:input.provider,ownershipVerified,ownershipVerificationAvailable,externalDependencies:"unknown",blockers,plannedChanges,reviewDigest,executionEnabled:false};
  }
  async recoveryRequests(id:SessionId,cursor?:string) {
    const actor=await this.admin(id),scope="recovery-requests",after=readCursor(cursor,scope);
    if(after&&(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(after.key)||!Number.isFinite(Date.parse(after.key))))throw new AppError("Refresh this recovery list","INVALID_CURSOR",400);
    const rows=await this.repository.requests(after);
    await this.audit(actor,"identity.recovery.requests.inspected","recovery-requests");
    return {requests:rows.slice(0,50),nextCursor:rows.length>50?pageCursor(scope,rows[49]!.createdAt,rows[49]!.id):null};
  }
  async createRecoveryRequest(id:SessionId,input:{sourceHumanIdentityId:string;targetHumanIdentityId:string;provider:string;requestId:string}) {
    return this.atomically(async()=>{const actor=await this.admin(id,true);
      const existing=await this.repository.requestForUpdate(input.requestId);
      if(existing){if(existing.actorHumanIdentityId!==actor||existing.sourceHumanIdentityId!==input.sourceHumanIdentityId||existing.targetHumanIdentityId!==input.targetHumanIdentityId||existing.provider!==input.provider)throw new AppError("This request reference belongs to a different review","RECOVERY_REQUEST_CONFLICT",409);await this.audit(actor,"identity.recovery.request.retried",existing.id);return existing;}
      const preview=await this.recoveryPreview(id,input);
      const now=this.clock.now().toISOString();const request={id:input.requestId,actorHumanIdentityId:actor,sourceHumanIdentityId:input.sourceHumanIdentityId,targetHumanIdentityId:input.targetHumanIdentityId,provider:input.provider,reviewDigest:preview.reviewDigest,state:"review_required",createdAt:now,updatedAt:now};
      await this.repository.saveRequest(request);await this.audit(actor,"identity.recovery.requested",request.id,{provider:input.provider,reviewDigest:preview.reviewDigest});return request;
    });
  }
  async cancelRecoveryRequest(id:SessionId,requestId:string) {
    return this.atomically(async()=>{const actor=await this.admin(id);const request=await this.repository.requestForUpdate(requestId);
      if(!request)throw new AppError("Recovery request is unavailable","RECOVERY_REQUEST_NOT_FOUND",404);
      if(request.state!=="cancelled"){request.state="cancelled";request.updatedAt=this.clock.now().toISOString();await this.repository.saveRequest(request);await this.audit(actor,"identity.recovery.cancelled",requestId);}
      return request;
    });
  }
  async rejectExecution(id:SessionId) {await this.admin(id,true);throw new AppError("Account-changing recovery and lifecycle operations remain disabled","RECOVERY_EXECUTION_DISABLED",403);}
}
