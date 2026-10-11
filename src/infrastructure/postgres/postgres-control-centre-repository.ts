import { AppError } from "../../shared/errors.js";
import type { DatabaseQuery } from "./database.js";
import type { ConsoleHuman, ControlCentreRepository, HumanDirectoryQuery, HumanDirectoryRow, RecoveryRequest } from "../../control-plane/application/console-control-centre.js";
import { resolvedDisplayName } from "../../control-plane/application/console-control-centre.js";

// Explicit projections only. No password hash, provider subject or token column is selected.
const verifiedEmail=`coalesce((SELECT normalized_email FROM credentials WHERE human_identity_id=h.id AND email_verified_at IS NOT NULL AND status='active' ORDER BY created_at LIMIT 1),
 (SELECT provider_email FROM federated_identities WHERE human_identity_id=h.id AND provider_email_verified=true AND status='active' ORDER BY created_at LIMIT 1))`;
const dateSQL=(value:string)=>`to_char(${value} AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const selectedHuman=`SELECT h.id,h.status,h.created_at,p.preferred_display_name,${verifiedEmail} AS email,
 (SELECT max(last_accessed_at) FROM sessions WHERE human_identity_id=h.id) AS last_activity
 FROM human_identities h LEFT JOIN human_profiles p ON p.human_identity_id=h.id`;
const projection=`SELECT h.id AS "humanIdentityId",h.status,h.preferred_display_name AS "preferredDisplayName",h.email,
 ${dateSQL('h.created_at')} AS "createdAt",${dateSQL('h.last_activity')} AS "lastActivityAt",
 coalesce((SELECT json_agg(json_build_object('method',m.method,'status',m.status,'email',m.email,'emailVerified',m.verified) ORDER BY m.method,m.created_at) FROM (
 SELECT 'email_password' AS method,status,normalized_email AS email,email_verified_at IS NOT NULL AS verified,created_at FROM credentials WHERE human_identity_id=h.id
 UNION ALL SELECT provider AS method,status,provider_email AS email,provider_email_verified AS verified,created_at FROM federated_identities WHERE human_identity_id=h.id) m),'[]'::json) AS "authenticationMethods",
 coalesce((SELECT json_agg(json_build_object('tenantId',m.tenant_id,'tenantName',t.display_name,'role',m.tenant_role,'status',m.status) ORDER BY m.tenant_id) FROM tenant_memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.human_identity_id=h.id),'[]'::json) AS memberships,
 (SELECT platform_role||CASE WHEN status='active' THEN '' ELSE ' ('||status||')' END FROM platform_administration_memberships WHERE human_identity_id=h.id) AS "platformRole",
 coalesce((SELECT json_agg(json_build_object('productId',p.id,'displayName',p.display_name,'participationStatus',(SELECT status FROM human_product_participations WHERE human_identity_id=h.id AND product_id=p.id),
 'entitlements',coalesce((SELECT json_agg(json_build_object('tenantId',tenant_id,'status',status) ORDER BY tenant_id) FROM product_entitlements WHERE human_identity_id=h.id AND product_id=p.id),'[]'::json)) ORDER BY p.id)
 FROM registered_products p WHERE EXISTS(SELECT 1 FROM human_product_participations WHERE human_identity_id=h.id AND product_id=p.id) OR EXISTS(SELECT 1 FROM product_entitlements WHERE human_identity_id=h.id AND product_id=p.id)),'[]'::json) AS products`;
const requestProjection=`id,actor_human_identity_id AS "actorHumanIdentityId",source_human_identity_id AS "sourceHumanIdentityId",target_human_identity_id AS "targetHumanIdentityId",provider,review_digest AS "reviewDigest",state,${dateSQL('created_at')} AS "createdAt",${dateSQL('updated_at')} AS "updatedAt"`;
function human(row:Omit<ConsoleHuman,'displayName'|'displayNameSource'>):ConsoleHuman {return {...row,...resolvedDisplayName(row.preferredDisplayName,row.email,row.humanIdentityId)};}

export class PostgresControlCentreRepository implements ControlCentreRepository {
 constructor(private readonly db:DatabaseQuery) {}
 async insertProduct(id:string,name:string) {const r=await this.db.query("INSERT INTO registered_products(id,display_name,status) VALUES($1,$2,'active') ON CONFLICT(id) DO NOTHING",[id,name]);return r.rowCount===1;}
 async humans(input:HumanDirectoryQuery,after:{key:string;id:string}|null) {
  const sort=input.sort??"created",descending=sort==='created'||sort==='activity';
  const key=sort==='id'?'id':sort==='name'?"lower(coalesce(preferred_display_name,email,'Human '||substring(id,1,8)))":sort==='created'?dateSQL('created_at'):`coalesce(${dateSQL('last_activity')},'')`;
  const r=await this.db.query<HumanDirectoryRow>(`WITH metadata AS (${selectedHuman}), candidates AS (SELECT *,${key} AS sort_key FROM metadata), selected AS (
    SELECT * FROM candidates h WHERE ($1='' OR strpos(lower(h.id),$1)>0 OR strpos(lower(coalesce(h.preferred_display_name,'')),$1)>0 OR EXISTS(SELECT 1 FROM credentials WHERE human_identity_id=h.id AND strpos(lower(normalized_email),$1)>0) OR EXISTS(SELECT 1 FROM federated_identities WHERE human_identity_id=h.id AND strpos(lower(coalesce(provider_email,'')),$1)>0))
    AND ($2='' OR status=$2) AND ($3='' OR ($3='email_password' AND EXISTS(SELECT 1 FROM credentials WHERE human_identity_id=h.id AND status='active')) OR EXISTS(SELECT 1 FROM federated_identities WHERE human_identity_id=h.id AND provider=$3 AND status='active'))
    AND ($4='' OR EXISTS(SELECT 1 FROM human_product_participations WHERE human_identity_id=h.id AND product_id=$4) OR EXISTS(SELECT 1 FROM product_entitlements WHERE human_identity_id=h.id AND product_id=$4))
    AND ($5::text IS NULL OR (sort_key COLLATE "C",id COLLATE "C") ${descending?'<':'>'} ($5 COLLATE "C",$6 COLLATE "C"))
    ORDER BY sort_key COLLATE "C" ${descending?'DESC':'ASC'},id COLLATE "C" ${descending?'DESC':'ASC'} LIMIT 51)
   ${projection},h.sort_key AS "sortKey" FROM selected h ORDER BY h.sort_key COLLATE "C" ${descending?'DESC':'ASC'},h.id COLLATE "C" ${descending?'DESC':'ASC'}`,
   [input.query?.trim().toLowerCase()??'',input.status??'',input.provider??'',input.productId??'',after?.key??null,after?.id??null]);
  return r.rows.map(row=>({...human(row),sortKey:row.sortKey}));
 }
 async human(id:string) {const r=await this.db.query<ConsoleHuman>(`WITH selected AS (${selectedHuman} WHERE h.id=$1) ${projection} FROM selected h`,[id]);return r.rows[0]?human(r.rows[0]):null;}
 async summary() {
  const r=await this.db.query<Record<string,string>>(`SELECT
   (SELECT count(*) FROM human_identities) AS humans,(SELECT count(*) FROM registered_products) AS products,(SELECT count(*) FROM tenants) AS businesses,
   (SELECT count(DISTINCT human_identity_id) FROM human_product_participations WHERE status='active') AS "knownParticipants",
   (SELECT count(*) FROM (SELECT lower(trim(email)) FROM (SELECT human_identity_id,normalized_email AS email FROM credentials UNION ALL SELECT human_identity_id,provider_email AS email FROM federated_identities WHERE provider_email IS NOT NULL) e GROUP BY lower(trim(email)) HAVING count(DISTINCT human_identity_id)>1) duplicates) AS "duplicateEmailGroups",
   (SELECT count(*) FROM identity_recovery_requests WHERE state='review_required') AS "pendingRecoveryRequests",
   (SELECT count(*) FROM google_identity_verification_cases WHERE payload->>'state'='awaiting_proof' AND (payload->>'expiresAt')::timestamptz>now()) AS "pendingVerificationCases"`);
  const row=r.rows[0]!;return {humans:Number(row.humans),products:Number(row.products),businesses:Number(row.businesses),knownParticipants:Number(row.knownParticipants),duplicateEmailGroups:Number(row.duplicateEmailGroups),pendingRecoveryRequests:Number(row.pendingRecoveryRequests),pendingVerificationCases:Number(row.pendingVerificationCases)};
 }
 async products() {
  const r=await this.db.query<{id:string;displayName:string;status:string;participants:number;entitledHumans:number;businesses:number;workloads:number}>(`SELECT p.id,p.display_name AS "displayName",p.status,
   (SELECT count(*)::int FROM human_product_participations WHERE product_id=p.id AND status='active') AS participants,
   (SELECT count(DISTINCT human_identity_id)::int FROM product_entitlements WHERE product_id=p.id AND status='active') AS "entitledHumans",
   (SELECT count(*)::int FROM product_participations WHERE product_id=p.id AND status='active') AS businesses,
   (SELECT count(*)::int FROM product_workloads WHERE product_id=p.id AND status='active') AS workloads
   FROM registered_products p ORDER BY p.display_name,p.id`);return r.rows;
 }
 async activity(input:{eventType?:string|undefined},after:{key:string;id:string}|null) {
  const r=await this.db.query<{id:string;eventType:string;actorReference:string;subjectReference:string;productId:string|null;tenantId:string|null;occurredAt:string}>(`SELECT id,event_type AS "eventType",actor_reference AS "actorReference",subject_reference AS "subjectReference",product_id AS "productId",tenant_id AS "tenantId",${dateSQL('occurred_at')} AS "occurredAt" FROM platform_audit_events
   WHERE ($1='' OR event_type=$1) AND ($2::timestamptz IS NULL OR (occurred_at,id COLLATE "C") < ($2::timestamptz,$3 COLLATE "C")) ORDER BY occurred_at DESC,id COLLATE "C" DESC LIMIT 51`,[input.eventType??'',after?.key??null,after?.id??null]);return r.rows;
 }
 async profile(id:string) {const r=await this.db.query<{humanIdentityId:string;preferredDisplayName:string|null;revision:number}>(`SELECT h.id AS "humanIdentityId",p.preferred_display_name AS "preferredDisplayName",coalesce(p.revision,0) AS revision FROM human_identities h LEFT JOIN human_profiles p ON p.human_identity_id=h.id WHERE h.id=$1`,[id]);return r.rows[0]!;}
 async updateProfile(id:string,name:string|null,revision:number,now:Date) {
  const r=revision===0?await this.db.query("INSERT INTO human_profiles(human_identity_id,preferred_display_name,revision,updated_at) VALUES($1,$2,1,$3) ON CONFLICT(human_identity_id) DO NOTHING",[id,name,now]):await this.db.query("UPDATE human_profiles SET preferred_display_name=$2,revision=revision+1,updated_at=$3 WHERE human_identity_id=$1 AND revision=$4",[id,name,now,revision]);return r.rowCount===1;
 }
 async registerParticipation(id:string,product:string,workload:string,now:Date) {
  const r=await this.db.query("INSERT INTO human_product_participations(human_identity_id,product_id,workload_id,status,created_at,updated_at) VALUES($1,$2,$3,'active',$4,$4) ON CONFLICT(human_identity_id,product_id) DO NOTHING",[id,product,workload,now]);
  if(r.rowCount===0){const existing=await this.db.query<{status:string}>("SELECT status FROM human_product_participations WHERE human_identity_id=$1 AND product_id=$2",[id,product]);if(existing.rows[0]?.status!=='active')throw new AppError('This participation is inactive and requires separate review','PARTICIPATION_INACTIVE',409);}
  return r.rowCount===1;
 }
 async dependencyCounts(id:string,now:Date) {
  const r=await this.db.query<{activeSessions:number;renewableSessions:number;totalSessions:number;provisioningReferences:number;emailChallenges:number;appleRevocationReferences:number}>(`SELECT
  (SELECT count(*)::int FROM sessions WHERE human_identity_id=$1 AND status='active' AND expires_at>$2) AS "activeSessions",
  (SELECT count(*)::int FROM sessions WHERE human_identity_id=$1 AND status<>'revoked' AND renewal_expires_at>$2 AND renewal_token_hash IS NOT NULL) AS "renewableSessions",
  (SELECT count(*)::int FROM sessions WHERE human_identity_id=$1) AS "totalSessions",
  (SELECT count(*)::int FROM tenant_provisioning_requests WHERE initial_owner_human_identity_id=$1) AS "provisioningReferences",
  (SELECT count(*)::int FROM email_action_challenges a JOIN credentials c ON c.id=a.credential_id WHERE c.human_identity_id=$1) AS "emailChallenges",
  (SELECT count(*)::int FROM product_apple_revocations WHERE human_identity_id=$1) AS "appleRevocationReferences"`,[id,now]);return r.rows[0]!;
 }
 async requests(after:{key:string;id:string}|null) {const r=await this.db.query<RecoveryRequest>(`SELECT ${requestProjection} FROM identity_recovery_requests WHERE ($1::timestamptz IS NULL OR (created_at,id::text COLLATE "C")<($1::timestamptz,$2 COLLATE "C")) ORDER BY created_at DESC,id::text COLLATE "C" DESC LIMIT 51`,[after?.key??null,after?.id??null]);return r.rows;}
 async requestForUpdate(id:string) {await this.db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,710014))',[id]);const r=await this.db.query<RecoveryRequest>(`SELECT ${requestProjection} FROM identity_recovery_requests WHERE id=$1 FOR UPDATE`,[id]);return r.rows[0]??null;}
 async saveRequest(r:RecoveryRequest) {await this.db.query(`INSERT INTO identity_recovery_requests(id,actor_human_identity_id,source_human_identity_id,target_human_identity_id,provider,state,created_at,updated_at,review_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET state=EXCLUDED.state,updated_at=EXCLUDED.updated_at`,[r.id,r.actorHumanIdentityId,r.sourceHumanIdentityId,r.targetHumanIdentityId,r.provider,r.state,r.createdAt,r.updatedAt,r.reviewDigest]);}
}
