import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import type { PostgresDatabase } from "../../infrastructure/postgres/database.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import type { PasswordHasher, PasswordVerifier } from "../../authentication/credentials/ports/password-operations.js";
import { PasswordHash } from "../../authentication/credentials/domain/password.js";
import type { Clock } from "../../shared/clock.js";
import type { SessionId } from "../../sessions/domain/session-id.js";
import { AppError } from "../../shared/errors.js";
import { HUMAN_DATA_CLEANUP_CAPABILITY, MANAGED_WORKLOAD_CAPABILITIES, type ManagedWorkloadCapability } from "../models.js";

const identifier = z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u);
// The operator CLI creates 32 cryptographically random bytes; never use a human password.
const secret = z.string().regex(/^[A-Za-z0-9_-]{43}$/u).refine(value => Buffer.from(value,"base64url").length===32 && Buffer.from(value,"base64url").toString("base64url")===value && new Set(value).size>=16);
const reason = z.string().trim().min(8).max(240).regex(/^[^\p{Cc}\p{Cf}]+$/u);
const common = { requestId:z.uuid(), id:identifier, reason };
export const workloadCreateSchema = z.object({...common,productId:identifier,secret,capabilities:z.array(z.enum([...MANAGED_WORKLOAD_CAPABILITIES,HUMAN_DATA_CLEANUP_CAPABILITY])).min(1).max(3).refine(value=>new Set(value).size===value.length)}).strict();
export const workloadRotateSchema = z.object({...common,expectedRevision:z.number().int().min(1).max(2147483646),secret}).strict();
export const workloadRevokeSchema = workloadRotateSchema.omit({secret:true}).strict();
export const workloadInspectSchema = z.object({id:identifier.optional(),cursor:identifier.optional()}).strict().refine(value=>!(value.id&&value.cursor));
type Create = z.infer<typeof workloadCreateSchema>;
type Rotate = z.infer<typeof workloadRotateSchema>;
type Revoke = z.infer<typeof workloadRevokeSchema>;
export interface WorkloadMetadata { readonly id:string; readonly productId:string; readonly status:"active"|"retired"; readonly revision:number; readonly capabilities:readonly ManagedWorkloadCapability[]; readonly createdAt:string; readonly updatedAt:string }
type Row = {id:string;product_id:string;secret_hash:string;status:"active"|"retired";revision:number;capabilities:ManagedWorkloadCapability[];created_at:Date;updated_at:Date};
const digest=(value:unknown)=>createHash("sha256").update(JSON.stringify(value)).digest("hex");
function parse<T>(schema:z.ZodType<T>,value:unknown):T {const result=schema.safeParse(value);if(!result.success)throw new AppError("Invalid workload administration request","INVALID_REQUEST",400);return result.data;}
function metadata(row:Omit<Row,"secret_hash">):WorkloadMetadata {return {id:row.id,productId:row.product_id,status:row.status,revision:row.revision,capabilities:row.capabilities,createdAt:row.created_at.toISOString(),updatedAt:row.updated_at.toISOString()};}

/** Supported server-only operations. This independent gate cannot enable Human management. */
export class WorkloadAdministration {
  constructor(private readonly db:PostgresDatabase,private readonly control:ControlPlaneRepository,private readonly passwords:PasswordHasher&PasswordVerifier,private readonly clock:Clock,readonly enabled=false,private readonly cleanupProvisioningEnabled=false) {}
  private gate() {if(!this.enabled)throw new AppError("Workload administration is disabled pending separate release approval","WORKLOAD_ADMINISTRATION_DISABLED",403);}
  private async administrator(token:SessionId,lock=false):Promise<string> {
    // Read without ValidateSession: administration never touches or renews sessions.
    const result=await this.db.query<{id:string;session_status:string;expires_at:Date;authenticated_at:Date;human_status:string;membership_status:string;platform_role:string}>(`SELECT h.id,s.status AS session_status,s.expires_at,s.authenticated_at,h.status AS human_status,m.status AS membership_status,m.platform_role
      FROM sessions s JOIN human_identities h ON h.id=s.human_identity_id JOIN platform_administration_memberships m ON m.human_identity_id=h.id WHERE s.id=$1 ${lock?"FOR SHARE OF s,h,m":""}`,[token.value]);
    const row=result.rows[0],now=this.clock.now();
    if(!row||row.session_status!=="active"||row.expires_at<=now||row.human_status!=="active"||row.membership_status!=="active"||row.platform_role!=="administrator")throw new AppError("A current active Platform Administrator session is required","NOT_PLATFORM_ADMIN",403);
    const age=now.getTime()-row.authenticated_at.getTime();
    if(age<0||age>300000)throw new AppError("Fresh administrator authentication is required","FRESH_AUTHENTICATION_REQUIRED",403);
    return row.id;
  }
  private async audit(actor:string,eventType:string,subject:string,data:Record<string,string>,productId?:string) {
    await this.control.appendAudit({id:randomUUID(),eventType,actorReference:actor,subjectReference:subject,eventData:data,...(productId?{productId}:{}),occurredAt:this.clock.now()});
  }
  async inspect(token:SessionId,input:unknown) {
    this.gate(); const filter=parse(workloadInspectSchema,input); await this.administrator(token);
    if(JSON.stringify(filter).toLowerCase().includes(token.value.toLowerCase()))throw new AppError("Credentials cannot appear in workload review metadata","INVALID_REQUEST",400);
    return this.db.withTransaction(async()=>{
      const actor=await this.administrator(token,true);
      const rows=await this.db.query<Omit<Row,"secret_hash">>("SELECT id,product_id,status,revision,capabilities,created_at,updated_at FROM managed_product_workloads WHERE ($1::text IS NULL OR id=$1) AND ($2::text IS NULL OR id COLLATE \"C\">$2 COLLATE \"C\") ORDER BY id COLLATE \"C\" LIMIT 51",[filter.id??null,filter.cursor??null]);
      await this.audit(actor,"workload.managed.inspected",filter.id??"managed-workloads",{resultCount:String(Math.min(rows.rows.length,50))});
      return {workloads:rows.rows.slice(0,50).map(metadata),nextCursor:rows.rows.length>50?rows.rows[49]!.id:null,legacyPolicy:"Legacy workloads are preserved and cannot be changed through this API."};
    });
  }
  async create(token:SessionId,input:unknown) {return this.mutate(token,"create",parse(workloadCreateSchema,input));}
  async rotate(token:SessionId,input:unknown) {return this.mutate(token,"rotate",parse(workloadRotateSchema,input));}
  async revoke(token:SessionId,input:unknown) {return this.mutate(token,"revoke",parse(workloadRevokeSchema,input));}
  private async mutate(token:SessionId,operation:"create"|"rotate"|"revoke",input:Create|Rotate|Revoke):Promise<{workload:WorkloadMetadata;replayed:boolean}> {
    this.gate();await this.administrator(token);
    if (operation === "create" && "capabilities" in input && input.capabilities.includes(HUMAN_DATA_CLEANUP_CAPABILITY) && !this.cleanupProvisioningEnabled) throw new AppError("Cleanup authority requires separate enabled Human administration","CLEANUP_PROVISIONING_DISABLED",403);
    const reviewMetadata=JSON.stringify({...input,secret:undefined});
    if(reviewMetadata.toLowerCase().includes(token.value.toLowerCase())||("secret" in input&&reviewMetadata.includes(input.secret)))throw new AppError("Credentials cannot appear in workload review metadata","INVALID_REQUEST",400);
    return this.db.withTransaction(async()=>{
      const actor=await this.administrator(token,true);
      const command={...input,...("capabilities" in input?{capabilities:[...input.capabilities].sort()}:{}),...("secret" in input?{secret:digest(input.secret)}:{})};
      const intent=digest({actor,operation,command});
      await this.db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",[`managed-workload-request:${input.requestId}`]);
      const prior=await this.db.query<{actor_human_identity_id:string;operation:string;intent_digest:string;result:WorkloadMetadata}>("SELECT actor_human_identity_id,operation,intent_digest,result FROM managed_workload_operations WHERE request_id=$1",[input.requestId]);
      if(prior.rows[0]) {
        const p=prior.rows[0];if(p.actor_human_identity_id!==actor||p.operation!==operation||p.intent_digest!==intent)throw new AppError("The operation request identifier is already bound to another command","IDEMPOTENCY_KEY_REUSED",409);
        return {workload:p.result,replayed:true};
      }
      await this.db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",[`workload-namespace:${input.id}`]);
      const legacy=await this.control.findWorkload(input.id);
      if(legacy||input.id==="coco-backend")throw new AppError("Legacy workload identities are preserved; use a new dedicated reporting workload identifier","LEGACY_WORKLOAD_PROTECTED",409);
      const existing=(await this.db.query<Row>("SELECT * FROM managed_product_workloads WHERE id=$1 FOR UPDATE",[input.id])).rows[0];
      const productId=operation==="create"?(input as Create).productId:existing?.product_id;
      if(!productId)throw new AppError("Managed workload not found","WORKLOAD_NOT_FOUND",404);
      const product=(await this.db.query<{status:string}>("SELECT status FROM registered_products WHERE id=$1 FOR SHARE",[productId])).rows[0];
      // Revocation remains available when a product is inactive; create/rotate require active registration.
      if(!product||(operation!=="revoke"&&product.status!=="active"))throw new AppError("An active registered product is required","PRODUCT_NOT_AVAILABLE",409);
      const now=this.clock.now();
      if(operation==="create") {
        if(existing)throw new AppError("The workload identifier is already registered","WORKLOAD_CONFLICT",409);
        const c=input as Create;
        await this.db.query("INSERT INTO managed_product_workloads(id,product_id,secret_hash,status,revision,capabilities,created_at,updated_at) VALUES($1,$2,$3,'active',1,$4,$5,$5)",[c.id,c.productId,(await this.passwords.hash(c.secret)).value,[...c.capabilities].sort(),now]);
      } else {
        const c=input as Rotate|Revoke;
        if(!existing||existing.status!=="active")throw new AppError("The workload is revoked and cannot be reactivated","WORKLOAD_REVOKED",409);
        if(existing.revision!==c.expectedRevision)throw new AppError("The workload changed; inspect its current revision before proceeding","WORKLOAD_REVISION_CONFLICT",409);
        if(operation==="rotate") {
          const r=input as Rotate;
          if(await this.passwords.verify(r.secret,PasswordHash.from(existing.secret_hash)))throw new AppError("Rotation requires a new generated secret","WORKLOAD_SECRET_UNCHANGED",409);
          await this.db.query("UPDATE managed_product_workloads SET secret_hash=$2,revision=revision+1,updated_at=$3 WHERE id=$1",[r.id,(await this.passwords.hash(r.secret)).value,now]);
        } else await this.db.query("UPDATE managed_product_workloads SET status='retired',revision=revision+1,updated_at=$2 WHERE id=$1",[input.id,now]);
      }
      const result=metadata((await this.db.query<Omit<Row,"secret_hash">>("SELECT id,product_id,status,revision,capabilities,created_at,updated_at FROM managed_product_workloads WHERE id=$1",[input.id])).rows[0]!);
      await this.audit(actor,`workload.managed.${operation==="create"?"created":operation==="rotate"?"rotated":"revoked"}`,input.id,{requestId:input.requestId,revision:String(result.revision),reason:input.reason,capabilities:result.capabilities.join(","),status:result.status},result.productId);
      await this.db.query("INSERT INTO managed_workload_operations(request_id,actor_human_identity_id,operation,intent_digest,result,created_at) VALUES($1,$2,$3,$4,$5,$6)",[input.requestId,actor,operation,intent,JSON.stringify(result),now]);
      return {workload:result,replayed:false};
    });
  }
}
