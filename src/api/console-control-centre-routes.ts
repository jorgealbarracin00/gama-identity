import type { FastifyPluginAsync,FastifyRequest } from "fastify";
import { z } from "zod";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import { AdministrationAuthorizationError } from "../control-plane/application/administration-principals.js";
import type { IdentityServices } from "./services.js";
const cursor=z.string().min(1).max(2048).optional();
const identifier=z.string().trim().min(1).max(200);
const pair=z.object({sourceHumanIdentityId:identifier,targetHumanIdentityId:identifier,provider:z.enum(['google','apple','email_password'])}).strict();
const directory=z.object({query:z.string().trim().max(320).optional(),status:z.enum(['active','suspended','retired']).optional(),provider:z.enum(['google','apple','email_password']).optional(),productId:identifier.optional(),sort:z.enum(['name','created','activity','id']).optional(),cursor}).strict();
function session(request:FastifyRequest) {const m=/^Bearer ([^\s]+)$/.exec(request.headers.authorization??'');if(!m?.[1])throw new AppError('Sign in to continue','SESSION_INVALID',401);return SessionId.from(m[1]);}
function parse<T>(schema:z.ZodType<T>,value:unknown):T {const p=schema.safeParse(value);if(!p.success)throw new AppError('The request is invalid','INVALID_REQUEST',400);return p.data;}
export function consoleControlCentreRoutes(services:IdentityServices):FastifyPluginAsync {return async(app)=>{
 const handle=async(request:FastifyRequest,reply:{header:(a:string,b:string)=>unknown},work:(centre:NonNullable<IdentityServices['administration']['controlCentre']>,id:SessionId)=>Promise<unknown>)=>{
  reply.header('Cache-Control','no-store');const id=session(request);const centre=services.administration.controlCentre;
  if(!centre)throw new AppError('Control centre is unavailable','CONTROL_CENTRE_UNAVAILABLE',503);
  try{return await work(centre,id);}catch(error){if(error instanceof AdministrationAuthorizationError)throw new AppError('Platform Administrator access is required',error.code,403);throw error;}
 };
 app.post('/administration/platform/overview',async(req,rep)=>handle(req,rep,(c,id)=>{parse(z.object({}).strict(),req.body??{});return c.overview(id);}));
 app.post('/administration/platform/humans/query',async(req,rep)=>handle(req,rep,(c,id)=>c.directory(id,parse(directory,req.body))));
 app.post('/administration/platform/humans/details',async(req,rep)=>handle(req,rep,(c,id)=>c.detail(id,parse(z.object({humanIdentityId:identifier}).strict(),req.body).humanIdentityId)));
 app.post('/administration/platform/products/inspect',async(req,rep)=>handle(req,rep,(c,id)=>{parse(z.object({}).strict(),req.body??{});return c.productDirectory(id);}));
 app.post('/administration/platform/products/register',async(req,rep)=>handle(req,rep,(c,id)=>c.registerProduct(id,parse(z.object({id:z.string().regex(/^[a-z][a-z0-9-]{0,63}$/),displayName:z.string().trim().min(1).max(160).regex(/^[^\p{Cc}\p{Cf}]+$/u)}).strict(),req.body))));
 app.post('/administration/platform/activity/query',async(req,rep)=>handle(req,rep,(c,id)=>c.activity(id,parse(z.object({eventType:z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/).optional(),cursor}).strict(),req.body))));
 app.get('/profile',async(req,rep)=>handle(req,rep,(c,id)=>c.selfProfile(id)));
 app.put('/profile',async(req,rep)=>handle(req,rep,(c,id)=>{const input=parse(z.object({preferredDisplayName:z.string().trim().max(120).nullable(),expectedRevision:z.number().int().min(0).max(2147483646)}).strict(),req.body);return c.updateSelfProfile(id,input.preferredDisplayName,input.expectedRevision);}));
 app.post('/control/human-participation',async(req,rep)=>handle(req,rep,(c,id)=>{
  parse(z.object({}).strict(),req.body??{});const workload=req.headers['x-gama-workload-id'],secret=req.headers['x-gama-workload-secret'];
  if(typeof workload!=='string'||typeof secret!=='string'||workload.length>200||secret.length>4096)throw new AppError('Product reporting authorization is required','WORKLOAD_INVALID',401);
  return c.participate(id,workload,secret);
 }));
 app.post('/administration/platform/recovery/preview',async(req,rep)=>handle(req,rep,(c,id)=>c.recoveryPreview(id,parse(pair,req.body))));
 app.post('/administration/platform/recovery/query',async(req,rep)=>handle(req,rep,(c,id)=>c.recoveryRequests(id,parse(z.object({cursor}).strict(),req.body).cursor)));
 app.post('/administration/platform/recovery/requests',async(req,rep)=>handle(req,rep,(c,id)=>c.createRecoveryRequest(id,parse(pair.extend({requestId:z.uuid()}).strict(),req.body))));
 app.post('/administration/platform/recovery/cancel',async(req,rep)=>handle(req,rep,(c,id)=>c.cancelRecoveryRequest(id,parse(z.object({requestId:z.uuid()}).strict(),req.body).requestId)));
 app.post('/administration/platform/recovery/execute',async(req,rep)=>handle(req,rep,(c,id)=>{parse(z.object({requestId:z.uuid()}).strict(),req.body);return c.rejectExecution(id);}));
 app.post('/administration/platform/humans/lifecycle',async(req,rep)=>handle(req,rep,(c,id)=>{parse(z.object({humanIdentityId:identifier,action:z.enum(['suspend','reactivate','revoke_sessions','retire','delete'])}).strict(),req.body);return c.rejectExecution(id);}));
};}
