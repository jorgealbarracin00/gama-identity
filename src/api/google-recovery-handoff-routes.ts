import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import type { IdentityServices } from "./services.js";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import { AdministrationAuthorizationError } from "../control-plane/application/administration-principals.js";
export function googleRecoveryHandoffRoutes(services:IdentityServices):FastifyPluginAsync {
  return async app => {
    const service = () => { const value=services.administration.googleRecoveryHandoff; if(!value) throw new AppError("Google ownership handoff is unavailable","GOOGLE_HANDOFF_NOT_CONFIGURED",503); return value; };
    const token = (header:string|undefined) => { const m=/^Bearer ([^\s]+)$/.exec(header??""); if(!m?.[1]) throw new AppError("Sign in to continue","SESSION_INVALID",401); return SessionId.from(m[1]); };
    const parse = <T>(schema:z.ZodType<T>,body:unknown) => { const p=schema.safeParse(body); if(!p.success) throw new AppError("Invalid verification request","INVALID_REQUEST",400); return p.data; };
    const guard = async<T>(work:()=>Promise<T>) => { try{return await work();}catch(e){if(e instanceof AdministrationAuthorizationError) throw new AppError("Platform Administrator access is required",e.code,403);throw e;} };
    app.post("/administration/platform/identity-management/recovery/google/start",{logLevel:"silent"},async(req,rep)=>{rep.header("Cache-Control","no-store");const s=token(req.headers.authorization),p=parse(z.object({caseId:z.uuid(),targetSession:z.string().min(1).max(200),kind:z.enum(["recovery","compensation"]).optional()}).strict(),req.body);return guard(()=>service().start(s,p));});
    app.post("/administration/platform/identity-management/recovery/google/result",{logLevel:"silent"},async(req,rep)=>{rep.header("Cache-Control","no-store");const s=token(req.headers.authorization),p=parse(z.object({handoffId:z.uuid()}).strict(),req.body);return guard(()=>service().result(s,p.handoffId));});
    app.post("/administration/platform/identity-management/recovery/google/cancel",{logLevel:"silent"},async(req,rep)=>{rep.header("Cache-Control","no-store");const s=token(req.headers.authorization),p=parse(z.object({handoffId:z.uuid()}).strict(),req.body);return guard(()=>service().cancel(s,p.handoffId));});
    // Disable request URL logging: an OAuth callback contains a one-time authorization code.
    app.get("/authentication/recovery/google/callback",{logLevel:"silent"},async(req,rep)=>{
      rep.header("Cache-Control","no-store").header("Referrer-Policy","no-referrer");
      const p=parse(z.object({state:z.string().regex(/^[A-Za-z0-9_-]{43}$/),code:z.string().min(1).max(4096).optional(),error:z.string().max(200).optional(),scope:z.string().max(1000).optional(),authuser:z.string().max(100).optional(),prompt:z.string().max(100).optional()}),req.query);
      const r=await service().callback(p);return rep.redirect(`gamaconsole://recovery?handoffId=${r.handoffId}&status=${r.state}`);
    });
  };
}
