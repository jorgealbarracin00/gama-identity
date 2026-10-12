import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";
import type { IdentityServices } from "./services.js";
import { accountSession } from "./account-management-routes.js";
import { AppError } from "../shared/errors.js";
import { AdministrationAuthorizationError } from "../control-plane/application/administration-principals.js";

const human = z.string().min(1).max(200);
const action = z.enum(["suspend", "reactivate", "retire", "revoke_sessions", "delete"]);
const scope = z.enum(["identity_only", "eligible_personal_data"]).default("identity_only");
const command = z.object({ humanIdentityId: human, action, scope, requestId: z.uuid(),
  reviewDigest: z.string().regex(/^[a-f0-9]{64}$/u), confirmation: z.string().max(500) }).strict();
function parse<T>(schema: z.ZodType<T>, body: unknown) {
  const result = schema.safeParse(body);
  if (!result.success) throw new AppError("Invalid administration request", "INVALID_REQUEST", 400);
  return result.data;
}

export function humanAdministrationRoutes(services: IdentityServices): FastifyPluginAsync {
  return async app => {
    const service = () => {
      if (!services.administration.humans) throw new AppError("Human administration is unavailable", "HUMAN_ADMINISTRATION_UNAVAILABLE", 503);
      return services.administration.humans;
    };
    const handle = async (request: FastifyRequest, work: (m: NonNullable<IdentityServices["administration"]["humans"]>, token: ReturnType<typeof accountSession>) => Promise<unknown>) => {
      const token = accountSession(request);
      try { return await work(service(), token); }
      catch (error) {
        if (error instanceof AdministrationAuthorizationError) throw new AppError("Platform administrator permission is required", error.code, 403);
        throw error;
      }
    };
    app.post("/administration/platform/humans/manage/available", request => handle(request, (m,s) => m.available(s, parse(z.object({humanIdentityId:human}).strict(),request.body).humanIdentityId)));
    app.post("/administration/platform/humans/manage/preview", request => handle(request, (m,s) => {
      const p=parse(z.object({humanIdentityId:human,action,scope}).strict(),request.body);return m.preview(s,p.humanIdentityId,p.action,p.scope);
    }));
    app.post("/administration/platform/humans/manage/execute", request => handle(request, (m,s) => m.execute(s,parse(command,request.body))));
    app.post("/administration/platform/humans/manage/status", request => handle(request, (m,s) => m.status(s,parse(z.object({requestId:z.uuid()}).strict(),request.body).requestId)));
    app.post("/administration/platform/humans/manage/bulk", request => handle(request, (m,s) => {
      const p=parse(z.object({items:z.array(command).min(1).max(50).refine(items=>new Set(items.map(i=>i.humanIdentityId)).size===items.length && new Set(items.map(i=>i.requestId)).size===items.length),confirmation:z.string().max(80)}).strict(),request.body);
      return m.bulk(s,p.items,p.confirmation);
    }));
    const credentials = (request: FastifyRequest) => {
      const id=request.headers["x-gama-workload-id"], secret=request.headers["x-gama-workload-secret"];
      if (typeof id!=="string" || typeof secret!=="string" || !/^[a-z][a-z0-9-]{0,63}$/u.test(id) || !/^[A-Za-z0-9_-]{43}$/u.test(secret)) throw new AppError("Cleanup workload authorization required","WORKLOAD_UNAUTHORIZED",401);
      return {id,secret};
    };
    const options = {logLevel:"silent" as const,bodyLimit:8192,onRequest:async (_r:FastifyRequest,reply:import("fastify").FastifyReply)=>{reply.header("Cache-Control","no-store");}};
    app.post("/control/human-data-cleanup/claim",options,request=>{
      const w=credentials(request);parse(z.object({}).strict(),request.body??{});return service().claimCleanup(w.id,w.secret);
    });
    app.post("/control/human-data-cleanup/complete",options,request=>{
      const w=credentials(request),p=parse(z.object({id:z.uuid(),revision:z.number().int().min(1).max(2147483646),state:z.enum(["completed","unsupported","failed"]),deletedRecords:z.number().int().min(0).max(2147483647),retainedRecords:z.number().int().min(0).max(2147483647)}).strict(),request.body);
      return service().completeCleanup(w.id,w.secret,p);
    });
  };
}
