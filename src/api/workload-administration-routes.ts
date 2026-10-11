import type { FastifyPluginAsync } from "fastify";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import type { IdentityServices } from "./services.js";

/** Server-only credential operations: never add this contract to native product clients. */
export function workloadAdministrationRoutes(services:IdentityServices):FastifyPluginAsync {
  return async app=>{
    for(const operation of ["inspect","create","rotate","revoke"] as const) {
      app.post(`/administration/platform/workloads/${operation}`,{logLevel:"silent",bodyLimit:8192,onRequest:async(_request,reply)=>{reply.header("Cache-Control","no-store").header("Pragma","no-cache");}},async(request,reply)=>{
        reply.header("Cache-Control","no-store").header("Pragma","no-cache");
        const match=/^Bearer ([^\s]+)$/.exec(request.headers.authorization??"");
        if(!match?.[1])throw new AppError("A current administrator session is required","SESSION_INVALID",401);
        const service=services.administration.workloads;
        if(!service)throw new AppError("Workload administration is disabled","WORKLOAD_ADMINISTRATION_DISABLED",403);
        return service[operation](SessionId.from(match[1]),request.body??{});
      });
    }
  };
}
