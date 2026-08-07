import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";

import type { ControlPlane } from "../control-plane/application/control-plane.js";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import type { IdentityServices } from "./services.js";

const workforceQuery = z.object({ tenantId: z.string().min(1), productId: z.string().min(1) });

export function controlPlaneRoutes(services: IdentityServices, controlPlane: ControlPlane): FastifyPluginAsync {
  return async (app) => {
    app.get("/control/workforce-context", async (request, reply) => {
      const session = await services.validateSession.execute(bearerSessionId(request));
      if (session.outcome !== "authenticated") throw new AppError("Session is not authenticated", `SESSION_${session.outcome.toUpperCase()}`, 401);
      const parsed = workforceQuery.safeParse(request.query);
      if (!parsed.success) throw new AppError("Invalid workforce context query", "INVALID_REQUEST", 400);
      const context = await controlPlane.workforceContext(session.humanIdentityId, parsed.data.tenantId, parsed.data.productId);
      if (!context.workforceContextSatisfied) throw new AppError("Workforce context is not satisfied", "WORKFORCE_CONTEXT_REQUIRED", 403);
      return reply.send(context);
    });

    app.get("/control/workload-context", async (request, reply) => {
      const workloadId = request.headers["x-gama-workload-id"];
      const secret = request.headers["x-gama-workload-secret"];
      if (typeof workloadId !== "string" || typeof secret !== "string") {
        throw new AppError("A workload identity is required", "WORKLOAD_INVALID", 401);
      }
      const workload = await controlPlane.authenticateWorkload(workloadId, secret);
      if (workload === null) throw new AppError("Workload identity is not authenticated", "WORKLOAD_INVALID", 401);
      return reply.send(workload);
    });
  };
}

function bearerSessionId(request: FastifyRequest): SessionId {
  const match = /^Bearer ([^\s]+)$/.exec(request.headers.authorization ?? "");
  if (match?.[1] === undefined) throw new AppError("A bearer session is required", "SESSION_INVALID", 401);
  return SessionId.from(match[1]);
}
