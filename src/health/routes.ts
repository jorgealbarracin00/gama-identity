import type { FastifyPluginAsync } from "fastify";

import { packageMetadata } from "../config/package.js";
import type { HealthCheck } from "./health-check.js";

export function healthRoutes(healthCheck: HealthCheck): FastifyPluginAsync {
  return async (app) => {
    const response = async () => {
      const health = await healthCheck.execute();
      return {
        service: packageMetadata.name,
        version: packageMetadata.version,
        ...health,
      };
    };

    app.get("/", async (_request, reply) => {
      const health = await response();
      return reply.status(health.status === "running" ? 200 : 503).send(health);
    });
    app.get("/health", async (_request, reply) => {
      const health = await response();
      return reply.status(health.status === "running" ? 200 : 503).send(health);
    });
  };
}
