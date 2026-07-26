import Fastify, { type FastifyInstance } from "fastify";

import { healthRoutes } from "../health/routes.js";
import { HealthCheck } from "../health/health-check.js";
import { logger } from "../shared/logger.js";
import { setErrorHandler } from "./error-handler.js";
import { identityRoutes } from "./identity-routes.js";
import {
  buildIdentityServices,
  type DatabaseHealth,
  type IdentityServices,
} from "./services.js";

export function buildApp(
  services: IdentityServices = buildIdentityServices(),
  databaseHealth: DatabaseHealth = {
    async check() {
      return "not_configured";
    },
  },
): FastifyInstance {
  const app = Fastify({ loggerInstance: logger });

  setErrorHandler(app);
  app.register(healthRoutes(new HealthCheck(databaseHealth)));
  app.register(identityRoutes(services));

  return app;
}
