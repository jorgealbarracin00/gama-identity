import Fastify, { type FastifyInstance } from "fastify";

import { healthRoutes } from "../health/routes.js";
import { logger } from "../shared/logger.js";
import { setErrorHandler } from "./error-handler.js";
import { identityRoutes } from "./identity-routes.js";
import {
  buildIdentityServices,
  type IdentityServices,
} from "./services.js";

export function buildApp(
  services: IdentityServices = buildIdentityServices(),
): FastifyInstance {
  const app = Fastify({ loggerInstance: logger });

  setErrorHandler(app);
  app.register(healthRoutes);
  app.register(identityRoutes(services));

  return app;
}
