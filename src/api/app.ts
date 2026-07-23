import Fastify, { type FastifyInstance } from "fastify";

import { healthRoutes } from "../health/routes.js";
import { logger } from "../shared/logger.js";
import { setErrorHandler } from "./error-handler.js";

export function buildApp(): FastifyInstance {
  const app = Fastify({ loggerInstance: logger });

  setErrorHandler(app);
  app.register(healthRoutes);

  return app;
}
