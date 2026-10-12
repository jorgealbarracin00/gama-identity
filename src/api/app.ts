import { humanAdministrationRoutes } from "./human-administration-routes.js";
import { accountManagementRoutes } from "./account-management-routes.js";
import { workloadAdministrationRoutes } from "./workload-administration-routes.js";
import { googleRecoveryHandoffRoutes } from "./google-recovery-handoff-routes.js";
import { identityManagementRoutes } from './identity-management-routes.js';
import Fastify, { type FastifyInstance } from "fastify";

import { healthRoutes } from "../health/routes.js";
import { HealthCheck } from "../health/health-check.js";
import { logger } from "../shared/logger.js";
import { setErrorHandler } from "./error-handler.js";
import { identityRoutes } from "./identity-routes.js";
import { controlPlaneRoutes } from "./control-plane-routes.js";
import type { ControlPlane } from "../control-plane/application/control-plane.js";
import {
  buildIdentityServices,
  type DatabaseHealth,
  type IdentityServices,
} from "./services.js";
import { administrationRoutes } from "./administration-routes.js";
import { consoleControlCentreRoutes } from "./console-control-centre-routes.js";

export function buildApp(
  services: IdentityServices = buildIdentityServices(),
  databaseHealth: DatabaseHealth = {
    async check() {
      return "not_configured";
    },
  },
  controlPlane: ControlPlane = services.controlPlane,
): FastifyInstance {
  const app = Fastify({ loggerInstance: logger });

  setErrorHandler(app);
  app.register(healthRoutes(new HealthCheck(databaseHealth)));
  app.register(identityRoutes(services));
  app.register(accountManagementRoutes(services));
  app.register(humanAdministrationRoutes(services));
  app.register(controlPlaneRoutes(services, controlPlane));
  app.register(administrationRoutes(services));
  app.register(workloadAdministrationRoutes(services));
  app.register(consoleControlCentreRoutes(services));
  app.register(identityManagementRoutes(services));
  app.register(googleRecoveryHandoffRoutes(services));

  return app;
}
