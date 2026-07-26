import type { FastifyPluginAsync } from "fastify";

import { packageMetadata } from "../config/package.js";

export const healthRoutes: FastifyPluginAsync = async (app) => {
  const response = () => ({
    service: packageMetadata.name,
    version: packageMetadata.version,
    status: "running",
  });

  app.get("/", async () => response());
  app.get("/health", async () => response());
};
