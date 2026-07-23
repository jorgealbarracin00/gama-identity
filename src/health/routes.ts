import type { FastifyPluginAsync } from "fastify";

import { packageMetadata } from "../config/package.js";

export const healthRoutes: FastifyPluginAsync = async (app) => {
  app.get("/", async () => ({
    service: packageMetadata.name,
    version: packageMetadata.version,
    status: "running",
  }));
};
