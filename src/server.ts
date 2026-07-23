import { buildApp } from "./api/app.js";
import { config } from "./config/index.js";
import { logger } from "./shared/logger.js";

const app = buildApp();

try {
  await app.listen({
    host: "0.0.0.0",
    port: config.PORT,
  });
} catch (error) {
  logger.fatal({ err: error }, "Failed to start server");
  process.exitCode = 1;
}
