import { buildApp } from "./api/app.js";
import { buildRuntime } from "./api/services.js";
import { config } from "./config/index.js";
import { logger } from "./shared/logger.js";

try {
  const runtime = await buildRuntime(config);
  const app = buildApp(runtime.services, runtime.databaseHealth);
  app.addHook("onClose", async () => runtime.close());

  const shutdown = async () => {
    await app.close();
  };
  process.once("SIGTERM", () => void shutdown());
  process.once("SIGINT", () => void shutdown());

  try {
    await app.listen({
      host: "0.0.0.0",
      port: config.PORT,
    });
  } catch (error) {
    await app.close();
    throw error;
  }
} catch (error) {
  logger.fatal({ err: error }, "Failed to start server");
  process.exitCode = 1;
}
