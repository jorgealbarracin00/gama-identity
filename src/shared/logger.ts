import type { FastifyBaseLogger } from "fastify";
import pino from "pino";

import { config } from "../config/index.js";

export const logger: FastifyBaseLogger = pino({
  level: config.LOG_LEVEL,
});
