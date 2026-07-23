import "dotenv/config";

import { z } from "zod";

const environmentSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  LOG_LEVEL: z
    .enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"])
    .default("info"),
});

export type Config = z.infer<typeof environmentSchema>;

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): Config {
  const result = environmentSchema.safeParse(environment);

  if (!result.success) {
    throw new Error(
      `Invalid environment configuration: ${z.prettifyError(result.error)}`,
    );
  }

  return result.data;
}
