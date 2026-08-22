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
  PASSWORD_HASH_MEMORY_KIB: z.coerce.number().int().min(8192).default(19_456),
  PASSWORD_HASH_ITERATIONS: z.coerce.number().int().min(2).default(2),
  PASSWORD_HASH_PARALLELISM: z.coerce.number().int().min(1).default(1),
  SESSION_DURATION_SECONDS: z.coerce
    .number()
    .int()
    .min(60)
    .default(86_400),
  REPOSITORY_MODE: z.enum(["memory", "postgres"]).default("memory"),
  DATABASE_URL: z.string().url().optional(),
  DATABASE_SSL: z.enum(["disable", "require"]).default("disable"),
  APPLE_CLIENT_IDS: z.string().optional().transform((value, context) => {
    if (value === undefined) return [];
    const clientIds = [...new Set(value.split(",").map((entry) => entry.trim()).filter(Boolean))];
    if (clientIds.length === 0) {
      context.addIssue({ code: "custom", message: "APPLE_CLIENT_IDS must contain at least one client identifier" });
      return z.NEVER;
    }
    return clientIds;
  }),
}).superRefine((environment, context) => {
  if (
    environment.REPOSITORY_MODE === "postgres" &&
    environment.DATABASE_URL === undefined
  ) {
    context.addIssue({
      code: "custom",
      path: ["DATABASE_URL"],
      message: "DATABASE_URL is required when REPOSITORY_MODE is postgres",
    });
  }
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
