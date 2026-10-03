import "dotenv/config";

import { z } from "zod";

const trustedIdentityAppsSchema = z.array(z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u),
  displayName: z.string().trim().min(1).max(80),
  baseUrl: z.string().url().transform((value) => value.replace(/\/$/u, "")),
}).strict()).min(1).max(20).superRefine((apps, context) => {
  if (new Set(apps.map((app) => app.id)).size !== apps.length) {
    context.addIssue({ code: "custom", message: "Trusted identity app ids must be unique" });
  }
  for (const [index, app] of apps.entries()) {
    const url = new URL(app.baseUrl);
    if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
      context.addIssue({
        code: "custom",
        path: [index, "baseUrl"],
        message: "Trusted identity app base URLs must use HTTPS",
      });
    }
    if (url.pathname !== "/" || url.search !== "" || url.hash !== "") {
      context.addIssue({
        code: "custom",
        path: [index, "baseUrl"],
        message: "Trusted identity app base URLs cannot contain a path, query, or fragment",
      });
    }
  }
});

const defaultTrustedApps = JSON.stringify([{
  id: "coco-web",
  displayName: "Coco the Llama",
  baseUrl: "https://cocothellama.com",
}]);

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
  SESSION_RENEWAL_DURATION_SECONDS: z.coerce
    .number()
    .int()
    .min(300)
    .default(2_592_000),
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
  APPLE_WEB_CLIENT_ID: z.string().trim().min(1).optional(),
  APPLE_WEB_REDIRECT_URI: z.string().url().startsWith("https://").optional(),
  APPLE_TEAM_ID: z.string().regex(/^[A-Z0-9]{10}$/u).optional(),
  APPLE_KEY_ID: z.string().regex(/^[A-Z0-9]{10}$/u).optional(),
  APPLE_PRIVATE_KEY: z.string().min(1).optional(),
  GOOGLE_CLIENT_IDS: z.string().optional().transform((value, context) => {
    if (value === undefined) return [];
    const clientIds = [...new Set(value.split(",").map((entry) => entry.trim()).filter(Boolean))];
    if (clientIds.length === 0) {
      context.addIssue({ code: "custom", message: "GOOGLE_CLIENT_IDS must contain at least one client identifier" });
      return z.NEVER;
    }
    return clientIds;
  }),
  GOOGLE_WEB_CLIENT_ID: z.string().trim().min(1).optional(),
  GOOGLE_WEB_CLIENT_SECRET: z.string().min(1).optional(),
  GOOGLE_WEB_REDIRECT_URI: z.string().url().startsWith("https://").optional(),
  IDENTITY_TRUSTED_APPS: z.string().default(defaultTrustedApps).transform((value, context) => {
    try {
      const result = trustedIdentityAppsSchema.safeParse(JSON.parse(value));
      if (!result.success) {
        context.addIssue({ code: "custom", message: z.prettifyError(result.error) });
        return z.NEVER;
      }
      return result.data;
    } catch {
      context.addIssue({ code: "custom", message: "IDENTITY_TRUSTED_APPS must be valid JSON" });
      return z.NEVER;
    }
  }),
  IDENTITY_DEFAULT_APP_ID: z.string().default("coco-web"),
  IDENTITY_EMAIL_PROVIDER: z.enum(["disabled", "resend"]).default("disabled"),
  IDENTITY_EMAIL_FROM: z.string().trim().min(3).max(320).optional(),
  RESEND_API_KEY: z.string().min(10).optional(),
  IDENTITY_EMAIL_VERIFICATION_TTL_SECONDS: z.coerce.number().int().min(300).max(604_800).default(86_400),
  IDENTITY_PASSWORD_RESET_TTL_SECONDS: z.coerce.number().int().min(300).max(86_400).default(3_600),
  IDENTITY_RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(60).max(86_400).default(900),
  IDENTITY_RATE_LIMIT_MAXIMUM_ATTEMPTS: z.coerce.number().int().min(1).max(100).default(5),
  IDENTITY_RATE_LIMIT_SECRET: z.string().min(32).default("development-only-rate-limit-key-change-me"),
}).superRefine((environment, context) => {
  if (environment.SESSION_RENEWAL_DURATION_SECONDS <= environment.SESSION_DURATION_SECONDS) {
    context.addIssue({
      code: "custom",
      path: ["SESSION_RENEWAL_DURATION_SECONDS"],
      message: "SESSION_RENEWAL_DURATION_SECONDS must exceed SESSION_DURATION_SECONDS",
    });
  }
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
  const appleWebValues = [
    environment.APPLE_WEB_CLIENT_ID,
    environment.APPLE_WEB_REDIRECT_URI,
    environment.APPLE_TEAM_ID,
    environment.APPLE_KEY_ID,
    environment.APPLE_PRIVATE_KEY,
  ];
  const configuredAppleWebValues = appleWebValues.filter((value) => value !== undefined).length;
  if (configuredAppleWebValues !== 0 && configuredAppleWebValues !== appleWebValues.length) {
    context.addIssue({
      code: "custom",
      path: ["APPLE_WEB_CLIENT_ID"],
      message: "Apple web authentication must be configured completely",
    });
  }
  if (
    environment.APPLE_WEB_CLIENT_ID !== undefined &&
    !environment.APPLE_CLIENT_IDS.includes(environment.APPLE_WEB_CLIENT_ID)
  ) {
    context.addIssue({
      code: "custom",
      path: ["APPLE_CLIENT_IDS"],
      message: "APPLE_CLIENT_IDS must include APPLE_WEB_CLIENT_ID",
    });
  }
  const googleWebValues = [
    environment.GOOGLE_WEB_CLIENT_ID,
    environment.GOOGLE_WEB_CLIENT_SECRET,
    environment.GOOGLE_WEB_REDIRECT_URI,
  ];
  const configuredGoogleWebValues = googleWebValues.filter((value) => value !== undefined).length;
  if (configuredGoogleWebValues !== 0 && configuredGoogleWebValues !== googleWebValues.length) {
    context.addIssue({
      code: "custom",
      path: ["GOOGLE_WEB_CLIENT_ID"],
      message: "Google web authentication must be configured completely",
    });
  }
  if (
    environment.GOOGLE_WEB_CLIENT_ID !== undefined &&
    !environment.GOOGLE_CLIENT_IDS.includes(environment.GOOGLE_WEB_CLIENT_ID)
  ) {
    context.addIssue({
      code: "custom",
      path: ["GOOGLE_CLIENT_IDS"],
      message: "GOOGLE_CLIENT_IDS must include GOOGLE_WEB_CLIENT_ID",
    });
  }
  if (!environment.IDENTITY_TRUSTED_APPS.some((app) => app.id === environment.IDENTITY_DEFAULT_APP_ID)) {
    context.addIssue({
      code: "custom",
      path: ["IDENTITY_DEFAULT_APP_ID"],
      message: "IDENTITY_DEFAULT_APP_ID must identify a trusted app",
    });
  }
  if (
    environment.IDENTITY_EMAIL_PROVIDER === "resend" &&
    (environment.RESEND_API_KEY === undefined || environment.IDENTITY_EMAIL_FROM === undefined)
  ) {
    context.addIssue({
      code: "custom",
      path: ["IDENTITY_EMAIL_PROVIDER"],
      message: "Resend delivery requires RESEND_API_KEY and IDENTITY_EMAIL_FROM",
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
