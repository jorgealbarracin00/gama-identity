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

const webIdentityAppsSchema = z.array(z.object({
  appId: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u),
  purpose: z.enum(["preview", "production"]),
  allowedPrincipalIds: z.array(z.string().min(1).max(200)).min(1).max(100).optional(),
  apple: z.object({
    clientId: z.string().trim().min(1),
    redirectUri: z.string().url().startsWith("https://"),
    teamId: z.string().regex(/^[A-Z0-9]{10}$/u),
    keyId: z.string().regex(/^[A-Z0-9]{10}$/u),
    privateKey: z.string().min(1),
  }).strict().optional(),
  google: z.object({
    clientId: z.string().trim().min(1),
    clientSecret: z.string().min(1),
    redirectUri: z.string().url().startsWith("https://"),
  }).strict().optional(),
}).strict()).max(20).superRefine((apps, context) => {
  if (new Set(apps.map((app) => app.appId)).size !== apps.length) {
    context.addIssue({ code: "custom", message: "Web identity app IDs must be unique" });
  }
  for (const app of apps) {
    if (app.purpose === "preview" && app.allowedPrincipalIds === undefined) {
      context.addIssue({ code: "custom", message: "Preview web identity apps require existing authorized principals" });
    }
    if (app.apple === undefined && app.google === undefined) {
      context.addIssue({ code: "custom", message: "Web identity apps require a configured provider" });
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
  GROCERY_REVOCATION_SERVICE_TOKEN: z.string().min(32).optional(),
  GROCERY_APPLE_TEAM_ID: z.string().regex(/^[A-Z0-9]{10}$/u).optional(),
  GROCERY_APPLE_KEY_ID: z.string().regex(/^[A-Z0-9]{10}$/u).optional(),
  GROCERY_APPLE_PRIVATE_KEY: z.string().min(1).optional(),
  GROCERY_APPLE_GRANT_ENCRYPTION_KEY: z.string().regex(/^[A-Za-z0-9+/]{43}=$/u).optional(),
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
  // Optional additive registry. Empty preserves all legacy/native behaviour.
  IDENTITY_WEB_APPS: z.string().default("[]").transform((value, context) => {
    try {
      const result = webIdentityAppsSchema.safeParse(JSON.parse(value));
      if (!result.success) {
        context.addIssue({ code: "custom", message: "Invalid web identity app registry" });
        return z.NEVER;
      }
      return result.data;
    } catch {
      context.addIssue({ code: "custom", message: "Web identity app registry must be valid JSON" });
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
  const groceryRevocationValues = [environment.GROCERY_REVOCATION_SERVICE_TOKEN, environment.GROCERY_APPLE_TEAM_ID,
    environment.GROCERY_APPLE_KEY_ID, environment.GROCERY_APPLE_PRIVATE_KEY, environment.GROCERY_APPLE_GRANT_ENCRYPTION_KEY];
  if (groceryRevocationValues.some((value) => value !== undefined) &&
      (groceryRevocationValues.some((value) => value === undefined) || environment.REPOSITORY_MODE !== "postgres")) {
    context.addIssue({ code: "custom", message: "Grocery Apple revocation requires PostgreSQL and all five GROCERY revocation settings" });
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
  for (const app of environment.IDENTITY_WEB_APPS) {
    const trusted = environment.IDENTITY_TRUSTED_APPS.find((candidate) => candidate.id === app.appId);
    if (trusted === undefined) {
      context.addIssue({ code: "custom", path: ["IDENTITY_WEB_APPS"], message: "Web identity apps must identify a trusted application" });
      continue;
    }
    for (const provider of ["apple", "google"] as const) {
      const configured = app[provider];
      if (configured === undefined) continue;
      const approvedClientIds = provider === "apple" ? environment.APPLE_CLIENT_IDS : environment.GOOGLE_CLIENT_IDS;
      // A preview client is scoped to this registry; admitting it through the
      // unrestricted legacy token endpoint would bypass its creation policy.
      if (app.purpose === "preview" && (approvedClientIds.includes(configured.clientId) ||
        environment.IDENTITY_WEB_APPS.some((other) => other.purpose === "production" && other[provider]?.clientId === configured.clientId))) {
        context.addIssue({ code: "custom", path: ["IDENTITY_WEB_APPS"], message: "Preview clients must be separate from unrestricted provider audiences" });
      }
      if (configured.redirectUri !== `${trusted.baseUrl}/api/auth/${provider}/callback`) {
        context.addIssue({ code: "custom", path: ["IDENTITY_WEB_APPS"], message: "Web identity callback must match its trusted application origin and provider path" });
      }
    }
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
