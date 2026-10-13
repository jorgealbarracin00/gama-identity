import { createHash, randomUUID } from "node:crypto";
import type { Config } from "../../config/env.js";
import { AppError } from "../../shared/errors.js";

export type HumanCapability = "classification" | "suspend" | "reactivate" | "revoke_sessions" | "retire" | "delete" | "bulk";
export type HumanCapabilities = Readonly<Record<HumanCapability, boolean>>;
export function legacyHumanCapabilities(enabled: boolean): HumanCapabilities {
  return { classification: enabled, suspend: enabled, reactivate: enabled, revoke_sessions: enabled, retire: enabled, delete: enabled, bulk: enabled };
}
export function humanCapabilities(config: Config): HumanCapabilities {
  const legacy = config.IDENTITY_HUMAN_ADMINISTRATION_ENABLED;
  return {
    classification: config.IDENTITY_HUMAN_CLASSIFICATION_ENABLED ?? legacy,
    suspend: config.IDENTITY_HUMAN_SUSPENSION_ENABLED ?? legacy,
    reactivate: config.IDENTITY_HUMAN_REACTIVATION_ENABLED ?? legacy,
    revoke_sessions: config.IDENTITY_HUMAN_SESSION_REVOCATION_ENABLED ?? legacy,
    retire: config.IDENTITY_HUMAN_RETIREMENT_ENABLED ?? legacy,
    delete: config.IDENTITY_HUMAN_DELETION_ENABLED ?? legacy,
    bulk: config.IDENTITY_HUMAN_BULK_ENABLED ?? legacy,
  };
}
export function anyHumanCapability(capabilities: HumanCapabilities): boolean {
  return Object.values(capabilities).some(Boolean);
}
export function requireHumanCapability(capabilities: HumanCapabilities, action: HumanCapability): void {
  if (!capabilities[action]) throw new AppError("This administrative capability is disabled", "HUMAN_ADMINISTRATION_DISABLED", 403);
}
export async function requireConfirmedTest(
  db: import("../../infrastructure/postgres/database.js").PostgresDatabase, human: string,
): Promise<void> {
  const result = await db.query("SELECT 1 FROM human_purposes WHERE human_identity_id=$1 AND purpose='test'", [human]);
  if (!result.rows.length) throw new AppError("Bulk administration requires an explicitly classified test account", "BULK_REQUIRES_CONFIRMED_TEST", 409);
}

export interface AccountCapabilities {
  appleLink: boolean; googleLink: boolean; federatedUnlink: boolean;
  appleAudiences?: readonly string[]; googleAudiences?: readonly string[];
  emailConnect: boolean; emailUnlink: boolean; passwordChange: boolean; profile: boolean;
}
export function accountCapabilities(config: Config): AccountCapabilities {
  return {
    appleLink: config.APPLE_CLIENT_IDS.length > 0, appleAudiences: config.APPLE_CLIENT_IDS,
    googleLink: config.GOOGLE_CLIENT_IDS.length > 0, googleAudiences: config.GOOGLE_CLIENT_IDS,
    federatedUnlink: true, profile: true,
    emailConnect: config.IDENTITY_EMAIL_LINKING_ENABLED ?? config.IDENTITY_ACCOUNT_MANAGEMENT_ENABLED,
    emailUnlink: config.IDENTITY_EMAIL_UNLINKING_ENABLED ?? config.IDENTITY_ACCOUNT_MANAGEMENT_ENABLED,
    passwordChange: config.IDENTITY_PASSWORD_MANAGEMENT_ENABLED ?? config.IDENTITY_ACCOUNT_MANAGEMENT_ENABLED,
  };
}

/** One safe startup receipt per configuration transition; no credentials or provider secrets. */
export async function recordCapabilityConfiguration(db: import("../../infrastructure/postgres/database.js").PostgresDatabase, config: Config): Promise<void> {
  const { appleAudiences: _apple, googleAudiences: _google, ...account } = accountCapabilities(config);
  const snapshot = { human: humanCapabilities(config), account,
    providerTransfer: config.IDENTITY_PROVIDER_TRANSFER_ENABLED, workloadAdministration: config.IDENTITY_WORKLOAD_ADMINISTRATION_ENABLED };
  const configurationDigest = createHash("sha256").update(JSON.stringify(snapshot)).digest("hex");
  await db.withTransaction(async () => {
    await db.query("SELECT pg_advisory_xact_lock(710022)");
    const previous = await db.query<{event_data: Record<string, string>}>("SELECT event_data FROM platform_audit_events WHERE event_type='administration.capabilities.configured' ORDER BY occurred_at DESC,id DESC LIMIT 1");
    if (previous.rows[0]?.event_data.configurationDigest === configurationDigest) return;
    await db.query("INSERT INTO platform_audit_events(id,event_type,actor_reference,subject_reference,event_data,occurred_at) VALUES($1,'administration.capabilities.configured','system:runtime-configuration','platform:administrative-capabilities',$2,now())", [randomUUID(), {configurationDigest, capabilities: JSON.stringify(snapshot)}]);
  });
}
