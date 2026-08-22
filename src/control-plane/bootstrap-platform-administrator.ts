import { buildRuntime } from "../api/services.js";
import { config } from "../config/index.js";

const humanIdentityId = process.env.PLATFORM_ADMIN_HUMAN_IDENTITY_ID;
const actorReference = process.env.PLATFORM_ADMIN_BOOTSTRAP_ACTOR_REFERENCE;

if (config.REPOSITORY_MODE !== "postgres") {
  throw new Error("Platform administrator bootstrap requires REPOSITORY_MODE=postgres");
}
if (!humanIdentityId || !actorReference) {
  throw new Error("PLATFORM_ADMIN_HUMAN_IDENTITY_ID and PLATFORM_ADMIN_BOOTSTRAP_ACTOR_REFERENCE are required");
}

const runtime = await buildRuntime(config);
try {
  await runtime.platformAdministrationProvisioning.bootstrapAdministrator(
    humanIdentityId,
    actorReference,
  );
} finally {
  await runtime.close();
}
