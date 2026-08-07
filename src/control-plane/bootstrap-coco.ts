import { buildRuntime } from "../api/services.js";
import { config } from "../config/index.js";

const ownerHumanIdentityId = process.env.COCO_OWNER_HUMAN_IDENTITY_ID;
const workloadSecret = process.env.COCO_WORKLOAD_SECRET;
const actorReference = process.env.COCO_BOOTSTRAP_ACTOR_REFERENCE;

if (config.REPOSITORY_MODE !== "postgres") {
  throw new Error("Coco bootstrap requires REPOSITORY_MODE=postgres");
}
if (!ownerHumanIdentityId || !workloadSecret || !actorReference) {
  throw new Error("COCO_OWNER_HUMAN_IDENTITY_ID, COCO_WORKLOAD_SECRET and COCO_BOOTSTRAP_ACTOR_REFERENCE are required");
}

const runtime = await buildRuntime(config);
try {
  await runtime.controlPlane.bootstrapCoco({ ownerHumanIdentityId, workloadSecret, actorReference });
} finally {
  await runtime.close();
}
