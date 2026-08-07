import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { FastifyInstance } from "fastify";

import { buildApp } from "../../src/api/app.js";
import { COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID, COCO_WORKLOAD_ID } from "../../src/control-plane/models.js";
import { buildTestServices } from "../operational/test-doubles.js";

const workloadSecret = "coco-development-workload-secret";

describe("control-plane HTTP API", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => app?.close());

  it("validates an owner workforce context from a GAMA session", async () => {
    const { services } = buildTestServices();
    const owner = await services.register.execute({ email: "owner@coco.example", password: "correct-password" });
    await services.controlPlane.bootstrapCoco({ ownerHumanIdentityId: owner.humanIdentityId, workloadSecret, actorReference: "platform-operator:test" });
    app = buildApp(services);
    const response = await app.inject({ method: "GET", url: `/control/workforce-context?tenantId=${COCO_DEVELOPMENT_TENANT_ID}&productId=${COCO_PRODUCT_ID}`, headers: { authorization: `Bearer ${owner.session.sessionId}` } });
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().workforceContextSatisfied, true);
  });

  it("rejects a non-member from workforce context while preserving Human authentication", async () => {
    const { services } = buildTestServices();
    const owner = await services.register.execute({ email: "owner@coco.example", password: "correct-password" });
    await services.controlPlane.bootstrapCoco({ ownerHumanIdentityId: owner.humanIdentityId, workloadSecret, actorReference: "platform-operator:test" });
    const customer = await services.register.execute({ email: "customer@coco.example", password: "correct-password" });
    app = buildApp(services);
    const response = await app.inject({ method: "GET", url: `/control/workforce-context?tenantId=${COCO_DEVELOPMENT_TENANT_ID}&productId=${COCO_PRODUCT_ID}`, headers: { authorization: `Bearer ${customer.session.sessionId}` } });
    assert.equal(response.statusCode, 403);
    assert.equal(response.json().error.code, "WORKFORCE_CONTEXT_REQUIRED");
  });

  it("authenticates the Coco workload only with its registered secret", async () => {
    const { services } = buildTestServices();
    const owner = await services.register.execute({ email: "owner@coco.example", password: "correct-password" });
    await services.controlPlane.bootstrapCoco({ ownerHumanIdentityId: owner.humanIdentityId, workloadSecret, actorReference: "platform-operator:test" });
    app = buildApp(services);
    const accepted = await app.inject({ method: "GET", url: "/control/workload-context", headers: { "x-gama-workload-id": COCO_WORKLOAD_ID, "x-gama-workload-secret": workloadSecret } });
    assert.equal(accepted.statusCode, 200);
    assert.equal(accepted.json().productId, COCO_PRODUCT_ID);
    const rejected = await app.inject({ method: "GET", url: "/control/workload-context", headers: { "x-gama-workload-id": COCO_WORKLOAD_ID, "x-gama-workload-secret": "invalid" } });
    assert.equal(rejected.statusCode, 401);
  });
});
