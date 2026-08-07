import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  COCO_DEVELOPMENT_TENANT_ID,
  COCO_PRODUCT_ID,
  COCO_WORKLOAD_ID,
} from "../../src/control-plane/models.js";
import { buildTestServices } from "../operational/test-doubles.js";

const workloadSecret = "coco-development-workload-secret";

async function bootstrapOwner() {
  const fixture = buildTestServices();
  const owner = await fixture.services.register.execute({ email: "owner@coco.example", password: "correct-password" });
  await fixture.services.controlPlane.bootstrapCoco({
    ownerHumanIdentityId: owner.humanIdentityId,
    workloadSecret,
    actorReference: "platform-operator:test",
  });
  return { fixture, owner };
}

describe("Coco minimum control plane", () => {
  it("registers and retrieves the stable Coco Product", async () => {
    const { fixture } = await bootstrapOwner();
    assert.deepEqual(await fixture.controlPlaneRepository.findProduct(COCO_PRODUCT_ID), {
      id: COCO_PRODUCT_ID, displayName: "Coco the Llama", status: "active",
    });
  });

  it("establishes a complete workforce context for the owner", async () => {
    const { fixture, owner } = await bootstrapOwner();
    const context = await fixture.services.controlPlane.workforceContext(owner.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    assert.equal(context.workforceContextSatisfied, true);
    assert.equal(context.membershipActive, true);
    assert.equal(context.participationActive, true);
    assert.equal(context.entitlementActive, true);
  });

  it("authenticates the Coco Product Workload and rejects an invalid secret", async () => {
    const { fixture } = await bootstrapOwner();
    assert.deepEqual(await fixture.services.controlPlane.authenticateWorkload(COCO_WORKLOAD_ID, workloadSecret), {
      workloadId: COCO_WORKLOAD_ID, productId: COCO_PRODUCT_ID,
    });
    assert.equal(await fixture.services.controlPlane.authenticateWorkload(COCO_WORKLOAD_ID, "not-the-secret"), null);
  });

  it("rejects a Human without workforce relationships", async () => {
    const { fixture } = await bootstrapOwner();
    const nonMember = await fixture.services.register.execute({ email: "customer@coco.example", password: "correct-password" });
    const context = await fixture.services.controlPlane.workforceContext(nonMember.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    assert.equal(context.workforceContextSatisfied, false);
    assert.equal(context.membershipActive, false);
    assert.equal(context.entitlementActive, false);
  });

  it("does not add a customer to the Coco Tenant merely because the customer has a Human Identity", async () => {
    const { fixture } = await bootstrapOwner();
    const customer = await fixture.services.register.execute({ email: "retail-customer@coco.example", password: "correct-password" });
    const context = await fixture.services.controlPlane.workforceContext(customer.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    assert.equal(context.membershipActive, false);
    assert.equal(context.entitlementActive, false);
  });

  it("records the required Platform bootstrap audit events", async () => {
    const { fixture } = await bootstrapOwner();
    assert.deepEqual(fixture.controlPlaneRepository.auditEvents.map((event) => event.eventType), [
      "product.registered", "workload.identity.established", "tenant.membership.granted",
      "product.participation.established", "product.entitlement.granted",
    ]);
  });
});
