import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  COCO_DEVELOPMENT_TENANT_ID,
  COCO_PRODUCT_ID,
  COCO_WORKLOAD_ID,
  TENANT_WORKFORCE_CAPABILITIES,
  capabilitiesForTenantWorkforceRole,
} from "../../src/control-plane/models.js";
import { buildTestServices } from "../operational/test-doubles.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";

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
    assert.equal(context.membershipStatus, "active");
    assert.equal(context.tenantRole, "owner");
    assert.equal(context.participationActive, true);
    assert.equal(context.entitlementActive, true);
    assert.deepEqual(context.capabilities, TENANT_WORKFORCE_CAPABILITIES);
  });

  it("resolves one stable role capability policy for Owner, Admin, and Staff", async () => {
    const { fixture, owner } = await bootstrapOwner();
    const admin = await fixture.services.register.execute({ email: "admin@coco.example", password: "correct-password" });
    const staff = await fixture.services.register.execute({ email: "staff@coco.example", password: "correct-password" });
    for (const [humanIdentityId, tenantRole] of [[admin.humanIdentityId, "admin"], [staff.humanIdentityId, "staff"]] as const) {
      await fixture.workforceAdministration.grantProductWorkforceAccess({
        actorReference: owner.humanIdentityId,
        tenantId: COCO_DEVELOPMENT_TENANT_ID,
        productId: COCO_PRODUCT_ID,
        humanIdentityId,
        tenantRole,
      });
    }

    const ownerContext = await fixture.services.controlPlane.workforceContext(owner.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    const adminContext = await fixture.services.controlPlane.workforceContext(admin.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    const staffContext = await fixture.services.controlPlane.workforceContext(staff.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);

    assert.deepEqual(ownerContext.capabilities, capabilitiesForTenantWorkforceRole("owner"));
    assert.deepEqual(adminContext.capabilities, capabilitiesForTenantWorkforceRole("admin"));
    assert.deepEqual(staffContext.capabilities, capabilitiesForTenantWorkforceRole("staff"));
    assert.equal(adminContext.capabilities.includes("ownership.manage"), false);
    assert.equal(staffContext.capabilities.includes("products.create"), true);
    assert.equal(staffContext.capabilities.includes("catalogue.view"), false);
    assert.equal(staffContext.capabilities.includes("team.manage"), false);
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
    assert.equal(context.tenantRole, null);
    assert.equal(context.entitlementActive, false);
    assert.deepEqual(context.capabilities, []);
  });

  it("rejects workforce context immediately when the Human Identity is suspended", async () => {
    const { fixture, owner } = await bootstrapOwner();
    const identity = await fixture.identities.findById(HumanIdentityId.from(owner.humanIdentityId));
    assert.ok(identity);
    identity.suspend(fixture.clock);
    await fixture.identities.save(identity);
    const context = await fixture.services.controlPlane.workforceContext(owner.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    assert.equal(context.humanIdentityActive, false);
    assert.equal(context.membershipActive, true);
    assert.equal(context.workforceContextSatisfied, false);
    assert.deepEqual(context.capabilities, []);
  });

  it("does not add a customer to the Coco Tenant merely because the customer has a Human Identity", async () => {
    const { fixture } = await bootstrapOwner();
    const customer = await fixture.services.register.execute({ email: "retail-customer@coco.example", password: "correct-password" });
    const context = await fixture.services.controlPlane.workforceContext(customer.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    assert.equal(context.membershipActive, false);
    assert.equal(context.entitlementActive, false);
  });

  it("records the required Platform bootstrap audit events", async () => {
    const { fixture, owner } = await bootstrapOwner();
    assert.deepEqual(fixture.controlPlaneRepository.auditEvents.map((event) => event.eventType), [
      "product.registered", "workload.identity.established", "tenant.membership.granted",
      "product.participation.established", "product.entitlement.granted",
    ]);

    const membershipBeforeRetry = await fixture.controlPlaneRepository.findMembership(
      COCO_DEVELOPMENT_TENANT_ID,
      owner.humanIdentityId,
    );
    fixture.clock.set(new Date("2026-01-01T00:05:00.000Z"));
    await fixture.services.controlPlane.bootstrapCoco({
      ownerHumanIdentityId: owner.humanIdentityId,
      workloadSecret,
      actorReference: "platform-operator:retry",
    });

    assert.equal(fixture.controlPlaneRepository.auditEvents.length, 5);
    assert.deepEqual(
      await fixture.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, owner.humanIdentityId),
      membershipBeforeRetry,
    );
  });
});
