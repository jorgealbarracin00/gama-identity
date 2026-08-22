import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  WorkforceAdministrationError,
} from "../../src/control-plane/application/workforce-administration.js";
import {
  COCO_DEVELOPMENT_TENANT_ID,
  COCO_PRODUCT_ID,
} from "../../src/control-plane/models.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { buildTestServices, type MutableClock } from "../operational/test-doubles.js";

const workloadSecret = "coco-development-workload-secret";
const actorReference = "platform-operator:test";

async function fixture() {
  const built = buildTestServices();
  const owner = await built.services.register.execute({ email: "owner@coco.example", password: "correct-password" });
  await built.services.controlPlane.bootstrapCoco({ ownerHumanIdentityId: owner.humanIdentityId, workloadSecret, actorReference });
  return { ...built, owner };
}

async function register(f: Awaited<ReturnType<typeof fixture>>, email: string) {
  return f.services.register.execute({ email, password: "correct-password" });
}

function grant(humanIdentityId: string, tenantRole: string, tenantId = COCO_DEVELOPMENT_TENANT_ID) {
  return { actorReference, tenantId, productId: COCO_PRODUCT_ID, humanIdentityId, tenantRole };
}

function assertCode(code: string) {
  return (value: unknown) => value instanceof WorkforceAdministrationError && value.code === code;
}

describe("canonical workforce administration", () => {
  it("bootstraps Coco's explicit owner with a role-bearing workforce context", async () => {
    const f = await fixture();
    const membership = await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, f.owner.humanIdentityId);
    const context = await f.services.controlPlane.workforceContext(f.owner.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    assert.equal(membership?.tenantRole, "owner");
    assert.equal(context.membershipStatus, "active");
    assert.equal(context.tenantRole, "owner");
    assert.equal(context.workforceContextSatisfied, true);
  });

  it("resolves an active Human Identity by normalized email without using email as membership identity", async () => {
    const f = await fixture();
    const resolved = await f.workforceAdministration.resolveHumanIdentityByEmail("owner@coco.example");
    assert.deepEqual(resolved, {
      humanIdentityId: f.owner.humanIdentityId,
      displayName: null,
      email: "owner@coco.example",
      status: "active",
    });
    await assert.rejects(() => f.workforceAdministration.resolveHumanIdentityByEmail("missing@coco.example"), assertCode("IDENTITY_NOT_FOUND"));
  });

  it("grants membership, participation, and entitlement as one idempotent product-access operation", async () => {
    const f = await fixture();
    const staff = await register(f, "staff@coco.example");
    const first = await f.workforceAdministration.grantProductWorkforceAccess(grant(staff.humanIdentityId, "staff"));
    const auditCount = f.controlPlaneRepository.auditEvents.length;
    const repeated = await f.workforceAdministration.grantProductWorkforceAccess(grant(staff.humanIdentityId, "staff"));
    assert.equal(first.membership.tenantRole, "staff");
    assert.equal(first.entitlement.status, "active");
    assert.deepEqual(repeated, first);
    assert.equal(f.controlPlaneRepository.auditEvents.length, auditCount);
    assert.equal((await f.services.controlPlane.workforceContext(staff.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID)).workforceContextSatisfied, true);
  });

  it("persists a constrained role and updates the same membership identity", async () => {
    const f = await fixture();
    const worker = await register(f, "admin@coco.example");
    const granted = await f.workforceAdministration.grantProductWorkforceAccess(grant(worker.humanIdentityId, "staff"));
    advance(f.clock);
    const updated = await f.workforceAdministration.changeTenantRole({ actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: worker.humanIdentityId, tenantRole: "admin" });
    assert.equal(updated.tenantRole, "admin");
    assert.deepEqual(updated.createdAt, granted.membership.createdAt);
    assert.ok(updated.updatedAt > granted.membership.updatedAt);
    assert.equal((await f.services.controlPlane.workforceContext(worker.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID)).tenantRole, "admin");
    assert.deepEqual(f.controlPlaneRepository.auditEvents.at(-1)?.eventData, {
      authorityScope: "internal-workforce-administration",
      previousTenantRole: "staff",
      tenantRole: "admin",
    });
    await assert.rejects(
      () => f.workforceAdministration.changeTenantRole({ actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: worker.humanIdentityId, tenantRole: "founder" }),
      assertCode("INVALID_TENANT_ROLE"),
    );
  });

  it("rejects unknown identities, tenants, products, and unaccountable mutation actors", async () => {
    const f = await fixture();
    await assert.rejects(() => f.workforceAdministration.grantProductWorkforceAccess(grant("missing-identity", "staff")), assertCode("IDENTITY_NOT_FOUND"));
    await assert.rejects(() => f.workforceAdministration.grantProductWorkforceAccess(grant(f.owner.humanIdentityId, "staff", "missing-tenant")), assertCode("TENANT_NOT_FOUND"));
    await assert.rejects(
      () => f.workforceAdministration.grantProductWorkforceAccess({ ...grant(f.owner.humanIdentityId, "staff"), productId: "missing-product" }),
      assertCode("PRODUCT_NOT_FOUND"),
    );
    await assert.rejects(
      () => f.workforceAdministration.grantProductWorkforceAccess({ ...grant(f.owner.humanIdentityId, "staff"), actorReference: "" }),
      assertCode("NOT_AUTHORIZED"),
    );
  });

  it("protects the final active owner during grant, role change, and tenant revocation", async () => {
    const f = await fixture();
    await assert.rejects(() => f.workforceAdministration.changeTenantRole({ actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: f.owner.humanIdentityId, tenantRole: "admin" }), assertCode("LAST_OWNER"));
    await assert.rejects(() => f.workforceAdministration.grantProductWorkforceAccess(grant(f.owner.humanIdentityId, "staff")), assertCode("LAST_OWNER"));
    await assert.rejects(() => f.workforceAdministration.revokeTenantMembership({ actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: f.owner.humanIdentityId }), assertCode("LAST_OWNER"));

    const secondOwner = await register(f, "second-owner@coco.example");
    await f.workforceAdministration.grantProductWorkforceAccess(grant(secondOwner.humanIdentityId, "owner"));
    const demoted = await f.workforceAdministration.changeTenantRole({ actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: f.owner.humanIdentityId, tenantRole: "admin" });
    assert.equal(demoted.tenantRole, "admin");
    await assert.rejects(() => f.workforceAdministration.revokeTenantMembership({ actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: secondOwner.humanIdentityId }), assertCode("LAST_OWNER"));
  });

  it("revokes product access independently from tenant membership and retries safely", async () => {
    const f = await fixture();
    const staff = await register(f, "product-revoke@coco.example");
    await f.workforceAdministration.grantProductWorkforceAccess(grant(staff.humanIdentityId, "staff"));
    const input = { actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, productId: COCO_PRODUCT_ID, humanIdentityId: staff.humanIdentityId };
    const revoked = await f.workforceAdministration.revokeProductAccess(input);
    const auditCount = f.controlPlaneRepository.auditEvents.length;
    const repeated = await f.workforceAdministration.revokeProductAccess(input);
    assert.equal(revoked?.status, "suspended");
    assert.equal(repeated?.status, "suspended");
    assert.equal((await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, staff.humanIdentityId))?.status, "active");
    assert.equal(f.controlPlaneRepository.auditEvents.length, auditCount);
    const context = await f.services.controlPlane.workforceContext(staff.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    assert.equal(context.membershipActive, true);
    assert.equal(context.entitlementActive, false);
    assert.equal(context.workforceContextSatisfied, false);
  });

  it("revokes tenant membership and all of that person's tenant entitlements without deleting identity", async () => {
    const f = await fixture();
    const staff = await register(f, "tenant-revoke@coco.example");
    await f.workforceAdministration.grantProductWorkforceAccess(grant(staff.humanIdentityId, "staff"));
    const input = { actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: staff.humanIdentityId };
    const revoked = await f.workforceAdministration.revokeTenantMembership(input);
    const auditCount = f.controlPlaneRepository.auditEvents.length;
    const repeated = await f.workforceAdministration.revokeTenantMembership(input);
    assert.equal(revoked?.status, "suspended");
    assert.equal(repeated?.status, "suspended");
    assert.equal((await f.controlPlaneRepository.findEntitlement(COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID, staff.humanIdentityId))?.status, "suspended");
    assert.equal((await f.identities.findById(HumanIdentityId.from(staff.humanIdentityId)))?.status, "active");
    assert.equal(f.controlPlaneRepository.auditEvents.length, auditCount);
  });

  it("keeps customer identity independent from workforce and isolates Tenant relationships", async () => {
    const f = await fixture();
    const customer = await register(f, "customer-only@coco.example");
    const otherTenant = "other-tenant";
    await f.controlPlaneRepository.saveTenant({ id: otherTenant, displayName: "Other Tenant", status: "active" });
    await f.workforceAdministration.grantProductWorkforceAccess(grant(customer.humanIdentityId, "staff", otherTenant));
    const cocoContext = await f.services.controlPlane.workforceContext(customer.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID);
    const otherContext = await f.services.controlPlane.workforceContext(customer.humanIdentityId, otherTenant, COCO_PRODUCT_ID);
    assert.equal(cocoContext.membershipActive, false);
    assert.equal(cocoContext.workforceContextSatisfied, false);
    assert.equal(otherContext.workforceContextSatisfied, true);
  });

  it("requires all three independent workforce relationships", async () => {
    const f = await fixture();
    const worker = await register(f, "relationships@coco.example");
    const isolatedTenant = "relationships-tenant";
    await f.controlPlaneRepository.saveTenant({ id: isolatedTenant, displayName: "Relationships Tenant", status: "active" });
    const now = f.clock.now();
    await f.controlPlaneRepository.saveMembership({ tenantId: isolatedTenant, humanIdentityId: worker.humanIdentityId, status: "active", tenantRole: "staff", createdAt: now, updatedAt: now });
    const membershipOnly = await f.services.controlPlane.workforceContext(worker.humanIdentityId, isolatedTenant, COCO_PRODUCT_ID);
    assert.equal(membershipOnly.membershipActive, true);
    assert.equal(membershipOnly.participationActive, false);
    assert.equal(membershipOnly.entitlementActive, false);
    assert.equal(membershipOnly.workforceContextSatisfied, false);
    await f.controlPlaneRepository.saveParticipation({ tenantId: isolatedTenant, productId: COCO_PRODUCT_ID, status: "active" });
    const withoutEntitlement = await f.services.controlPlane.workforceContext(worker.humanIdentityId, isolatedTenant, COCO_PRODUCT_ID);
    assert.equal(withoutEntitlement.participationActive, true);
    assert.equal(withoutEntitlement.entitlementActive, false);
    assert.equal(withoutEntitlement.workforceContextSatisfied, false);
  });

  it("lists the one canonical relationship per tenant and person", async () => {
    const f = await fixture();
    const staff = await register(f, "listed@coco.example");
    await f.workforceAdministration.grantProductWorkforceAccess(grant(staff.humanIdentityId, "staff"));
    await f.workforceAdministration.changeTenantRole({ actorReference, tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: staff.humanIdentityId, tenantRole: "admin" });
    const memberships = await f.workforceAdministration.listTenantWorkforce(COCO_DEVELOPMENT_TENANT_ID);
    assert.equal(memberships.filter((membership) => membership.humanIdentityId === staff.humanIdentityId).length, 1);
    assert.equal((await f.workforceAdministration.inspectTenantMembership(COCO_DEVELOPMENT_TENANT_ID, staff.humanIdentityId)).tenantRole, "admin");
  });
});

function advance(clock: MutableClock): void {
  clock.set(new Date("2026-01-01T00:01:00.000Z"));
}
