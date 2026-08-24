import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { AdministrationAuthorizationError } from "../../src/control-plane/application/administration-principals.js";
import { PlatformAdministrationError } from "../../src/control-plane/application/platform-administration.js";
import { WorkforceAdministrationError } from "../../src/control-plane/application/workforce-administration.js";
import { HumanIdentity } from "../../src/identity/domain/human-identity.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import {
  COCO_DEVELOPMENT_TENANT_ID,
  COCO_PRODUCT_ID,
} from "../../src/control-plane/models.js";
import { buildTestServices } from "../operational/test-doubles.js";

const workloadSecret = "coco-development-workload-secret";
const bootstrapActor = "deployment-operator:test";

async function fixture() {
  const built = buildTestServices();
  const owner = await register(built, "owner@coco.example");
  await built.services.controlPlane.bootstrapCoco({
    ownerHumanIdentityId: owner.humanIdentityId,
    workloadSecret,
    actorReference: bootstrapActor,
  });
  const platformAdministrator = await register(built, "platform-admin@gama.example");
  await built.platformAdministrationProvisioning.bootstrapAdministrator(
    platformAdministrator.humanIdentityId,
    bootstrapActor,
  );
  return { ...built, owner, platformAdministrator };
}

type TestFixture = ReturnType<typeof buildTestServices>;

async function register(fixture: TestFixture, email: string) {
  return fixture.services.register.execute({ email, password: "correct-password" });
}

function tenantContext(actorHumanIdentityId: string, tenantId = COCO_DEVELOPMENT_TENANT_ID, productId = COCO_PRODUCT_ID) {
  return { actorHumanIdentityId, tenantId, productId };
}

function hasCode(code: string) {
  return (value: unknown) =>
    (
      value instanceof AdministrationAuthorizationError ||
      value instanceof PlatformAdministrationError ||
      value instanceof WorkforceAdministrationError
    ) && value.code === code;
}

describe("administration principal boundaries", () => {
  it("accepts only a current active Platform administrator membership", async () => {
    const f = await fixture();
    await assert.doesNotReject(() => f.services.administration.platform.listTenants(f.platformAdministrator.humanIdentityId));
    const platformAdministratorCocoContext = await f.services.controlPlane.workforceContext(
      f.platformAdministrator.humanIdentityId,
      COCO_DEVELOPMENT_TENANT_ID,
      COCO_PRODUCT_ID,
    );
    assert.equal(platformAdministratorCocoContext.workforceContextSatisfied, false);
    assert.deepEqual(platformAdministratorCocoContext.capabilities, []);
    await assert.rejects(
      () => f.services.administration.platform.listTenants(f.owner.humanIdentityId),
      hasCode("NOT_PLATFORM_ADMIN"),
    );

    for (const [email, tenantRole] of [["tenant-admin@coco.example", "admin"], ["tenant-staff@coco.example", "staff"]] as const) {
      const tenantWorker = await register(f, email);
      await f.workforceAdministration.grantProductWorkforceAccess({
        actorReference: bootstrapActor,
        tenantId: COCO_DEVELOPMENT_TENANT_ID,
        productId: COCO_PRODUCT_ID,
        humanIdentityId: tenantWorker.humanIdentityId,
        tenantRole,
      });
      await assert.rejects(
        () => f.services.administration.platform.listTenants(tenantWorker.humanIdentityId),
        hasCode("NOT_PLATFORM_ADMIN"),
      );
    }
    const ordinaryHuman = await register(f, "ordinary@gama.example");
    await assert.rejects(
      () => f.services.administration.platform.listTenants(ordinaryHuman.humanIdentityId),
      hasCode("NOT_PLATFORM_ADMIN"),
    );

    const membership = await f.controlPlaneRepository.findPlatformAdministrationMembership(f.platformAdministrator.humanIdentityId);
    assert.ok(membership);
    await f.controlPlaneRepository.savePlatformAdministrationMembership({
      ...membership,
      status: "suspended",
      updatedAt: f.clock.now(),
    });
    await assert.rejects(
      () => f.services.administration.platform.listTenants(f.platformAdministrator.humanIdentityId),
      hasCode("NOT_PLATFORM_ADMIN"),
    );
  });

  it("bootstraps a Platform administrator explicitly, idempotently, and auditably", async () => {
    const f = buildTestServices();
    const administrator = await register(f, "administrator@gama.example");
    const [first, concurrent] = await Promise.all([
      f.platformAdministrationProvisioning.bootstrapAdministrator(administrator.humanIdentityId, bootstrapActor),
      f.platformAdministrationProvisioning.bootstrapAdministrator(administrator.humanIdentityId, bootstrapActor),
    ]);
    assert.deepEqual(concurrent, first);
    const auditCount = f.controlPlaneRepository.auditEvents.length;
    const retry = await f.platformAdministrationProvisioning.bootstrapAdministrator(administrator.humanIdentityId, bootstrapActor);
    assert.deepEqual(retry, first);
    assert.equal(auditCount, 1);
    assert.equal(f.controlPlaneRepository.auditEvents.length, auditCount);
    assert.deepEqual(f.controlPlaneRepository.auditEvents.at(-1)?.eventData, {
      authorityScope: "deployment-bootstrap",
      platformRole: "administrator",
      status: "active",
    });
  });

  it("provisions one stable Tenant with an atomic initial Owner and retry-safe request identity", async () => {
    const f = await fixture();
    const initialOwner = await register(f, "new-owner@example.com");
    const input = {
      idempotencyKey: "11111111-1111-4111-8111-111111111111",
      displayName: "  New Retailer  ",
      initialOwnerHumanIdentityId: initialOwner.humanIdentityId,
    };
    const concurrentResults = await Promise.all([
      f.services.administration.platform.provisionTenant(f.platformAdministrator.humanIdentityId, input),
      f.services.administration.platform.provisionTenant(f.platformAdministrator.humanIdentityId, input),
    ]);
    assert.deepEqual(concurrentResults.map((result) => result.created).sort(), [false, true]);
    const first = concurrentResults.find((result) => result.created);
    const concurrentRetry = concurrentResults.find((result) => !result.created);
    assert.ok(first);
    assert.ok(concurrentRetry);
    assert.equal(concurrentRetry.tenant.id, first.tenant.id);
    assert.deepEqual(first.tenant, { id: "tenant-1", displayName: "New Retailer", status: "active" });
    assert.equal(first.initialOwnerMembership.tenantRole, "owner");
    assert.equal(first.initialOwnerMembership.status, "active");
    assert.equal((await f.controlPlaneRepository.listMembershipsForTenant(first.tenant.id)).length, 1);

    const auditCount = f.controlPlaneRepository.auditEvents.length;
    const retry = await f.services.administration.platform.provisionTenant(f.platformAdministrator.humanIdentityId, input);
    assert.equal(retry.created, false);
    assert.deepEqual(retry.tenant, first.tenant);
    assert.deepEqual(retry.initialOwnerMembership, first.initialOwnerMembership);
    assert.equal(f.controlPlaneRepository.auditEvents.length, auditCount);
    assert.equal(f.controlPlaneRepository.auditEvents.filter((event) => event.eventType === "tenant.created").length, 1);
    assert.deepEqual(f.controlPlaneRepository.auditEvents.find((event) => event.eventType === "tenant.created")?.eventData, {
      authorityScope: "platform-administration",
      displayName: "New Retailer",
      initialOwnerHumanIdentityId: initialOwner.humanIdentityId,
      status: "active",
    });

    await assert.rejects(
      () => f.services.administration.platform.provisionTenant(f.platformAdministrator.humanIdentityId, {
        ...input,
        displayName: "Different Retailer",
      }),
      hasCode("IDEMPOTENCY_KEY_REUSED"),
    );
    const sameDisplayNewRequest = await f.services.administration.platform.provisionTenant(
      f.platformAdministrator.humanIdentityId,
      { ...input, idempotencyKey: "22222222-2222-4222-8222-222222222222" },
    );
    assert.equal(sameDisplayNewRequest.created, true);
    assert.notEqual(sameDisplayNewRequest.tenant.id, first.tenant.id);
    assert.equal(sameDisplayNewRequest.tenant.displayName, first.tenant.displayName);
    await assert.rejects(
      () => f.services.administration.platform.provisionTenant(f.platformAdministrator.humanIdentityId, {
        idempotencyKey: "66666666-6666-4666-8666-666666666666",
        displayName: "No Owner",
        initialOwnerHumanIdentityId: "missing-human",
      }),
      hasCode("IDENTITY_NOT_FOUND"),
    );
    await assert.rejects(
      () => f.services.administration.platform.changeTenantRole(
        f.platformAdministrator.humanIdentityId,
        first.tenant.id,
        initialOwner.humanIdentityId,
        "staff",
      ),
      hasCode("LAST_OWNER"),
    );
  });

  it("uses Product Participation as the human-independent Tenant Product relationship", async () => {
    const f = await fixture();
    const initialOwner = await register(f, "product-owner@example.com");
    await f.controlPlaneRepository.saveProduct({ id: "ledger", displayName: "GAMA Ledger", status: "active" });
    await f.controlPlaneRepository.saveProduct({ id: "reconnect", displayName: "Reconnect Product", status: "active" });
    await f.controlPlaneRepository.saveProduct({ id: "suspended-product", displayName: "Suspended Product", status: "suspended" });
    await f.controlPlaneRepository.saveProduct({ id: "retired-product", displayName: "Retired Product", status: "retired" });
    const provisioned = await f.services.administration.platform.provisionTenant(f.platformAdministrator.humanIdentityId, {
      idempotencyKey: "33333333-3333-4333-8333-333333333333",
      displayName: "Product Retailer",
      initialOwnerHumanIdentityId: initialOwner.humanIdentityId,
    });

    const directory = await f.services.administration.platform.listProducts(f.platformAdministrator.humanIdentityId);
    assert.deepEqual(directory.find((product) => product.id === "ledger"), {
      id: "ledger",
      displayName: "GAMA Ledger",
      status: "active",
    });
    assert.equal(directory.find((product) => product.id === "retired-product")?.status, "retired");
    assert.deepEqual(await f.services.administration.platform.listTenantProducts(
      f.platformAdministrator.humanIdentityId,
      provisioned.tenant.id,
    ), []);

    const assigned = await f.services.administration.platform.assignTenantProduct(
      f.platformAdministrator.humanIdentityId,
      provisioned.tenant.id,
      "ledger",
    );
    assert.deepEqual(assigned, {
      productId: "ledger",
      displayName: "GAMA Ledger",
      productStatus: "active",
      participationStatus: "active",
    });
    assert.equal(await f.controlPlaneRepository.findEntitlement(provisioned.tenant.id, "ledger", initialOwner.humanIdentityId), null);
    const auditCount = f.controlPlaneRepository.auditEvents.length;
    assert.deepEqual(
      await f.services.administration.platform.assignTenantProduct(f.platformAdministrator.humanIdentityId, provisioned.tenant.id, "ledger"),
      assigned,
    );
    assert.equal(f.controlPlaneRepository.auditEvents.length, auditCount);
    assert.deepEqual(await f.services.administration.platform.listTenantProducts(
      f.platformAdministrator.humanIdentityId,
      provisioned.tenant.id,
    ), [assigned]);

    await f.controlPlaneRepository.saveParticipation({ tenantId: provisioned.tenant.id, productId: "reconnect", status: "suspended" });
    const reactivated = await f.services.administration.platform.assignTenantProduct(
      f.platformAdministrator.humanIdentityId,
      provisioned.tenant.id,
      "reconnect",
    );
    assert.equal(reactivated.participationStatus, "active");
    assert.deepEqual(f.controlPlaneRepository.auditEvents.at(-1)?.eventData, {
      authorityScope: "platform-administration",
      previousParticipationStatus: "suspended",
      participationStatus: "active",
    });

    await assert.rejects(
      () => f.services.administration.platform.assignTenantProduct(f.platformAdministrator.humanIdentityId, "missing-tenant", "ledger"),
      hasCode("TENANT_NOT_FOUND"),
    );
    await assert.rejects(
      () => f.services.administration.platform.assignTenantProduct(f.platformAdministrator.humanIdentityId, provisioned.tenant.id, "missing-product"),
      hasCode("PRODUCT_NOT_FOUND"),
    );
    await assert.rejects(
      () => f.services.administration.platform.assignTenantProduct(f.platformAdministrator.humanIdentityId, provisioned.tenant.id, "suspended-product"),
      hasCode("PRODUCT_NOT_AVAILABLE"),
    );
    await assert.rejects(
      () => f.services.administration.platform.assignTenantProduct(f.platformAdministrator.humanIdentityId, provisioned.tenant.id, "retired-product"),
      hasCode("PRODUCT_NOT_AVAILABLE"),
    );
  });

  it("projects safe Human display fields and supports the complete discovery-to-grant path", async () => {
    const f = await fixture();
    const initialOwner = await register(f, "directory-owner@example.com");
    const worker = await register(f, "Worker@Example.com");
    await f.controlPlaneRepository.saveProduct({ id: "operations", displayName: "GAMA Operations", status: "active" });
    const provisioned = await f.services.administration.platform.provisionTenant(f.platformAdministrator.humanIdentityId, {
      idempotencyKey: "44444444-4444-4444-8444-444444444444",
      displayName: "Directory Retailer",
      initialOwnerHumanIdentityId: initialOwner.humanIdentityId,
    });
    await f.services.administration.platform.assignTenantProduct(f.platformAdministrator.humanIdentityId, provisioned.tenant.id, "operations");
    const resolved = await f.services.administration.platform.resolveHumanIdentityByEmail(
      f.platformAdministrator.humanIdentityId,
      "Worker@example.com",
    );
    assert.deepEqual(resolved, {
      humanIdentityId: worker.humanIdentityId,
      displayName: null,
      email: "Worker@example.com",
      status: "active",
      signInMethods: ["email_password"],
    });
    await f.services.administration.platform.grantProductWorkforceAccess(f.platformAdministrator.humanIdentityId, {
      tenantId: provisioned.tenant.id,
      productId: "operations",
      humanIdentityId: worker.humanIdentityId,
      tenantRole: "admin",
    });
    const team = await f.services.administration.platform.listTenantWorkforce(
      f.platformAdministrator.humanIdentityId,
      provisioned.tenant.id,
    );
    assert.deepEqual(team.find((member) => member.humanIdentityId === worker.humanIdentityId), {
      tenantId: provisioned.tenant.id,
      humanIdentityId: worker.humanIdentityId,
      displayName: null,
      email: "Worker@example.com",
      humanIdentityStatus: "active",
      signInMethods: ["email_password"],
      status: "active",
      membershipStatus: "active",
      tenantRole: "admin",
      products: [{
        productId: "operations",
        displayName: "GAMA Operations",
        productStatus: "active",
        participationStatus: "active",
        entitlementStatus: "active",
      }],
    });

    const identityWithoutCredential = HumanIdentity.reconstitute({
      id: HumanIdentityId.from("identity-without-email"),
      status: "active",
      createdAt: f.clock.now(),
      updatedAt: f.clock.now(),
    });
    await f.identities.save(identityWithoutCredential);
    await f.controlPlaneRepository.saveMembership({
      tenantId: provisioned.tenant.id,
      humanIdentityId: identityWithoutCredential.id.value,
      status: "active",
      tenantRole: "staff",
      createdAt: f.clock.now(),
      updatedAt: f.clock.now(),
    });
    const optionalProjection = (await f.services.administration.platform.listTenantWorkforce(
      f.platformAdministrator.humanIdentityId,
      provisioned.tenant.id,
    )).find((member) => member.humanIdentityId === identityWithoutCredential.id.value);
    assert.equal(optionalProjection?.displayName, null);
    assert.equal(optionalProjection?.email, null);
    assert.equal("passwordHash" in (optionalProjection ?? {}), false);
  });

  it("allows a Platform administrator to select a real Tenant and perform the full workforce contract", async () => {
    const f = await fixture();
    const worker = await register(f, "worker@coco.example");
    const resolved = await f.services.administration.platform.resolveHumanIdentityByEmail(
      f.platformAdministrator.humanIdentityId,
      "worker@COCO.EXAMPLE",
    );
    assert.equal(resolved.humanIdentityId, worker.humanIdentityId);
    await f.services.administration.platform.grantProductWorkforceAccess(f.platformAdministrator.humanIdentityId, {
      tenantId: COCO_DEVELOPMENT_TENANT_ID,
      productId: COCO_PRODUCT_ID,
      humanIdentityId: worker.humanIdentityId,
      tenantRole: "owner",
    });
    const changed = await f.services.administration.platform.changeTenantRole(
      f.platformAdministrator.humanIdentityId,
      COCO_DEVELOPMENT_TENANT_ID,
      worker.humanIdentityId,
      "admin",
    );
    assert.equal(changed.tenantRole, "admin");
    assert.equal((await f.services.administration.platform.listTenantWorkforce(
      f.platformAdministrator.humanIdentityId,
      COCO_DEVELOPMENT_TENANT_ID,
    )).some((membership) => membership.humanIdentityId === worker.humanIdentityId), true);
    await f.services.administration.platform.revokeProductAccess(
      f.platformAdministrator.humanIdentityId,
      COCO_DEVELOPMENT_TENANT_ID,
      COCO_PRODUCT_ID,
      worker.humanIdentityId,
    );
    assert.equal((await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, worker.humanIdentityId))?.status, "active");
    await f.services.administration.platform.revokeTenantMembership(
      f.platformAdministrator.humanIdentityId,
      COCO_DEVELOPMENT_TENANT_ID,
      worker.humanIdentityId,
    );
    assert.equal((await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, worker.humanIdentityId))?.status, "suspended");
    assert.equal(f.controlPlaneRepository.auditEvents.at(-1)?.eventData?.authorityScope, "platform-administration");
    await assert.rejects(
      () => f.services.administration.platform.listTenantWorkforce(f.platformAdministrator.humanIdentityId, "unknown-tenant"),
      hasCode("TENANT_NOT_FOUND"),
    );
  });
});

describe("tenant Team administration policy", () => {
  it("lets Owner and Admin list only a workforce-authorized Tenant while Staff and customers are denied", async () => {
    const f = await fixture();
    const admin = await register(f, "admin@coco.example");
    const staff = await register(f, "staff@coco.example");
    const customer = await register(f, "customer@coco.example");
    for (const [humanIdentityId, tenantRole] of [[admin.humanIdentityId, "admin"], [staff.humanIdentityId, "staff"]] as const) {
      await f.workforceAdministration.grantProductWorkforceAccess({
        actorReference: bootstrapActor,
        tenantId: COCO_DEVELOPMENT_TENANT_ID,
        productId: COCO_PRODUCT_ID,
        humanIdentityId,
        tenantRole,
      });
    }
    const ownerTeam = await f.services.administration.tenantTeam.listTeam(tenantContext(f.owner.humanIdentityId));
    const adminTeam = await f.services.administration.tenantTeam.listTeam(tenantContext(admin.humanIdentityId));
    assert.equal(ownerTeam.length, 3);
    assert.deepEqual(adminTeam.find((member) => member.humanIdentityId === staff.humanIdentityId), {
      humanIdentityId: staff.humanIdentityId,
      email: "staff@coco.example",
      signInMethods: ["email_password"],
      tenantRole: "staff",
      membershipStatus: "active",
      productParticipationStatus: "active",
      productEntitlementStatus: "active",
    });
    await assert.rejects(() => f.services.administration.tenantTeam.listTeam(tenantContext(staff.humanIdentityId)), hasCode("NOT_TENANT_ADMIN"));
    await assert.rejects(() => f.services.administration.tenantTeam.listTeam(tenantContext(customer.humanIdentityId)), hasCode("NOT_TENANT_ADMIN"));
    await assert.rejects(() => f.services.administration.tenantTeam.listTeam(tenantContext(f.owner.humanIdentityId, "other-tenant")), hasCode("NOT_TENANT_ADMIN"));
    await assert.rejects(() => f.services.administration.tenantTeam.listTeam(tenantContext(f.owner.humanIdentityId, COCO_DEVELOPMENT_TENANT_ID, "other-product")), hasCode("NOT_TENANT_ADMIN"));
  });

  it("enforces the conservative Owner/Admin role hierarchy and self-mutation firewall", async () => {
    const f = await fixture();
    const admin = await register(f, "admin@coco.example");
    const staff = await register(f, "staff@coco.example");
    const secondStaff = await register(f, "second-staff@coco.example");
    const adminPeer = await register(f, "admin-peer@coco.example");
    await f.services.administration.tenantTeam.addTeamMember(tenantContext(f.owner.humanIdentityId), "admin@coco.example", "admin");
    await f.services.administration.tenantTeam.addTeamMember(tenantContext(f.owner.humanIdentityId), "staff@coco.example", "staff");
    await f.services.administration.tenantTeam.addTeamMember(tenantContext(f.owner.humanIdentityId), "admin-peer@coco.example", "admin");
    await f.services.administration.tenantTeam.addTeamMember(tenantContext(admin.humanIdentityId), "second-staff@coco.example", "staff");
    assert.equal((await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, secondStaff.humanIdentityId))?.tenantRole, "staff");

    await assert.rejects(
      () => f.services.administration.tenantTeam.addTeamMember(tenantContext(admin.humanIdentityId), "second-staff@coco.example", "admin"),
      hasCode("ROLE_ESCALATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.addTeamMember(tenantContext(admin.humanIdentityId), "second-staff@coco.example", "owner"),
      hasCode("ROLE_ESCALATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.addTeamMember(tenantContext(f.owner.humanIdentityId), "second-staff@coco.example", "owner"),
      hasCode("ROLE_ESCALATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.removeTeamMember(tenantContext(admin.humanIdentityId), f.owner.humanIdentityId),
      hasCode("ROLE_ESCALATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.removeTeamMember(tenantContext(admin.humanIdentityId), adminPeer.humanIdentityId),
      hasCode("ROLE_ESCALATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.removeTeamMember(tenantContext(admin.humanIdentityId), admin.humanIdentityId),
      hasCode("SELF_MUTATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.addTeamMember(tenantContext(f.owner.humanIdentityId), "owner@coco.example", "staff"),
      hasCode("SELF_MUTATION_FORBIDDEN"),
    );

    const promoted = await f.services.administration.tenantTeam.changeTeamMemberRole(
      tenantContext(f.owner.humanIdentityId),
      staff.humanIdentityId,
      "admin",
    );
    assert.equal(promoted.tenantRole, "admin");
    await assert.rejects(
      () => f.services.administration.tenantTeam.changeTeamMemberRole(tenantContext(admin.humanIdentityId), secondStaff.humanIdentityId, "admin"),
      hasCode("ROLE_ESCALATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.changeTeamMemberRole(tenantContext(admin.humanIdentityId), admin.humanIdentityId, "owner"),
      hasCode("SELF_MUTATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.changeTeamMemberRole(tenantContext(f.owner.humanIdentityId), admin.humanIdentityId, "owner"),
      hasCode("ROLE_ESCALATION_FORBIDDEN"),
    );
    await assert.rejects(
      () => f.services.administration.tenantTeam.addTeamMember(tenantContext(f.owner.humanIdentityId), "missing@coco.example", "staff"),
      hasCode("IDENTITY_NOT_FOUND"),
    );
  });

  it("derives Product scope, converges on retries, and keeps Product revocation separate from membership", async () => {
    const f = await fixture();
    const staff = await register(f, "retry-staff@coco.example");
    const context = tenantContext(f.owner.humanIdentityId);
    const first = await f.services.administration.tenantTeam.addTeamMember(context, "retry-staff@coco.example", "staff");
    const auditCount = f.controlPlaneRepository.auditEvents.length;
    const repeated = await f.services.administration.tenantTeam.addTeamMember(context, "retry-staff@coco.example", "staff");
    assert.deepEqual(repeated, first);
    assert.equal(f.controlPlaneRepository.auditEvents.length, auditCount);
    assert.equal(f.controlPlaneRepository.auditEvents.at(-1)?.eventData?.authorityScope, "tenant-team-administration");
    await f.services.administration.tenantTeam.revokeProductAccess(context, staff.humanIdentityId);
    assert.equal((await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, staff.humanIdentityId))?.status, "active");
    assert.equal((await f.controlPlaneRepository.findEntitlement(COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID, staff.humanIdentityId))?.status, "suspended");
    await f.services.administration.tenantTeam.grantProductAccess(context, staff.humanIdentityId);
    assert.equal((await f.controlPlaneRepository.findEntitlement(COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID, staff.humanIdentityId))?.status, "active");
    await f.services.administration.tenantTeam.removeTeamMember(context, staff.humanIdentityId);
    assert.equal((await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, staff.humanIdentityId))?.status, "suspended");
    await assert.rejects(
      () => f.services.administration.tenantTeam.grantProductAccess(context, staff.humanIdentityId),
      hasCode("MEMBERSHIP_INACTIVE"),
    );
    assert.equal((await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, staff.humanIdentityId))?.status, "suspended");
  });
});
