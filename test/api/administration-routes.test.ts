import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from "fastify";

import { buildApp } from "../../src/api/app.js";
import {
  COCO_DEVELOPMENT_TENANT_ID,
  COCO_PRODUCT_ID,
  COCO_WORKLOAD_ID,
} from "../../src/control-plane/models.js";
import { buildTestServices } from "../operational/test-doubles.js";

const workloadSecret = "coco-development-workload-secret";
const bootstrapActor = "deployment-operator:test";

async function fixture() {
  const built = buildTestServices();
  const owner = await built.services.register.execute({ email: "owner@coco.example", password: "correct-password" });
  await built.services.controlPlane.bootstrapCoco({ ownerHumanIdentityId: owner.humanIdentityId, workloadSecret, actorReference: bootstrapActor });
  const platformAdministrator = await built.services.register.execute({ email: "administrator@gama.example", password: "correct-password" });
  await built.platformAdministrationProvisioning.bootstrapAdministrator(platformAdministrator.humanIdentityId, bootstrapActor);
  return { ...built, owner, platformAdministrator };
}

function tenantHeaders(sessionId: string, tenantId = COCO_DEVELOPMENT_TENANT_ID, secret = workloadSecret) {
  return {
    authorization: `Bearer ${sessionId}`,
    "x-gama-workload-id": COCO_WORKLOAD_ID,
    "x-gama-workload-secret": secret,
    "x-gama-tenant-id": tenantId,
  };
}

describe("administration HTTP boundaries", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => app?.close());

  it("exposes Platform workforce administration only to a current Platform principal", async () => {
    const f = await fixture();
    const worker = await f.services.register.execute({ email: "worker@coco.example", password: "correct-password" });
    app = buildApp(f.services);

    const tenantOwnerRejected = await app.inject({
      method: "GET",
      url: "/administration/platform/tenants",
      headers: { authorization: `Bearer ${f.owner.session.sessionId}` },
    });
    assert.equal(tenantOwnerRejected.statusCode, 403);
    assert.equal(tenantOwnerRejected.json().error.code, "NOT_PLATFORM_ADMIN");

    const tenants = await app.inject({
      method: "GET",
      url: "/administration/platform/tenants",
      headers: { authorization: `Bearer ${f.platformAdministrator.session.sessionId}` },
    });
    assert.equal(tenants.statusCode, 200);
    assert.equal(tenants.json()[0].id, COCO_DEVELOPMENT_TENANT_ID);

    const resolved = await app.inject({
      method: "GET",
      url: "/administration/platform/identities/resolve?email=worker%40coco.example",
      headers: { authorization: `Bearer ${f.platformAdministrator.session.sessionId}` },
    });
    assert.equal(resolved.statusCode, 200);
    assert.equal(resolved.json().humanIdentityId, worker.humanIdentityId);

    const granted = await app.inject({
      method: "POST",
      url: `/administration/platform/tenants/${COCO_DEVELOPMENT_TENANT_ID}/team`,
      headers: { authorization: `Bearer ${f.platformAdministrator.session.sessionId}` },
      payload: { productId: COCO_PRODUCT_ID, humanIdentityId: worker.humanIdentityId, tenantRole: "owner" },
    });
    assert.equal(granted.statusCode, 200);
    assert.equal(granted.json().membership.tenantRole, "owner");
    assert.equal(f.controlPlaneRepository.auditEvents.at(-1)?.eventData?.authorityScope, "platform-administration");
  });

  it("discovers an Apple-only Human safely and grants Team access by the canonical resolved Human", async () => {
    const f = await fixture();
    f.appleVerifier.accept("apple-team-token", {
      subject: "private-apple-team-subject",
      email: "shared-apple-user@example.com",
      emailVerified: true,
      emailPrivate: false,
    });
    const appleOnly = await f.services.authenticateFederated.execute({
      provider: "apple",
      identityToken: "apple-team-token",
      nonce: "apple_team_nonce_that_is_at_least_32_chars",
    });
    app = buildApp(f.services);
    const platformHeaders = { authorization: `Bearer ${f.platformAdministrator.session.sessionId}` };

    const byEmail = await app.inject({
      method: "GET",
      url: "/administration/platform/identities/resolve?identifier=shared-apple-user%40example.com",
      headers: platformHeaders,
    });
    assert.equal(byEmail.statusCode, 200);
    assert.deepEqual(byEmail.json(), {
      humanIdentityId: appleOnly.humanIdentityId,
      displayName: null,
      email: "shared-apple-user@example.com",
      status: "active",
      signInMethods: ["apple"],
    });
    assert.equal(byEmail.body.includes("private-apple-team-subject"), false);

    const byHumanId = await app.inject({
      method: "GET",
      url: `/administration/platform/identities/resolve?humanIdentityId=${appleOnly.humanIdentityId}`,
      headers: platformHeaders,
    });
    assert.equal(byHumanId.statusCode, 200);
    assert.equal(byHumanId.json().humanIdentityId, appleOnly.humanIdentityId);

    const granted = await app.inject({
      method: "POST",
      url: "/administration/team",
      headers: tenantHeaders(f.owner.session.sessionId),
      payload: { identifier: "shared-apple-user@example.com", tenantRole: "staff" },
    });
    assert.equal(granted.statusCode, 200);
    assert.equal(granted.json().membership.humanIdentityId, appleOnly.humanIdentityId);
    const context = await f.services.controlPlane.workforceContext(
      appleOnly.humanIdentityId,
      COCO_DEVELOPMENT_TENANT_ID,
      COCO_PRODUCT_ID,
    );
    assert.equal(context.workforceContextSatisfied, true);
  });

  it("returns an explicit conflict for ambiguous email discovery and leaves Human-ID fallback unambiguous", async () => {
    const f = await fixture();
    const passwordHuman = await f.services.register.execute({ email: "ambiguous@example.com", password: "correct-password" });
    f.appleVerifier.accept("ambiguous-directory-token", {
      subject: "private-ambiguous-subject",
      email: "ambiguous@example.com",
      emailVerified: true,
    });
    const appleHuman = await f.services.authenticateFederated.execute({
      provider: "apple",
      identityToken: "ambiguous-directory-token",
      nonce: "ambiguous_directory_nonce_at_least_32_chars",
    });
    assert.notEqual(passwordHuman.humanIdentityId, appleHuman.humanIdentityId);
    app = buildApp(f.services);
    const headers = { authorization: `Bearer ${f.platformAdministrator.session.sessionId}` };

    const ambiguous = await app.inject({
      method: "GET",
      url: "/administration/platform/identities/resolve?identifier=ambiguous%40example.com",
      headers,
    });
    assert.equal(ambiguous.statusCode, 409);
    assert.equal(ambiguous.json().error.code, "IDENTITY_AMBIGUOUS");
    assert.equal(ambiguous.body.includes("private-ambiguous-subject"), false);

    const canonical = await app.inject({
      method: "GET",
      url: `/administration/platform/identities/resolve?identifier=${appleHuman.humanIdentityId}`,
      headers,
    });
    assert.equal(canonical.statusCode, 200);
    assert.equal(canonical.json().humanIdentityId, appleHuman.humanIdentityId);
  });

  it("supports the complete Platform Tenant, Product, identity, and Team HTTP workflow", async () => {
    const f = await fixture();
    const initialOwner = await f.services.register.execute({ email: "new-owner@example.com", password: "correct-password" });
    const worker = await f.services.register.execute({ email: "new-worker@example.com", password: "correct-password" });
    await f.controlPlaneRepository.saveProduct({ id: "gama-ledger", displayName: "GAMA Ledger", status: "active" });
    app = buildApp(f.services);
    const headers = { authorization: `Bearer ${f.platformAdministrator.session.sessionId}` };
    const provisioning = {
      idempotencyKey: "11111111-1111-4111-8111-111111111111",
      displayName: "  New Retailer  ",
      initialOwnerHumanIdentityId: initialOwner.humanIdentityId,
    };

    const created = await app.inject({ method: "POST", url: "/administration/platform/tenants", headers, payload: provisioning });
    assert.equal(created.statusCode, 201);
    assert.equal(created.json().tenant.displayName, "New Retailer");
    assert.equal(created.json().initialOwnerMembership.tenantRole, "owner");
    assert.equal(created.json().initialOwnerMembership.status, "active");
    const tenantId = created.json().tenant.id as string;

    const retried = await app.inject({ method: "POST", url: "/administration/platform/tenants", headers, payload: provisioning });
    assert.equal(retried.statusCode, 200);
    assert.equal(retried.json().tenant.id, tenantId);
    assert.equal((await f.controlPlaneRepository.listTenants()).filter((tenant) => tenant.id === tenantId).length, 1);
    assert.equal((await f.controlPlaneRepository.listMembershipsForTenant(tenantId)).length, 1);

    const products = await app.inject({ method: "GET", url: "/administration/platform/products", headers });
    assert.equal(products.statusCode, 200);
    assert.deepEqual(products.json().find((product: { id: string }) => product.id === "gama-ledger"), {
      id: "gama-ledger",
      displayName: "GAMA Ledger",
      status: "active",
    });
    assert.equal(JSON.stringify(products.json()).includes("secret"), false);

    const assigned = await app.inject({ method: "PUT", url: `/administration/platform/tenants/${tenantId}/products/gama-ledger`, headers });
    assert.equal(assigned.statusCode, 200);
    assert.deepEqual(assigned.json(), {
      productId: "gama-ledger",
      displayName: "GAMA Ledger",
      productStatus: "active",
      participationStatus: "active",
    });
    const assignmentAuditCount = f.controlPlaneRepository.auditEvents.filter((event) => event.eventType === "tenant.product.assigned").length;
    assert.equal((await app.inject({ method: "PUT", url: `/administration/platform/tenants/${tenantId}/products/gama-ledger`, headers })).statusCode, 200);
    assert.equal(f.controlPlaneRepository.auditEvents.filter((event) => event.eventType === "tenant.product.assigned").length, assignmentAuditCount);

    const tenantProducts = await app.inject({ method: "GET", url: `/administration/platform/tenants/${tenantId}/products`, headers });
    assert.equal(tenantProducts.statusCode, 200);
    assert.deepEqual(tenantProducts.json(), [assigned.json()]);
    const cocoProducts = await app.inject({ method: "GET", url: `/administration/platform/tenants/${COCO_DEVELOPMENT_TENANT_ID}/products`, headers });
    assert.equal(cocoProducts.json().some((product: { productId: string }) => product.productId === "gama-ledger"), false);

    const resolved = await app.inject({
      method: "GET",
      url: "/administration/platform/identities/resolve?email=new-worker%40example.com",
      headers,
    });
    assert.deepEqual(resolved.json(), {
      humanIdentityId: worker.humanIdentityId,
      displayName: null,
      email: "new-worker@example.com",
      status: "active",
      signInMethods: ["email_password"],
    });
    assert.equal((await app.inject({
      method: "POST",
      url: `/administration/platform/tenants/${tenantId}/team`,
      headers,
      payload: { productId: "gama-ledger", humanIdentityId: worker.humanIdentityId, tenantRole: "admin" },
    })).statusCode, 200);
    const team = await app.inject({ method: "GET", url: `/administration/platform/tenants/${tenantId}/team`, headers });
    const projectedWorker = team.json().find((member: { humanIdentityId: string }) => member.humanIdentityId === worker.humanIdentityId);
    assert.deepEqual(projectedWorker, {
      tenantId,
      humanIdentityId: worker.humanIdentityId,
      displayName: null,
      email: "new-worker@example.com",
      humanIdentityStatus: "active",
      signInMethods: ["email_password"],
      status: "active",
      membershipStatus: "active",
      tenantRole: "admin",
      products: [{
        productId: "gama-ledger",
        displayName: "GAMA Ledger",
        productStatus: "active",
        participationStatus: "active",
        entitlementStatus: "active",
      }],
    });
    assert.equal("passwordHash" in projectedWorker, false);
    assert.equal("providerSubject" in projectedWorker, false);
  });

  it("requires a current Platform Administrator principal on every new Platform route", async () => {
    const f = await fixture();
    const tenantAdmin = await f.services.register.execute({ email: "tenant-admin@example.com", password: "correct-password" });
    const tenantStaff = await f.services.register.execute({ email: "tenant-staff@example.com", password: "correct-password" });
    const ordinaryHuman = await f.services.register.execute({ email: "ordinary@example.com", password: "correct-password" });
    const proposedOwner = await f.services.register.execute({ email: "proposed-owner@example.com", password: "correct-password" });
    for (const [humanIdentityId, tenantRole] of [[tenantAdmin.humanIdentityId, "admin"], [tenantStaff.humanIdentityId, "staff"]] as const) {
      await f.workforceAdministration.grantProductWorkforceAccess({
        actorReference: bootstrapActor,
        tenantId: COCO_DEVELOPMENT_TENANT_ID,
        productId: COCO_PRODUCT_ID,
        humanIdentityId,
        tenantRole,
      });
    }
    app = buildApp(f.services);
    const requests: InjectOptions[] = [
      { method: "POST" as const, url: "/administration/platform/tenants", payload: {
        idempotencyKey: "22222222-2222-4222-8222-222222222222",
        displayName: "Unauthorized Retailer",
        initialOwnerHumanIdentityId: proposedOwner.humanIdentityId,
      } },
      { method: "GET" as const, url: "/administration/platform/products" },
      { method: "GET" as const, url: `/administration/platform/tenants/${COCO_DEVELOPMENT_TENANT_ID}/products` },
      { method: "PUT" as const, url: `/administration/platform/tenants/${COCO_DEVELOPMENT_TENANT_ID}/products/${COCO_PRODUCT_ID}` },
    ];
    const nonPlatformSessions = [
      f.owner.session.sessionId,
      tenantAdmin.session.sessionId,
      tenantStaff.session.sessionId,
      ordinaryHuman.session.sessionId,
    ];
    for (const request of requests) {
      const unauthenticated: LightMyRequestResponse = await app.inject(request);
      assert.equal(unauthenticated.statusCode, 401, `${request.method} ${request.url} unauthenticated`);
      for (const sessionId of nonPlatformSessions) {
        const rejected: LightMyRequestResponse = await app.inject({ ...request, headers: { authorization: `Bearer ${sessionId}` } });
        assert.equal(rejected.statusCode, 403, `${request.method} ${request.url} non-Platform principal`);
        assert.equal(rejected.json().error.code, "NOT_PLATFORM_ADMIN");
      }
    }
    assert.equal((await f.controlPlaneRepository.listTenants()).some((tenant) => tenant.displayName === "Unauthorized Retailer"), false);

    const platformMembership = await f.controlPlaneRepository.findPlatformAdministrationMembership(f.platformAdministrator.humanIdentityId);
    assert.ok(platformMembership);
    await f.controlPlaneRepository.savePlatformAdministrationMembership({ ...platformMembership, status: "suspended", updatedAt: f.clock.now() });
    for (const request of requests) {
      const rejected: LightMyRequestResponse = await app.inject({ ...request, headers: { authorization: `Bearer ${f.platformAdministrator.session.sessionId}` } });
      assert.equal(rejected.statusCode, 403, `${request.method} ${request.url} suspended Platform principal`);
      assert.equal(rejected.json().error.code, "NOT_PLATFORM_ADMIN");
    }
  });

  it("validates Tenant provisioning and maps idempotency and missing-resource conflicts", async () => {
    const f = await fixture();
    const initialOwner = await f.services.register.execute({ email: "validation-owner@example.com", password: "correct-password" });
    app = buildApp(f.services);
    const headers = { authorization: `Bearer ${f.platformAdministrator.session.sessionId}` };

    const invalid = await app.inject({
      method: "POST",
      url: "/administration/platform/tenants",
      headers,
      payload: { idempotencyKey: "not-a-uuid", displayName: "", initialOwnerHumanIdentityId: initialOwner.humanIdentityId },
    });
    assert.equal(invalid.statusCode, 400);
    assert.equal(invalid.json().error.code, "INVALID_REQUEST");

    const payload = {
      idempotencyKey: "33333333-3333-4333-8333-333333333333",
      displayName: "Validation Retailer",
      initialOwnerHumanIdentityId: initialOwner.humanIdentityId,
    };
    assert.equal((await app.inject({ method: "POST", url: "/administration/platform/tenants", headers, payload })).statusCode, 201);
    const reused = await app.inject({
      method: "POST",
      url: "/administration/platform/tenants",
      headers,
      payload: { ...payload, displayName: "Different Retailer" },
    });
    assert.equal(reused.statusCode, 409);
    assert.equal(reused.json().error.code, "IDEMPOTENCY_KEY_REUSED");

    const missingTenant = await app.inject({ method: "GET", url: "/administration/platform/tenants/missing/products", headers });
    assert.equal(missingTenant.statusCode, 404);
    assert.equal(missingTenant.json().error.code, "TENANT_NOT_FOUND");
    const missingProduct = await app.inject({ method: "PUT", url: `/administration/platform/tenants/${COCO_DEVELOPMENT_TENANT_ID}/products/missing`, headers });
    assert.equal(missingProduct.statusCode, 404);
    assert.equal(missingProduct.json().error.code, "PRODUCT_NOT_FOUND");
  });

  it("derives Tenant and Product from authenticated server context and rejects client scope override", async () => {
    const f = await fixture();
    const staff = await f.services.register.execute({ email: "staff@coco.example", password: "correct-password" });
    app = buildApp(f.services);
    const headers = tenantHeaders(f.owner.session.sessionId);

    const queryOverrideIgnored = await app.inject({
      method: "GET",
      url: "/administration/team?tenantId=attacker-tenant&productId=attacker-product",
      headers,
    });
    assert.equal(queryOverrideIgnored.statusCode, 200);
    assert.equal(queryOverrideIgnored.json()[0].humanIdentityId, f.owner.humanIdentityId);

    const bodyOverrideRejected = await app.inject({
      method: "POST",
      url: "/administration/team",
      headers,
      payload: { email: "staff@coco.example", tenantRole: "staff", tenantId: "attacker-tenant", productId: "attacker-product" },
    });
    assert.equal(bodyOverrideRejected.statusCode, 400);
    assert.equal(await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, staff.humanIdentityId), null);

    const granted = await app.inject({
      method: "POST",
      url: "/administration/team",
      headers,
      payload: { email: "staff@coco.example", tenantRole: "staff" },
    });
    assert.equal(granted.statusCode, 200);
    assert.equal(granted.json().membership.tenantId, COCO_DEVELOPMENT_TENANT_ID);
    assert.equal(granted.json().entitlement.productId, COCO_PRODUCT_ID);
    assert.equal(f.controlPlaneRepository.auditEvents.at(-1)?.eventData?.authorityScope, "tenant-team-administration");

    const badWorkload = await app.inject({ method: "GET", url: "/administration/team", headers: tenantHeaders(f.owner.session.sessionId, COCO_DEVELOPMENT_TENANT_ID, "wrong-secret") });
    assert.equal(badWorkload.statusCode, 401);
    assert.equal(badWorkload.json().error.code, "WORKLOAD_INVALID");

    await f.controlPlaneRepository.saveTenant({ id: "other-tenant", displayName: "Other Tenant", status: "active" });
    const crossTenant = await app.inject({ method: "GET", url: "/administration/team", headers: tenantHeaders(f.owner.session.sessionId, "other-tenant") });
    assert.equal(crossTenant.statusCode, 403);
    assert.equal(crossTenant.json().error.code, "NOT_TENANT_ADMIN");
  });

  it("enforces Owner/Admin/Staff policy at the GAMA route boundary", async () => {
    const f = await fixture();
    const admin = await f.services.register.execute({ email: "admin@coco.example", password: "correct-password" });
    const staff = await f.services.register.execute({ email: "staff@coco.example", password: "correct-password" });
    const secondStaff = await f.services.register.execute({ email: "second-staff@coco.example", password: "correct-password" });
    app = buildApp(f.services);
    const ownerHeaders = tenantHeaders(f.owner.session.sessionId);

    assert.equal((await app.inject({ method: "POST", url: "/administration/team", headers: ownerHeaders, payload: { email: "admin@coco.example", tenantRole: "admin" } })).statusCode, 200);
    assert.equal((await app.inject({ method: "POST", url: "/administration/team", headers: ownerHeaders, payload: { email: "staff@coco.example", tenantRole: "staff" } })).statusCode, 200);

    const adminHeaders = tenantHeaders(admin.session.sessionId);
    const adminAddsStaff = await app.inject({ method: "POST", url: "/administration/team", headers: adminHeaders, payload: { email: "second-staff@coco.example", tenantRole: "staff" } });
    assert.equal(adminAddsStaff.statusCode, 200);

    const adminAddsAdmin = await app.inject({ method: "POST", url: "/administration/team", headers: adminHeaders, payload: { email: "second-staff@coco.example", tenantRole: "admin" } });
    assert.equal(adminAddsAdmin.statusCode, 403);
    assert.equal(adminAddsAdmin.json().error.code, "ROLE_ESCALATION_FORBIDDEN");

    const adminRemovesPeer = await app.inject({ method: "DELETE", url: `/administration/team/${admin.humanIdentityId}`, headers: ownerHeaders });
    assert.equal(adminRemovesPeer.statusCode, 200);
    const staffCannotAdminister = await app.inject({ method: "GET", url: "/administration/team", headers: tenantHeaders(staff.session.sessionId) });
    assert.equal(staffCannotAdminister.statusCode, 403);
    assert.equal(staffCannotAdminister.json().error.code, "NOT_TENANT_ADMIN");

    const customer = await f.services.register.execute({ email: "customer@coco.example", password: "correct-password" });
    const customerRejected = await app.inject({ method: "GET", url: "/administration/team", headers: tenantHeaders(customer.session.sessionId) });
    assert.equal(customerRejected.statusCode, 403);
    assert.equal(customerRejected.json().error.code, "NOT_TENANT_ADMIN");
    assert.equal((await f.controlPlaneRepository.findMembership(COCO_DEVELOPMENT_TENANT_ID, secondStaff.humanIdentityId))?.tenantRole, "staff");
  });
});
