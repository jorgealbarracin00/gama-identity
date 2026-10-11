import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { buildRuntime, type ApplicationRuntime, type IdentityServices } from "../../src/api/services.js";
import { buildApp } from "../../src/api/app.js";
import { loadConfig } from "../../src/config/env.js";
import { PostgresDatabase } from "../../src/infrastructure/postgres/database.js";
import { PostgresControlPlaneRepository } from "../../src/infrastructure/postgres/postgres-control-plane-repository.js";
import { Argon2PasswordOperations } from "../../src/authentication/adapters/argon2-password-operations.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { syntheticManagementEnabled } from "../../src/control-plane/application/identity-management.js";
import { integrationFacts, productIntegrationSchema } from "../../src/control-plane/application/product-integration.js";

const url = process.env.POSTGRES_PARTICIPATION_TEST_DATABASE_URL;
const password = "Synthetic-password-123!", secret = "Synthetic-product-workload-secret-123!";
const integration = { productId: "cashcast", integrationStatus: "gama_identity", participationRecording: "missing", evidenceReference: "synthetic-fixture-only", verifiedAt: "2026-10-11T00:00:00Z", warnings: ["This fixture is not a live product integration."], webAppIds: ["synthetic-web"], reportingWorkloadId: "cashcast-workload" };

describe("V2.2 factual product integration configuration", () => {
  it("defaults to unknown and does not translate workload availability into verified integration", () => {
    assert.equal(integrationFacts(undefined).integrationStatus, "unknown");
    assert.equal(integrationFacts(undefined).participationRecording, "unknown");
    assert.deepEqual(loadConfig({}).IDENTITY_PRODUCT_INTEGRATIONS, []);
  });
  it("rejects contradictory integration claims, ambiguous mappings and missing web reporting authority", () => {
    for (const input of [
      [{ ...integration, integrationStatus: "cloudkit_only" }],
      [{ ...integration, reportingWorkloadId: undefined }],
      [integration, integration],
      [integration, { ...integration, productId: "other" }],
      [{ ...integration, evidenceReference: "" }],
    ]) assert.equal(productIntegrationSchema.safeParse(input).success, false);
    assert.ok(productIntegrationSchema.safeParse([{ productId: "cloudkit-product", integrationStatus: "cloudkit_only", participationRecording: "not_applicable", evidenceReference: "source-audit-fixture", verifiedAt: "2026-10-11T00:00:00Z" }]).success);
  });
});

describe("V2.2 canonical product participation and bounded administration", { skip: !url }, () => {
  let db: PostgresDatabase, runtime: ApplicationRuntime, app: FastifyInstance, plane: PostgresControlPlaneRepository;
  let admin: string, adminSession: string, human: string, session: string, other: string, hash: string;
  const centre = () => runtime.services.administration.controlCentre!;
  const request = (path: string, payload: Record<string, unknown> = {}, bearer = adminSession, headers: Record<string, string> = {}) => app.inject({ method: "POST", url: path, payload, headers: { ...(bearer ? { authorization: `Bearer ${bearer}` } : {}), ...headers } });
  const reporter = (product = "cashcast") => ({ "x-gama-workload-id": `${product}-workload`, "x-gama-workload-secret": secret });
  const register = (product = "cashcast", payload: Record<string, unknown> = {}, bearer = session) => request("/control/human-participation", payload, bearer, reporter(product));
  const backfill = (entries: { humanIdentityId: string; evidenceReference: string }[], bearer = adminSession) => request("/administration/platform/products/participation/backfill/preview", { entries }, bearer, reporter());
  before(async () => {
    assert.ok(syntheticManagementEnabled({ NODE_ENV: "test", REPOSITORY_MODE: "postgres", DATABASE_URL: url! }), "Synthetic fixtures must use a separate localhost *_management_test database");
    db = new PostgresDatabase(url!);
    runtime = await buildRuntime(loadConfig({ NODE_ENV: "test", REPOSITORY_MODE: "postgres", DATABASE_URL: url!, LOG_LEVEL: "silent", PASSWORD_HASH_MEMORY_KIB: "8192", PASSWORD_HASH_ITERATIONS: "2", IDENTITY_PRODUCT_INTEGRATIONS: JSON.stringify([integration, { productId: "cloudkit-product", integrationStatus: "cloudkit_only", participationRecording: "not_applicable", evidenceReference: "synthetic-source-audit", verifiedAt: "2026-10-11T00:00:00Z" }]) }));
    plane = new PostgresControlPlaneRepository(db);
    hash = (await new Argon2PasswordOperations({ memoryCost: 8192, timeCost: 2, parallelism: 1 }).hash(secret)).value;
    app = buildApp(runtime.services, runtime.databaseHealth);
  });
  after(async () => { await app?.close(); await runtime?.close(); await db?.close(); });
  beforeEach(async () => {
    await db.query("TRUNCATE human_identities, registered_products, tenants, platform_audit_events, federated_authentication_nonces CASCADE");
    const a = await runtime.services.register.execute({ email: "admin@participation.example", password }); admin = a.humanIdentityId; adminSession = a.session.sessionId;
    await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin, "synthetic-fixture");
    const h = await runtime.services.register.execute({ email: "human@participation.example", password }); human = h.humanIdentityId; session = h.session.sessionId;
    const o = await runtime.services.register.execute({ email: "other@participation.example", password }); other = o.humanIdentityId;
    for (const product of ["cashcast", "coco-the-llama", "grocery-master", "cloudkit-product", "unknown-integration"]) {
      await plane.saveProduct({ id: product, displayName: product, status: "active" });
      await plane.saveWorkload({ id: `${product}-workload`, productId: product, secretHash: hash, status: "active" });
    }
  });
  it("demonstrates one canonical Human across three registered synthetic products after repeated authentication", async () => {
    const canonicalCount = (await db.query("SELECT count(*)::int AS count FROM human_identities")).rows[0]!.count;
    for (const product of ["cashcast", "coco-the-llama", "grocery-master"]) {
      const first = await register(product); assert.equal(first.statusCode, 200); assert.equal(first.json().humanIdentityId, human); assert.equal(first.json().created, true);
      const fresh = await runtime.services.login.execute({ email: "human@participation.example", password });
      const second = await register(product, {}, fresh.sessionId); assert.equal(second.statusCode, 200); assert.equal(second.json().humanIdentityId, human); assert.equal(second.json().created, false);
    }
    assert.equal((await db.query("SELECT count(*)::int AS count FROM human_identities")).rows[0]!.count, canonicalCount);
    const rows = (await db.query("SELECT product_id FROM human_product_participations WHERE human_identity_id=$1 ORDER BY product_id", [human])).rows;
    assert.deepEqual(rows.map(r => r.product_id), ["cashcast", "coco-the-llama", "grocery-master"]);
    assert.equal((await db.query("SELECT 1 FROM tenant_memberships WHERE human_identity_id=$1", [human])).rowCount, 0);
    assert.equal((await db.query("SELECT 1 FROM product_entitlements WHERE human_identity_id=$1", [human])).rowCount, 0);
    const console = await request("/administration/platform/humans/products/query", { humanIdentityId: human });
    assert.equal(console.statusCode, 200); assert.equal(console.json().products.length, 3);
    for (const product of ["cashcast", "coco-the-llama", "grocery-master"]) {
      const screen = await request("/administration/platform/products/humans/query", { productId: product });
      assert.deepEqual(screen.json().humans.map((h: any) => h.humanIdentityId), [human]);
    }
    assert.equal((await db.query("SELECT 1 FROM platform_audit_events WHERE event_type='human.product.participation.registered'")).rowCount, 3);
  });
  it("serializes concurrent registration and never overwrites timestamps on retry", async () => {
    const results = await Promise.all(Array.from({ length: 8 }, () => register()));
    assert.ok(results.every(r => r.statusCode === 200)); assert.equal(results.filter(r => r.json().created).length, 1);
    const before = (await db.query("SELECT * FROM human_product_participations")).rows;
    await register(); assert.deepEqual((await db.query("SELECT * FROM human_product_participations")).rows, before);
    assert.equal((await db.query("SELECT 1 FROM platform_audit_events WHERE event_type='human.product.participation.registered'")).rowCount, 1);
  });
  it("keeps entitlement, subscription-like access and business membership independent from participation", async () => {
    await plane.saveTenant({ id: "business", displayName: "Business", status: "active" });
    await plane.saveMembership({ tenantId: "business", humanIdentityId: other, tenantRole: "staff", status: "active", createdAt: new Date(), updatedAt: new Date() });
    await plane.saveParticipation({ tenantId: "business", productId: "cashcast", status: "active" });
    await plane.saveEntitlement({ tenantId: "business", productId: "cashcast", humanIdentityId: other, status: "active" });
    await register();
    const products = (await request("/administration/platform/products/inspect")).json().products;
    const cashcast = products.find((p: any) => p.id === "cashcast"); assert.equal(cashcast.participants, 1); assert.equal(cashcast.entitledHumans, 1); assert.equal(cashcast.businesses, 1);
    assert.deepEqual((await request("/administration/platform/products/humans/query", { productId: "cashcast" })).json().humans.map((h: any) => h.humanIdentityId), [human]);
    assert.deepEqual((await request("/administration/platform/products/humans/query", { productId: "cashcast", relationship: "entitlement" })).json().humans.map((h: any) => h.humanIdentityId), [other]);
    assert.equal((await request("/administration/platform/humans/products/query", { humanIdentityId: other })).json().products.length, 0);
    assert.equal((await request("/administration/platform/humans/products/query", { humanIdentityId: other, relationship: "entitlement" })).json().products[0].participationStatus, null);
  });
  it("rejects cross-Human and product spoofing, unknown workloads and unauthenticated requests", async () => {
    assert.equal((await register("cashcast", { humanIdentityId: other })).statusCode, 400);
    assert.equal((await register("cashcast", { productId: "grocery-master" })).statusCode, 400);
    assert.equal((await register("unknown-product")).statusCode, 401);
    assert.equal((await register("cashcast", {}, "")).statusCode, 401);
    assert.equal((await request("/control/human-participation", {}, session, { ...reporter(), "x-gama-workload-secret": "invalid" })).statusCode, 401);
    assert.equal((await db.query("SELECT 1 FROM human_product_participations")).rowCount, 0);
  });
  it("enforces product, workload, Human, session and retained relationship lifecycle permissions", async () => {
    await plane.saveProduct({ id: "cashcast", displayName: "cashcast", status: "suspended" }); assert.equal((await register()).statusCode, 401);
    await plane.saveProduct({ id: "cashcast", displayName: "cashcast", status: "active" }); await db.query("UPDATE product_workloads SET status='suspended' WHERE id='cashcast-workload'"); assert.equal((await register()).statusCode, 401);
    await db.query("UPDATE product_workloads SET status='active' WHERE id='cashcast-workload'"); await db.query("UPDATE human_identities SET status='suspended' WHERE id=$1", [human]); assert.equal((await register()).statusCode, 403);
    await db.query("UPDATE human_identities SET status='active' WHERE id=$1", [human]); await db.query("UPDATE sessions SET status='revoked' WHERE id=$1", [session]); assert.equal((await register()).statusCode, 401);
    await db.query("UPDATE sessions SET status='active' WHERE id=$1", [session]); await register(); await db.query("UPDATE human_product_participations SET status='retired'"); assert.equal((await register()).statusCode, 409);
  });
  it("rolls registration back on audit failure and preserves all canonical security data", async () => {
    const snapshot = async () => Promise.all(["human_identities", "credentials", "sessions", "tenant_memberships", "product_entitlements"].map(async table => (await db.query(`SELECT to_jsonb(x) AS value FROM ${table} x ORDER BY to_jsonb(x)::text`)).rows));
    const before = await snapshot(); await db.query("ALTER TABLE platform_audit_events ADD CONSTRAINT fixture_participation_audit_failure CHECK(event_type<>'human.product.participation.registered') NOT VALID");
    try { assert.equal((await register()).statusCode, 500); assert.equal((await db.query("SELECT 1 FROM human_product_participations")).rowCount, 0); assert.deepEqual(await snapshot(), before); }
    finally { await db.query("ALTER TABLE platform_audit_events DROP CONSTRAINT fixture_participation_audit_failure"); }
  });
  it("reports factual unintegrated-product metadata without creating artificial Humans", async () => {
    const products = (await request("/administration/platform/products/inspect")).json().products;
    const cloud = products.find((p: any) => p.id === "cloudkit-product"), unknown = products.find((p: any) => p.id === "unknown-integration");
    assert.equal(cloud.integrationStatus, "cloudkit_only"); assert.equal(cloud.participationRecording, "not_applicable"); assert.equal(cloud.participants, 0);
    assert.equal(unknown.integrationStatus, "unknown"); assert.equal(unknown.participationRecording, "unknown"); assert.equal(unknown.integrationEvidenceReference, null);
    const denied = await register("cloudkit-product"); assert.equal(denied.statusCode, 403); assert.equal(denied.json().error.code, "PARTICIPATION_NOT_APPLICABLE");
    assert.equal((await db.query("SELECT count(*)::int AS count FROM human_identities")).rows[0]!.count, 3);
  });
  it("Overview warns only when reviewed integration evidence establishes missing participation recording", async () => {
    const overview=await request("/administration/platform/overview");assert.equal(overview.statusCode,200);
    const issues=overview.json().issues.filter((i:{id:string})=>i.id.startsWith("participation-"));
    assert.equal(issues.length,1);assert.equal(issues[0].id,"participation-cashcast");assert.equal(issues[0].destination,"products");assert.match(issues[0].detail,/reporting is missing/);
    assert.ok(!issues.some((i:{id:string})=>i.id.includes("cloudkit-product")||i.id.includes("unknown-integration")));
  });
  it("requires current administrator authority and audits both association directions before exposing PII", async () => {
    const routes = [["products/humans/query", { productId: "cashcast" }], ["humans/products/query", { humanIdentityId: human }]] as const;
    for (const [path, payload] of routes) { assert.equal((await request(`/administration/platform/${path}`, payload, "")).statusCode, 401); assert.equal((await request(`/administration/platform/${path}`, payload, session)).statusCode, 403); }
    await register(); await db.query("ALTER TABLE platform_audit_events ADD CONSTRAINT fixture_association_audit_failure CHECK(event_type NOT IN ('platform.product.humans.inspected','platform.human.products.inspected')) NOT VALID");
    try { for (const [path, payload] of routes) { const result = await request(`/administration/platform/${path}`, payload); assert.equal(result.statusCode, 500); assert.ok(!result.body.includes("human@participation.example")); } }
    finally { await db.query("ALTER TABLE platform_audit_events DROP CONSTRAINT fixture_association_audit_failure"); }
    await db.query("UPDATE platform_administration_memberships SET status='suspended' WHERE human_identity_id=$1", [admin]); assert.equal((await request("/administration/platform/products/humans/query", { productId: "cashcast" })).statusCode, 403);
  });
  it("uses bounded server-side association pages and filter-bound cursors", async () => {
    for (let index = 0; index < 53; index++) {
      const id = `synthetic-${String(index).padStart(3, "0")}`;
      await db.query("INSERT INTO human_identities(id,status,created_at,updated_at) VALUES($1,'active',now(),now())", [id]);
      await db.query("INSERT INTO human_product_participations(human_identity_id,product_id,workload_id,status,created_at,updated_at) VALUES($1,'cashcast','cashcast-workload','active',now(),now())", [id]);
    }
    const first = (await request("/administration/platform/products/humans/query", { productId: "cashcast", query: "synthetic-" })).json(); assert.equal(first.humans.length, 50); assert.ok(first.nextCursor);
    const second = (await request("/administration/platform/products/humans/query", { productId: "cashcast", query: "synthetic-", cursor: first.nextCursor })).json(); assert.equal(second.humans.length, 3); assert.equal(new Set([...first.humans, ...second.humans].map((h: any) => h.humanIdentityId)).size, 53);
    assert.equal((await request("/administration/platform/products/humans/query", { productId: "grocery-master", query: "synthetic-", cursor: first.nextCursor })).statusCode, 400);
    assert.equal((await request("/administration/platform/products/humans/query", { productId: "cashcast", relationship: "entitlement", query: "synthetic-", cursor: first.nextCursor })).statusCode, 400);
    for (let index = 0; index < 53; index++) { const id = `synthetic-product-${String(index).padStart(3, "0")}`; await plane.saveProduct({ id, displayName: id, status: "active" }); await plane.saveWorkload({ id: `${id}-workload`, productId: id, secretHash: hash, status: "active" }); await db.query("INSERT INTO human_product_participations(human_identity_id,product_id,workload_id,status,created_at,updated_at) VALUES($1,$2,$3,'active',now(),now())", [human, id, `${id}-workload`]); }
    const p1 = (await request("/administration/platform/humans/products/query", { humanIdentityId: human })).json(); assert.equal(p1.products.length, 50);
    const p2 = (await request("/administration/platform/humans/products/query", { humanIdentityId: human, cursor: p1.nextCursor })).json(); assert.equal(p2.products.length, 3);
    assert.equal((await request("/administration/platform/humans/products/query", { humanIdentityId: other, cursor: p1.nextCursor })).statusCode, 400);
  });
  it("previews canonical product assertions without email guessing, creating Humans or production backfill execution", async () => {
    const unknown = randomUUID(), entries = [{ humanIdentityId: human, evidenceReference: "synthetic-product-export-1" }, { humanIdentityId: unknown, evidenceReference: "synthetic-unresolved-reference" }];
    const preview = await backfill(entries); assert.equal(preview.statusCode, 200); assert.equal(preview.json().productionExecutionAvailable, false);
    assert.deepEqual(preview.json().rows.map((r: any) => r.status), ["eligible_canonical_workload_assertion", "human_unavailable"]);
    assert.equal((await db.query("SELECT 1 FROM human_product_participations")).rowCount, 0); assert.equal((await db.query("SELECT 1 FROM human_identities WHERE id=$1", [unknown])).rowCount, 0);
    assert.equal((await backfill(entries, session)).statusCode, 403);
    assert.equal((await request("/administration/platform/products/participation/backfill/preview", { entries: [{ humanIdentityId: human, email: "other@example.test", evidenceReference: "invalid" }] }, adminSession, reporter())).statusCode, 400);
    assert.equal((await request("/administration/platform/products/participation/backfill/execute", { entries }, adminSession, reporter())).statusCode, 404);
  });
  it("runs approved canonical backfill simulation only in isolated fixtures, with idempotent retry and audited preservation", async () => {
    const entries = [{ humanIdentityId: human, evidenceReference: "synthetic-export-1" }, { humanIdentityId: human, evidenceReference: "synthetic-export-duplicate" }, { humanIdentityId: randomUUID(), evidenceReference: "unresolved-canonical-reference" }];
    const result = await centre().simulateParticipationBackfill(SessionId.from(adminSession), "cashcast-workload", secret, entries);
    assert.deepEqual(result.results.map(r => r.created), [true, false, false]);
    const retry = await centre().simulateParticipationBackfill(SessionId.from(adminSession), "cashcast-workload", secret, entries); assert.ok(retry.results.every(r => !r.created));
    assert.equal((await db.query("SELECT 1 FROM human_product_participations")).rowCount, 1); assert.equal((await db.query("SELECT 1 FROM platform_audit_events WHERE event_type='human.product.participation.backfilled'")).rowCount, 1);
  });
  it("cannot execute backfill through a production-configured runtime even on an isolated database", async () => {
    const production = await buildRuntime(loadConfig({ NODE_ENV: "production", REPOSITORY_MODE: "postgres", DATABASE_URL: url!, LOG_LEVEL: "silent" }));
    try { await assert.rejects(production.services.administration.controlCentre!.simulateParticipationBackfill(SessionId.from(adminSession), "cashcast-workload", secret, [{ humanIdentityId: human, evidenceReference: "not-authorized-production-operation" }]), (e: any) => e.code === "PARTICIPATION_BACKFILL_DISABLED"); assert.equal((await db.query("SELECT 1 FROM human_product_participations")).rowCount, 0); }
    finally { await production.close(); }
  });
  it("keeps web reporting opt-in and validates exact registered workload-to-product mapping", async () => {
    assert.equal(await centre().participateFromWebAuthentication(SessionId.from(session), "unconfigured-web"), null);
    const result = await centre().participateFromWebAuthentication(SessionId.from(session), "synthetic-web"); assert.equal(result?.humanIdentityId, human); assert.equal(result?.created, true);
    assert.equal((await centre().participateFromWebAuthentication(SessionId.from(session), "synthetic-web"))?.created, false);
    await db.query("UPDATE product_workloads SET product_id='grocery-master' WHERE id='cashcast-workload'");
    await assert.rejects(centre().participateFromWebAuthentication(SessionId.from(session), "synthetic-web"), (e: any) => e.code === "PARTICIPATION_REPORTING_UNAVAILABLE");
  });
  it("records only after successful web authentication and preserves returned authentication on reporting outage", async () => {
    let authenticated = true;
    const services = { ...runtime.services, webAuthenticationApps: new Map([["synthetic-web", { google: { execute: async () => { if (!authenticated) throw new Error("synthetic-provider-rejected"); return { session: { sessionId: session }, providerEmail: "human@participation.example" }; } } }]]) } as unknown as IdentityServices;
    const web = buildApp(services, runtime.databaseHealth);
    const signin = () => web.inject({ method: "POST", url: "/authentication/federated/google/web", payload: { appId: "synthetic-web", authorizationCode: "synthetic-provider-code", nonce: "n".repeat(32), codeVerifier: "v".repeat(43) } });
    try {
      authenticated = false; assert.equal((await signin()).statusCode, 500); assert.equal((await db.query("SELECT 1 FROM human_product_participations")).rowCount, 0);
      authenticated = true; assert.equal((await signin()).json().participationRegistration.status, "recorded");
      await db.query("UPDATE product_workloads SET status='suspended' WHERE id='cashcast-workload'");
      const outage = await signin(); assert.equal(outage.statusCode, 200); assert.equal(outage.json().session.sessionId, session); assert.equal(outage.json().participationRegistration.status, "retry_required");
    } finally { await web.close(); }
  });
});
