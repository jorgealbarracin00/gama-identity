// Development-only demonstration B: actual existing Grocery PostgreSQL customer.
// No production connections, email correspondence, backfill execution or secret output.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import pg from "pg";
import { buildRuntime } from "../src/api/services.js";
import { buildApp } from "../src/api/app.js";
import { loadConfig } from "../src/config/env.js";
import { PostgresDatabase } from "../src/infrastructure/postgres/database.js";
import { PostgresControlPlaneRepository } from "../src/infrastructure/postgres/postgres-control-plane-repository.js";
import { Argon2PasswordOperations } from "../src/authentication/adapters/argon2-password-operations.js";

assert.equal(process.env.NODE_ENV, "test", "Explicit synthetic test mode required");
const names = { identity: "gama_post_v22_customer_management_test", grocery: "gama_post_v22_customer_grocery_test" };
function safeDatabaseURL(value: string | undefined, name: string) {
  assert.ok(value, "Explicit demonstration database URL required");
  const url = new URL(value);
  assert.ok(["postgres:", "postgresql:"].includes(url.protocol) && url.hostname === "127.0.0.1" && url.port === "55510" &&
    url.pathname === `/${name}` && !url.username && !url.password && !url.search && !url.hash,
    "Only the exact separately named disposable loopback55510 databases are allowed");
  return url.toString();
}
const identityURL = safeDatabaseURL(process.env.POSTGRES_CUSTOMER_MANAGEMENT_DATABASE_URL, names.identity);
const groceryURL = safeDatabaseURL(process.env.POSTGRES_CUSTOMER_GROCERY_DATABASE_URL, names.grocery);
const groceryRoot = process.env.GROCERY_CANDIDATE_ROOT;
assert.equal(groceryRoot, "/tmp/gama-post-v22-grocery", "Use the reviewed isolated Grocery candidate");
const output = process.argv[2];
assert.ok(output && resolve(output).endsWith("/review/post-v22-platform-integration/evidence/identity/DEMONSTRATION-B-EXISTING-CUSTOMER.json"), "Pass the dedicated demonstration-B evidence filename");
const imports = (file: string) => import(pathToFileURL(`${groceryRoot}/${file}`).href);
const administration = new pg.Client({ host: "127.0.0.1", port: 55510, database: "postgres" });
const owned: string[] = [];
let runtime: Awaited<ReturnType<typeof buildRuntime>> | undefined;
let central: PostgresDatabase | undefined;
let groceryDB: any;
let identity: ReturnType<typeof buildApp> | undefined;
let product: any;
let evidence: Record<string, unknown> | undefined;
try {
  await administration.connect();
  assert.equal((await administration.query("SELECT count(*)::int AS n FROM pg_database WHERE datname=ANY($1::text[])", [Object.values(names)])).rows[0].n, 0,
    "Refuses to reuse or reset any pre-existing database");
  for (const name of Object.values(names)) { await administration.query(`CREATE DATABASE "${name}"`); owned.push(name); }
  runtime = await buildRuntime(loadConfig({ NODE_ENV: "test", REPOSITORY_MODE: "postgres", DATABASE_URL: identityURL,
    LOG_LEVEL: "silent", PASSWORD_HASH_MEMORY_KIB: "8192", PASSWORD_HASH_ITERATIONS: "2",
    IDENTITY_PRODUCT_INTEGRATIONS: JSON.stringify([{ productId: "grocery-master", integrationStatus: "gama_identity", participationRecording: "verified", evidenceReference: "synthetic-populated-Grocery-customer-demonstration", verifiedAt: new Date().toISOString() }]) }));
  central = new PostgresDatabase(identityURL);
  const { PostgresDatabase: GroceryDatabase } = await imports("src/infrastructure/postgres/database.ts");
  const { runMigrations } = await imports("src/infrastructure/postgres/migrations.ts");
  groceryDB = new GroceryDatabase(groceryURL);
  await runMigrations(groceryDB, `${groceryRoot}/migrations`);
  const plane = new PostgresControlPlaneRepository(central);
  const password = `Synthetic-${randomUUID()}-123!`, workloadSecret = `Synthetic-workload-${randomUUID()}`;
  const admin = await runtime.services.register.execute({ email: "administrator-b@synthetic.invalid", password });
  await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin.humanIdentityId, "synthetic-existing-customer-demo");
  const customer = await runtime.services.register.execute({ email: "existing-customer-b@synthetic.invalid", password });
  const secondDevice = await runtime.services.login.execute({ email: "existing-customer-b@synthetic.invalid", password });
  await plane.saveProduct({ id: "grocery-master", displayName: "Synthetic Grocery Master", status: "active" });
  const workloadID = "synthetic-grocery-existing-customer";
  const hashed = await new Argon2PasswordOperations({ memoryCost: 8192, timeCost: 2, parallelism: 1 }).hash(workloadSecret);
  await plane.saveWorkload({ id: workloadID, productId: "grocery-master", secretHash: hashed.value, status: "active" });
  const { GroceryGroupService } = await imports("src/application/grocery-group-service.ts");
  const { PostgresGroceryGroupRepository } = await imports("src/infrastructure/postgres/postgres-grocery-group-repository.ts");
  const groups = new GroceryGroupService(new PostgresGroceryGroupRepository(groceryDB));
  const existingGroup = await groups.createGroup(customer.humanIdentityId, "Existing synthetic customer family");
  const { GroceryShopService } = await imports("src/application/grocery-shop-service.ts");
  const { PostgresGroceryShopRepository } = await imports("src/infrastructure/postgres/postgres-grocery-shop-repository.ts");
  const { GroceryLivingListService } = await imports("src/application/grocery-living-list-service.ts");
  const { PostgresGroceryLivingListRepository } = await imports("src/infrastructure/postgres/postgres-grocery-living-list-repository.ts");
  const shops = new PostgresGroceryShopRepository(groceryDB);
  const livingList = new GroceryLivingListService(new PostgresGroceryLivingListRepository(groceryDB), new GroceryShopService(shops), shops);
  const actor = { groupId: existingGroup.group.id, subjectKind: "human", subjectId: customer.humanIdentityId, role: "owner", displayName: "Synthetic existing customer" };
  const term = await livingList.createFamilyItem(actor, "Synthetic customer pantry item", "pantry");
  const entry = await livingList.add(actor, { canonicalItemId: term.id, quantity: 2, shopId: "system.any", labels: ["favourite"] });
  const identityBaseURL = "http://127.0.0.1:3131";
  identity = buildApp(runtime.services, runtime.databaseHealth);
  await identity.listen({ host: "127.0.0.1", port: 3131 });
  const { buildApp: buildGroceryApp } = await imports("src/api/app.ts");
  const { GAMASessionValidator } = await imports("src/infrastructure/gama/gama-session-validator.ts");
  const { HumanParticipationReporter, WorkloadParticipationTransport } = await imports("src/infrastructure/gama/human-participation.ts");
  const { GAMAProductAdministration } = await imports("src/infrastructure/gama/product-administration.ts");
  const { GroceryHumanDependencyInspector } = await imports("src/infrastructure/postgres/human-dependency-inspector.ts");
  const { GroceryParticipationBackfillPreview } = await imports("src/infrastructure/postgres/participation-backfill-preview.ts");
  const authority = new GAMAProductAdministration(identityBaseURL);
  const inspector = new GroceryHumanDependencyInspector(groceryDB, (session: string) => authority.authorise(session));
  const exporter = new GroceryParticipationBackfillPreview(groceryDB, (session: string) => authority.authorise(session), (session: string, human: string) => authority.confirmHuman(session, human));
  const reporter = () => new HumanParticipationReporter((bearer: string, human: string) => new WorkloadParticipationTransport(identityBaseURL, workloadID, workloadSecret, "grocery-master").register(bearer, human));
  product = buildGroceryApp(groups, new GAMASessionValidator(identityBaseURL), undefined, { participationReporter: reporter(), identityInspection: { inspector, backfill: exporter } });
  async function productFingerprint() {
    const tables = await groceryDB.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename");
    const entries = [];
    for (const { tablename } of tables.rows) {
      assert.match(tablename, /^[a-z_]+$/);
      const row = (await groceryDB.query(`SELECT count(*)::int AS count,md5(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text) AS fingerprint FROM "${tablename}" t`)).rows[0];
      entries.push([tablename, row]);
    }
    return Object.fromEntries(entries);
  }
  async function protectedCentralFingerprint() {
    const entries = [];
    for (const table of ["human_identities", "credentials", "federated_identities", "platform_administration_memberships", "tenant_memberships", "product_entitlements", "registered_products", "product_workloads"]) {
      const row = (await central!.query(`SELECT count(*)::int AS count,md5(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text) AS fingerprint FROM "${table}" t`)).rows[0];
      entries.push([table, row]);
    }
    // Existing validation updates last_accessed_at; all security fields must remain identical.
    entries.push(["sessions_excluding_last_accessed_at", (await central!.query("SELECT count(*)::int AS count,md5(coalesce(jsonb_agg(to_jsonb(s)-'last_accessed_at' ORDER BY (to_jsonb(s)-'last_accessed_at')::text),'[]'::jsonb)::text) AS fingerprint FROM sessions s")).rows[0]]);
    return Object.fromEntries(entries);
  }
  const protectedBefore = await protectedCentralFingerprint(), productBefore = await productFingerprint();
  assert.equal(protectedBefore.human_identities.count, 2); assert.equal(protectedBefore.credentials.count, 2);
  assert.equal(protectedBefore.federated_identities.count, 0); assert.equal(protectedBefore.tenant_memberships.count, 0); assert.equal(protectedBefore.product_entitlements.count, 0);
  const participationCount = async () => (await central!.query("SELECT count(*)::int AS count FROM human_product_participations")).rows[0]!.count;
  assert.equal(await participationCount(), 0, "Existing product data predates the participation relationship");
  const inspect = () => product.inject({ method: "POST", url: "/v1/administration/identity-dependencies/inspect", payload: { humanIdentityId: customer.humanIdentityId }, headers: { authorization: `Bearer ${admin.session.sessionId}` } });
  const dependencyBefore = await inspect(); assert.equal(dependencyBefore.statusCode, 200);
  assert.equal(dependencyBefore.json().state, "dependencies_present"); assert.equal(dependencyBefore.json().centralCompleteReportEligible, false);
  assert.equal(dependencyBefore.json().referenceCounts.grocery_groups, 1);
  assert.equal(dependencyBefore.json().referenceCounts.living_list_human_history, 1);
  const exported = await product.inject({ method: "POST", url: "/v1/administration/participation/backfill/preview", payload: {}, headers: { authorization: `Bearer ${admin.session.sessionId}` } });
  assert.equal(exported.statusCode, 200);
  const mapping = exported.json(); assert.equal(mapping.eligible, 1); assert.equal(mapping.unresolved, 0); assert.equal(mapping.nextCursor, null);
  assert.deepEqual(mapping.entries.map((row: { humanIdentityId: string }) => row.humanIdentityId), [customer.humanIdentityId]);
  assert.equal(mapping.assessments[0].classification, "authoritatively_mapped"); assert.equal(mapping.productionExecutionAvailable, false);
  assert.ok(!JSON.stringify(mapping).includes("@"), "Email is not an association input or output");
  const preview = await fetch(`${identityBaseURL}/administration/platform/products/participation/backfill/preview`, { method: "POST", headers: { authorization: `Bearer ${admin.session.sessionId}`, "content-type": "application/json", "x-gama-workload-id": workloadID, "x-gama-workload-secret": workloadSecret }, body: JSON.stringify({ entries: mapping.entries }) });
  assert.equal(preview.status, 200);
  const centralPreview = await preview.json() as { rows: { humanIdentityId: string; status: string }[]; productionExecutionAvailable: boolean };
  assert.equal(centralPreview.rows[0]?.humanIdentityId, customer.humanIdentityId); assert.equal(centralPreview.rows[0]?.status, "eligible_canonical_workload_assertion"); assert.equal(centralPreview.productionExecutionAvailable, false);
  assert.equal(await participationCount(), 0, "Both product and central previews are read-only");
  assert.deepEqual(await productFingerprint(), productBefore); assert.deepEqual(await protectedCentralFingerprint(), protectedBefore);
  assert.equal((await product.inject({ method: "POST", url: "/v1/administration/participation/backfill/preview", payload: {}, headers: { authorization: `Bearer ${customer.session.sessionId}` } })).statusCode, 403, "Product owner is not Platform Administrator");
  assert.equal((await product.inject({ method: "GET", url: "/v1/me/grocery-group" })).statusCode, 401);
  assert.equal((await product.inject({ method: "GET", url: "/v1/me/grocery-group", headers: { authorization: `Bearer ${randomUUID()}` } })).statusCode, 401);
  assert.equal(await participationCount(), 0);
  const accesses = [];
  for (const bearer of [customer.session.sessionId, secondDevice.sessionId, customer.session.sessionId, secondDevice.sessionId]) {
    const response = await product.inject({ method: "GET", url: "/v1/me/grocery-group?principalId=spoofed", headers: { authorization: `Bearer ${bearer}` } });
    assert.equal(response.statusCode, 200); assert.notEqual(response.headers["x-gama-participation-status"], "pending");
    assert.equal(response.json().membership.principalId, customer.humanIdentityId); assert.equal(response.json().group.id, existingGroup.group.id);
    accesses.push({ statusCode: response.statusCode, canonicalHumanPreserved: true, existingFamilyPreserved: true, reporting: response.headers["x-gama-participation-status"] ?? "recorded_or_cached" });
  }
  // Independent process/cache exercises central idempotency, not only local deduplication.
  const secondProduct = buildGroceryApp(groups, new GAMASessionValidator(identityBaseURL), undefined, { participationReporter: reporter() });
  try {
    const concurrent = await Promise.all([customer.session.sessionId, secondDevice.sessionId].map(bearer => secondProduct.inject({ method: "GET", url: "/v1/me/grocery-group", headers: { authorization: `Bearer ${bearer}` } })));
    assert.ok(concurrent.every(response => response.statusCode === 200 && response.headers["x-gama-participation-status"] !== "pending"));
  } finally { await secondProduct.close(); }
  assert.equal(await participationCount(), 1);
  const recorded = (await central.query("SELECT human_identity_id,product_id,status FROM human_product_participations")).rows;
  assert.deepEqual(recorded, [{ human_identity_id: customer.humanIdentityId, product_id: "grocery-master", status: "active" }]);
  const dependencyAfter = await inspect(); assert.equal(dependencyAfter.statusCode, 200);
  for (const field of ["state", "coverage", "referenceCounts", "groupReachableCounts", "blockers", "centralCompleteReportEligible"]) assert.deepEqual(dependencyAfter.json()[field], dependencyBefore.json()[field]);
  const productAfter = await productFingerprint(), protectedAfter = await protectedCentralFingerprint();
  assert.deepEqual(productAfter, productBefore); assert.deepEqual(protectedAfter, protectedBefore);
  assert.equal((await groups.currentGroup(customer.humanIdentityId)).membership.role, "owner");
  assert.equal((await livingList.list(actor)).entries[0].id, entry.id);
  const audits = (await central.query("SELECT event_type,count(*)::int AS count FROM platform_audit_events WHERE event_type IN ('human.product.participation.registered','human.product.participation.backfill.previewed','human.product.participation.backfilled') GROUP BY event_type ORDER BY event_type")).rows;
  assert.equal(audits.find(row => row.event_type === "human.product.participation.registered")?.count, 1);
  assert.equal(audits.find(row => row.event_type === "human.product.participation.backfill.previewed")?.count, 1);
  assert.ok(!audits.some(row => row.event_type === "human.product.participation.backfilled"));
  evidence = { demonstration: "B", result: "passed", verifiedAt: new Date().toISOString(), productionActions: false,
    environment: "Two separate disposable PostgreSQL18 databases, actual GAMAIdentity HTTP3131 and actual protected Grocery route with populated PostgreSQL product repositories",
    customer: { syntheticCanonicalHumanId: customer.humanIdentityId, identityExistedBeforeParticipation: true, familyAndLivingListPredatedReporting: true, mappingAuthority: "Product adult provenance + exact current central active Human lookup; no email correspondence" },
    previews: { productEligible: 1, productUnresolved: 0, centralStatus: centralPreview.rows[0]!.status, noParticipationWrites: true, productionExecutionAvailable: false },
    actualAuthenticatedAccesses: accesses, separateReporterConcurrentRetries: 2, finalParticipationRows: 1,
    preservation: { canonicalHumanCount: 1, totalFixtureHumanCount: 2, credentialCount: 2, federatedRelationshipCount: 0, noExtraHumansOrCredentials: true, noCentralBusinessMembershipOrEntitlementCreated: true, protectedCentralFingerprintsUnchanged: true, sessionSecurityFieldsUnchanged: true, expectedSessionLastAccessedMetadataMayChange: true, allGroceryTableFingerprintsUnchanged: true, existingGroupOwnerRoleAndLivingListEntryPreserved: true },
    permissionChecks: { ordinaryProductOwnerPreview: 403, noBearerProtectedRoute: 401, invalidSessionProtectedRoute: 401 },
    dependencies: { state: dependencyAfter.json().state, coverage: dependencyAfter.json().coverage, referenceCounts: dependencyAfter.json().referenceCounts, groupReachableCounts: dependencyAfter.json().groupReachableCounts, unknownCategories: dependencyAfter.json().blockers, centralCompleteReportEligible: false, unchangedAcrossReporting: true, recoveryClearance: "unknown_not_clearable" },
    fingerprints: { meaning: "Count + aggregate row fingerprints only; synthetic databases, no raw credential/token/provider data", protectedCentralBefore: protectedBefore, protectedCentralAfter: protectedAfter, groceryBefore: productBefore, groceryAfter: productAfter },
    auditCounts: audits, limitations: "Actual synthetic Email/Password sessions and PostgreSQL product data only; no live Apple/Google, production provisioning/backfill or complete distributed writer barrier" };
} finally {
  await product?.close(); await identity?.close(); await runtime?.close(); await groceryDB?.close(); await central?.close();
  for (const name of owned.reverse()) { await administration.query(`DROP DATABASE "${name}"`); }
  await administration.end();
}
assert.ok(evidence, "Demonstration must produce verified evidence");
evidence.cleanup = { ownedHTTPAndPoolsClosed: true, bothDisposableDatabasesDropped: true, sharedRootClusterNotStopped: true };
await writeFile(output, JSON.stringify(evidence, null, 2) + "\n", { mode: 0o600 });
console.log(JSON.stringify({ result: "passed", finalParticipationRows: 1, productTablesPreserved: true, previewWrites: 0, disposableDatabasesDropped: true, output }));
