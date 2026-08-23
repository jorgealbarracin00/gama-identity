import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";

import { EmailCredential } from "../../src/authentication/credentials/domain/email-credential.js";
import { EmailCredentialId } from "../../src/authentication/credentials/domain/email-credential-id.js";
import { EmailAlreadyInUseError } from "../../src/authentication/credentials/domain/errors.js";
import { NormalizedEmail } from "../../src/authentication/credentials/domain/email.js";
import { PasswordHash } from "../../src/authentication/credentials/domain/password.js";
import { HumanIdentity } from "../../src/identity/domain/human-identity.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { PostgresDatabase } from "../../src/infrastructure/postgres/database.js";
import { runMigrations } from "../../src/infrastructure/postgres/migrations.js";
import { PostgresEmailCredentialRepository } from "../../src/infrastructure/postgres/postgres-email-credential-repository.js";
import { PostgresHumanIdentityRepository } from "../../src/infrastructure/postgres/postgres-human-identity-repository.js";
import { PostgresSessionRepository } from "../../src/infrastructure/postgres/postgres-session-repository.js";
import { Session } from "../../src/sessions/domain/session.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { buildRuntime } from "../../src/api/services.js";
import { loadConfig } from "../../src/config/env.js";
import { WorkforceAdministrationError } from "../../src/control-plane/application/workforce-administration.js";
import { COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID } from "../../src/control-plane/models.js";
import {
  PostgresFederatedAuthenticationNonceRepository,
  PostgresFederatedIdentityRepository,
} from "../../src/infrastructure/postgres/postgres-federated-identity-repository.js";
import { AuthenticateFederated } from "../../src/authentication/federated/application/authenticate-federated.js";
import { FederatedIdentityTokenVerifiers } from "../../src/authentication/federated/application/token-verifier.js";
import { CreateSession } from "../../src/sessions/application/use-cases.js";
import {
  UuidFederatedIdentityIdGenerator,
  UuidHumanIdentityIdGenerator,
  UuidSessionIdGenerator,
} from "../../src/shared/identifiers.js";
import { SystemClock } from "../../src/shared/clock.js";
import { DeterministicAppleVerifier } from "../operational/test-doubles.js";
import {
  FederatedIdentity,
  FederatedIdentityProvider,
  FederatedProviderSubject,
} from "../../src/authentication/federated/domain/federated-identity.js";

const testDatabaseUrl = process.env.POSTGRES_TEST_DATABASE_URL;

describe(
  "PostgreSQL persistence",
  { skip: testDatabaseUrl === undefined, concurrency: false },
  () => {
    let database: PostgresDatabase;
    let identities: PostgresHumanIdentityRepository;
    let credentials: PostgresEmailCredentialRepository;
    let sessions: PostgresSessionRepository;

    before(async () => {
      database = new PostgresDatabase(testDatabaseUrl!);
      await runMigrations(database);
      identities = new PostgresHumanIdentityRepository(database);
      credentials = new PostgresEmailCredentialRepository(database);
      sessions = new PostgresSessionRepository(database);
    });

    beforeEach(async () => {
      await database.query(
        `TRUNCATE federated_authentication_nonces, federated_identities, sessions, credentials,
          platform_audit_events, tenant_provisioning_requests, platform_administration_memberships,
          product_entitlements, product_participations, tenant_memberships, product_workloads,
          tenants, registered_products, human_identities CASCADE`,
      );
    });

    after(async () => {
      await database.close();
    });

    it("runs versioned migrations repeatedly without changing applied state", async () => {
      await runMigrations(database);
      await runMigrations(database);
      const result = await database.query(
        "SELECT version FROM schema_migrations ORDER BY version",
      );
      assert.deepEqual(result.rows.map((row) => row.version), ["001", "002", "003", "004", "005", "006", "007", "008"]);
    });

    it("starts and closes a PostgreSQL runtime after a connectivity check", async () => {
      const runtime = await buildRuntime(
        loadConfig({
          REPOSITORY_MODE: "postgres",
          DATABASE_URL: testDatabaseUrl,
        }),
      );
      assert.equal(await runtime.databaseHealth.check(), "connected");
      await runtime.close();
    });

    it("persists and reconstitutes all three aggregates", async () => {
      const identity = identityAggregate();
      await identities.save(identity);
      const credential = credentialAggregate(identity.id);
      await credentials.save(credential);
      const session = sessionAggregate(identity.id);
      await sessions.save(session);

      assert.deepEqual(
        (await identities.findById(identity.id))?.snapshot(),
        identity.snapshot(),
      );
      assert.equal(
        (
          await credentials.findByNormalizedEmail(
            NormalizedEmail.from("Person@example.com"),
          )
        )?.id.value,
        credential.id.value,
      );
      assert.equal(
        (await credentials.findByHumanIdentityId(identity.id))?.id.value,
        credential.id.value,
      );
      assert.deepEqual(
        (await sessions.findById(session.id))?.snapshot(),
        session.snapshot(),
      );
    });

    it("matches credential uniqueness and retired-email reuse semantics", async () => {
      const identity = identityAggregate();
      await identities.save(identity);
      const first = credentialAggregate(identity.id);
      await credentials.save(first);
      await assert.rejects(
        credentials.save(
          credentialAggregate(
            identity.id,
            "22222222-2222-4222-8222-222222222222",
          ),
        ),
        EmailAlreadyInUseError,
      );
      first.retire(fixedClock);
      await credentials.save(first);
      await credentials.save(
        credentialAggregate(
          identity.id,
          "22222222-2222-4222-8222-222222222222",
        ),
      );
    });

    it("rolls back every repository write when a transaction fails", async () => {
      const identity = identityAggregate();
      await assert.rejects(
        database.withTransaction(async () => {
          await identities.save(identity);
          await credentials.save(credentialAggregate(identity.id));
          await sessions.save(sessionAggregate(identity.id));
          throw new Error("forced registration failure");
        }),
      );
      assert.equal(await identities.findById(identity.id), null);
      assert.equal(
        await credentials.findById(
          EmailCredentialId.from("11111111-1111-4111-8111-111111111111"),
        ),
        null,
      );
      assert.equal(
        await sessions.findById(
          SessionId.from("33333333-3333-4333-8333-333333333333"),
        ),
        null,
      );
    });

    it("revokes sessions idempotently with repository parity", async () => {
      const identity = identityAggregate();
      await identities.save(identity);
      const session = sessionAggregate(identity.id);
      await sessions.save(session);
      await sessions.revoke(session.id);
      await sessions.revoke(session.id);
      assert.equal((await sessions.findById(session.id))?.status, "revoked");
      assert.equal(await sessions.findActiveById(session.id), null);
    });

    it("persists provider-neutral identities, unique subjects and consumed nonces", async () => {
      const verifier = new DeterministicAppleVerifier();
      verifier.accept("postgres-apple-token", {
        subject: "postgres-apple-subject",
        email: "relay@privaterelay.appleid.com",
        emailVerified: true,
        emailPrivate: true,
      });
      const authentication = postgresFederatedAuthentication(database, verifier);
      const result = await authentication.execute({
        provider: "apple",
        identityToken: "postgres-apple-token",
        nonce: "postgres_nonce_that_is_at_least_thirty_two_characters",
      });
      const repository = new PostgresFederatedIdentityRepository(database);
      const relation = await repository.findByProviderSubject(
        FederatedIdentityProvider.from("apple"),
        FederatedProviderSubject.from("postgres-apple-subject"),
      );
      assert.equal(relation?.humanIdentityId.value, result.humanIdentityId);
      assert.equal(relation?.providerEmailPrivate, true);
      assert.deepEqual(
        (await repository.listActiveByVerifiedProviderEmail("RELAY@privaterelay.appleid.com"))
          .map((candidate) => candidate.humanIdentityId.value),
        [result.humanIdentityId],
      );
      assert.deepEqual(await repository.listActiveByVerifiedProviderEmail("missing@example.com"), []);
      assert.equal((await database.query<{ count: string }>("SELECT count(*)::text AS count FROM federated_authentication_nonces")).rows[0]?.count, "1");
    });

    it("enforces one active relationship per Human and provider while allowing reassignment", async () => {
      const repository = new PostgresFederatedIdentityRepository(database);
      const firstHuman = identityAggregate();
      const secondHuman = HumanIdentity.reconstitute({
        ...firstHuman.snapshot(),
        id: HumanIdentityId.from("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
      });
      await identities.save(firstHuman);
      await identities.save(secondHuman);
      const first = FederatedIdentity.create(
        new UuidFederatedIdentityIdGenerator(),
        firstHuman.id,
        FederatedIdentityProvider.from("apple"),
        FederatedProviderSubject.from("one-active-subject"),
        { email: null, emailVerified: null, emailPrivate: null },
        fixedClock,
      );
      const conflict = FederatedIdentity.create(
        new UuidFederatedIdentityIdGenerator(),
        firstHuman.id,
        FederatedIdentityProvider.from("apple"),
        FederatedProviderSubject.from("second-active-subject"),
        { email: null, emailVerified: null, emailPrivate: null },
        fixedClock,
      );
      await repository.save(first);
      await assert.rejects(repository.save(conflict), (error: unknown) =>
        (error as Error).name === "FederatedIdentityHumanProviderConflictError");

      first.reassignTo(secondHuman.id, fixedClock);
      await repository.save(first);
      assert.equal((await repository.findByProviderSubject(
        FederatedIdentityProvider.from("apple"),
        FederatedProviderSubject.from("one-active-subject"),
      ))?.humanIdentityId.value, secondHuman.id.value);
    });

    it("serializes concurrent first federated sign-ins into one Human", async () => {
      const verifier = new DeterministicAppleVerifier();
      verifier.accept("postgres-concurrent-a", { subject: "postgres-concurrent-subject" });
      verifier.accept("postgres-concurrent-b", { subject: "postgres-concurrent-subject" });
      const first = postgresFederatedAuthentication(database, verifier);
      const second = postgresFederatedAuthentication(database, verifier);
      const results = await Promise.all([
        first.execute({
          provider: "apple",
          identityToken: "postgres-concurrent-a",
          nonce: "postgres_concurrent_nonce_A_at_least_thirty_two_chars",
        }),
        second.execute({
          provider: "apple",
          identityToken: "postgres-concurrent-b",
          nonce: "postgres_concurrent_nonce_B_at_least_thirty_two_chars",
        }),
      ]);
      assert.equal(results[0]?.humanIdentityId, results[1]?.humanIdentityId);
      assert.deepEqual(results.map((result) => result.created).sort(), [false, true]);
      const counts = await database.query<{ relationships: string; humans: string; sessions: string }>(
        `SELECT
           (SELECT count(*)::text FROM federated_identities) AS relationships,
           (SELECT count(*)::text FROM human_identities) AS humans,
           (SELECT count(*)::text FROM sessions) AS sessions`,
      );
      assert.deepEqual(counts.rows[0], { relationships: "1", humans: "1", sessions: "2" });
    });

    it("serializes identical Coco bootstrap retries without duplicate audit events", async () => {
      const firstRuntime = await buildRuntime(
        loadConfig({ REPOSITORY_MODE: "postgres", DATABASE_URL: testDatabaseUrl }),
      );
      const secondRuntime = await buildRuntime(
        loadConfig({ REPOSITORY_MODE: "postgres", DATABASE_URL: testDatabaseUrl }),
      );
      try {
        const owner = await firstRuntime.services.register.execute({
          email: "concurrent-bootstrap-owner@coco.example",
          password: "correct-password",
        });
        const input = {
          ownerHumanIdentityId: owner.humanIdentityId,
          workloadSecret: "postgres-concurrent-bootstrap-secret",
          actorReference: "platform-operator:postgres-test",
        };

        await Promise.all([
          firstRuntime.controlPlane.bootstrapCoco(input),
          secondRuntime.controlPlane.bootstrapCoco(input),
        ]);

        const auditCount = await database.query<{ count: string }>(
          "SELECT count(*)::text AS count FROM platform_audit_events WHERE tenant_id = $1 AND product_id = $2",
          [COCO_DEVELOPMENT_TENANT_ID, COCO_PRODUCT_ID],
        );
        assert.equal(auditCount.rows[0]?.count, "5");
        assert.equal(
          (await firstRuntime.controlPlane.workforceContext(
            owner.humanIdentityId,
            COCO_DEVELOPMENT_TENANT_ID,
            COCO_PRODUCT_ID,
          )).workforceContextSatisfied,
          true,
        );
      } finally {
        await Promise.all([firstRuntime.close(), secondRuntime.close()]);
      }
    });

    it("serializes concurrent final-owner mutations", async () => {
      const runtime = await buildRuntime(
        loadConfig({ REPOSITORY_MODE: "postgres", DATABASE_URL: testDatabaseUrl }),
      );
      try {
        const first = await runtime.services.register.execute({ email: "first-owner@coco.example", password: "correct-password" });
        const second = await runtime.services.register.execute({ email: "second-owner@coco.example", password: "correct-password" });
        await runtime.controlPlane.bootstrapCoco({
          ownerHumanIdentityId: first.humanIdentityId,
          workloadSecret: "postgres-test-workload-secret",
          actorReference: "platform-operator:test",
        });
        await runtime.workforceAdministration.grantProductWorkforceAccess({
          actorReference: "platform-operator:test",
          tenantId: COCO_DEVELOPMENT_TENANT_ID,
          productId: COCO_PRODUCT_ID,
          humanIdentityId: second.humanIdentityId,
          tenantRole: "owner",
        });

        const results = await Promise.allSettled([
          runtime.workforceAdministration.changeTenantRole({
            actorReference: "platform-operator:test",
            tenantId: COCO_DEVELOPMENT_TENANT_ID,
            humanIdentityId: first.humanIdentityId,
            tenantRole: "staff",
          }),
          runtime.workforceAdministration.revokeTenantMembership({
            actorReference: "platform-operator:test",
            tenantId: COCO_DEVELOPMENT_TENANT_ID,
            humanIdentityId: second.humanIdentityId,
          }),
        ]);
        assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
        const rejection = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
        assert.ok(rejection?.reason instanceof WorkforceAdministrationError);
        assert.equal(rejection.reason.code, "LAST_OWNER");
        const memberships = await runtime.workforceAdministration.listTenantWorkforce(COCO_DEVELOPMENT_TENANT_ID);
        assert.equal(memberships.filter((membership) => membership.status === "active" && membership.tenantRole === "owner").length, 1);
      } finally {
        await runtime.close();
      }
    });

    it("persists and rechecks Platform administrator authority through the runtime boundary", async () => {
      const runtime = await buildRuntime(
        loadConfig({ REPOSITORY_MODE: "postgres", DATABASE_URL: testDatabaseUrl }),
      );
      try {
        const administrator = await runtime.services.register.execute({
          email: "postgres-platform-admin@gama.example",
          password: "correct-password",
        });
        await runtime.platformAdministrationProvisioning.bootstrapAdministrator(
          administrator.humanIdentityId,
          "deployment-operator:postgres-test",
        );
        assert.deepEqual(await runtime.services.administration.platform.listTenants(administrator.humanIdentityId), []);
        await database.query(
          "UPDATE platform_administration_memberships SET status = 'suspended', updated_at = now() WHERE human_identity_id = $1",
          [administrator.humanIdentityId],
        );
        await assert.rejects(
          () => runtime.services.administration.platform.listTenants(administrator.humanIdentityId),
          (error: unknown) => (error as { code?: string }).code === "NOT_PLATFORM_ADMIN",
        );
      } finally {
        await runtime.close();
      }
    });

    it("serializes cross-runtime Tenant provisioning retries into one Tenant and one initial Owner", async () => {
      const firstRuntime = await buildRuntime(
        loadConfig({ REPOSITORY_MODE: "postgres", DATABASE_URL: testDatabaseUrl }),
      );
      const secondRuntime = await buildRuntime(
        loadConfig({ REPOSITORY_MODE: "postgres", DATABASE_URL: testDatabaseUrl }),
      );
      try {
        const administrator = await firstRuntime.services.register.execute({
          email: "tenant-provisioning-admin@gama.example",
          password: "correct-password",
        });
        const initialOwner = await firstRuntime.services.register.execute({
          email: "tenant-provisioning-owner@gama.example",
          password: "correct-password",
        });
        await firstRuntime.platformAdministrationProvisioning.bootstrapAdministrator(
          administrator.humanIdentityId,
          "deployment-operator:postgres-test",
        );
        const input = {
          idempotencyKey: "55555555-5555-4555-8555-555555555555",
          displayName: "Concurrent Retailer",
          initialOwnerHumanIdentityId: initialOwner.humanIdentityId,
        };
        const results = await Promise.all([
          firstRuntime.services.administration.platform.provisionTenant(administrator.humanIdentityId, input),
          secondRuntime.services.administration.platform.provisionTenant(administrator.humanIdentityId, input),
        ]);

        assert.deepEqual(results.map((result) => result.created).sort(), [false, true]);
        assert.equal(results[0]?.tenant.id, results[1]?.tenant.id);
        const tenantId = results[0]!.tenant.id;
        const [requestCount, tenantCount, ownerCount, tenantAuditCount] = await Promise.all([
          database.query<{ count: string }>("SELECT count(*)::text AS count FROM tenant_provisioning_requests WHERE idempotency_key = $1", [input.idempotencyKey]),
          database.query<{ count: string }>("SELECT count(*)::text AS count FROM tenants WHERE id = $1", [tenantId]),
          database.query<{ count: string }>(`SELECT count(*)::text AS count FROM tenant_memberships
            WHERE tenant_id = $1 AND human_identity_id = $2 AND tenant_role = 'owner' AND status = 'active'`, [tenantId, initialOwner.humanIdentityId]),
          database.query<{ count: string }>("SELECT count(*)::text AS count FROM platform_audit_events WHERE event_type = 'tenant.created' AND tenant_id = $1", [tenantId]),
        ]);
        assert.equal(requestCount.rows[0]?.count, "1");
        assert.equal(tenantCount.rows[0]?.count, "1");
        assert.equal(ownerCount.rows[0]?.count, "1");
        assert.equal(tenantAuditCount.rows[0]?.count, "1");
      } finally {
        await Promise.all([firstRuntime.close(), secondRuntime.close()]);
      }
    });
  },
);

const fixedClock = {
  now: () => new Date("2026-01-01T00:00:00.000Z"),
};

function identityAggregate(): HumanIdentity {
  return HumanIdentity.reconstitute({
    id: HumanIdentityId.from("00000000-0000-4000-8000-000000000001"),
    status: "active",
    createdAt: fixedClock.now(),
    updatedAt: fixedClock.now(),
  });
}

function credentialAggregate(
  humanIdentityId: HumanIdentityId,
  id = "11111111-1111-4111-8111-111111111111",
): EmailCredential {
  return EmailCredential.reconstitute({
    id: EmailCredentialId.from(id),
    humanIdentityId,
    email: NormalizedEmail.from("Person@example.com"),
    passwordHash: PasswordHash.from("test:correct-password"),
    status: "active",
    createdAt: fixedClock.now(),
    updatedAt: fixedClock.now(),
  });
}

function sessionAggregate(humanIdentityId: HumanIdentityId): Session {
  return Session.reconstitute({
    id: SessionId.from("33333333-3333-4333-8333-333333333333"),
    humanIdentityId,
    createdAt: fixedClock.now(),
    lastAccessedAt: fixedClock.now(),
    expiresAt: new Date("2026-01-02T00:00:00.000Z"),
    status: "active",
  });
}

function postgresFederatedAuthentication(
  database: PostgresDatabase,
  verifier: DeterministicAppleVerifier,
): AuthenticateFederated {
  const clock = new SystemClock();
  return new AuthenticateFederated(
    new FederatedIdentityTokenVerifiers([verifier]),
    new PostgresFederatedIdentityRepository(database),
    new PostgresFederatedAuthenticationNonceRepository(database),
    new PostgresHumanIdentityRepository(database),
    new UuidHumanIdentityIdGenerator(),
    new UuidFederatedIdentityIdGenerator(),
    new CreateSession(
      new PostgresSessionRepository(database),
      new UuidSessionIdGenerator(),
      clock,
      3600,
    ),
    clock,
    (work) => database.withTransaction(work),
  );
}
