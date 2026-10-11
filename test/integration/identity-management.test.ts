import assert from "node:assert/strict";
import { before, after, beforeEach, describe, it } from "node:test";
import { randomBytes, randomUUID } from "node:crypto";
import { generateKeyPair, SignJWT } from "jose";
import {
  buildRuntime,
  type ApplicationRuntime,
} from "../../src/api/services.js";
import { buildApp } from "../../src/api/app.js";
import { loadConfig } from "../../src/config/env.js";
import { PostgresDatabase } from "../../src/infrastructure/postgres/database.js";
import { PostgresControlCentreRepository } from "../../src/infrastructure/postgres/postgres-control-centre-repository.js";
import { PostgresControlPlaneRepository } from "../../src/infrastructure/postgres/postgres-control-plane-repository.js";
import { PostgresHumanIdentityRepository } from "../../src/infrastructure/postgres/postgres-human-identity-repository.js";
import { PostgresSessionRepository } from "../../src/infrastructure/postgres/postgres-session-repository.js";
import {
  PostgresFederatedIdentityRepository,
  PostgresFederatedAuthenticationNonceRepository,
} from "../../src/infrastructure/postgres/postgres-federated-identity-repository.js";
import { AdministrationPrincipals } from "../../src/control-plane/application/administration-principals.js";
import {
  IdentityManagement,
  activityClassification,
  potentialTestAlias,
  syntheticManagementEnabled,
} from "../../src/control-plane/application/identity-management.js";
import { GoogleIdentityTokenVerifier } from "../../src/authentication/federated/adapters/google-identity-token-verifier.js";
import { FederatedIdentityTokenVerifiers } from "../../src/authentication/federated/application/token-verifier.js";
import { AuthenticateFederated } from "../../src/authentication/federated/application/authenticate-federated.js";
import { CreateSession } from "../../src/sessions/application/use-cases.js";
import { SystemClock } from "../../src/shared/clock.js";
import {
  UuidHumanIdentityIdGenerator,
  UuidFederatedIdentityIdGenerator,
  UuidSessionIdGenerator,
} from "../../src/shared/identifiers.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { FederatedIdentityProvider } from "../../src/authentication/federated/domain/federated-identity.js";
import type { FastifyInstance } from "fastify";
const url = process.env.POSTGRES_MANAGEMENT_TEST_DATABASE_URL;
const password = "Synthetic-password-123!";
const nonce = () => randomBytes(32).toString("base64url");
describe("Identity management conservative classifications and deployment gate", () => {
  it("recognizes only the exact owner alias family, without classifying it", () => {
    assert.ok(potentialTestAlias("jorgealbarracin+login@gmail.com"));
    for (const v of [
      "customer+test@gmail.com",
      "jorgealbarracin@gmail.com",
      "jorgealbarracin+test@other.example",
      null,
    ])
      assert.equal(potentialTestAlias(v), false);
  });
  it("keeps missing/old activity unknown independently of purpose/lifecycle", () => {
    const now = new Date();
    assert.equal(activityClassification(null, now), "unknown");
    assert.equal(activityClassification("2000-01-01", now), "unknown");
    assert.equal(
      activityClassification(now.toISOString(), now),
      "recently_active",
    );
    assert.equal(activityClassification("2099-01-01", now), "unknown");
  });
  it("cannot activate for production, public databases or ordinary development", () => {
    for (const c of [
      {
        NODE_ENV: "production",
        DATABASE_URL: "postgresql://localhost/x_management_test",
      },
      {
        NODE_ENV: "test",
        DATABASE_URL: "postgresql://remote.example/x_management_test",
      },
      { NODE_ENV: "test", DATABASE_URL: "postgresql://localhost/production" },
      {
        NODE_ENV: "development",
        DATABASE_URL: "postgresql://localhost/x_management_test",
      },
    ])
      assert.equal(
        syntheticManagementEnabled({
          ...c,
          REPOSITORY_MODE: "postgres",
        } as any),
        false,
      );
    assert.equal(
      syntheticManagementEnabled({
        NODE_ENV: "test",
        REPOSITORY_MODE: "postgres",
        DATABASE_URL: "postgresql://127.0.0.1/x_management_test",
      }),
      true,
    );
  });
});
describe(
  "V2.1 real PostgreSQL management execution, proofs and concurrency",
  { skip: !url },
  () => {
    let runtime: ApplicationRuntime,
      db: PostgresDatabase,
      plane: PostgresControlPlaneRepository,
      humans: PostgresHumanIdentityRepository,
      sessions: PostgresSessionRepository,
      federated: PostgresFederatedIdentityRepository,
      management: IdentityManagement,
      auth: AuthenticateFederated,
      app: FastifyInstance;
    let admin: string,
      adminSession: string,
      target: string,
      source: string,
      targetSession: string,
      sourceSession: string,
      sourceRenewalToken: string,
      key: Awaited<ReturnType<typeof generateKeyPair>>;
    const token = () => SessionId.from(adminSession);
    const jwt = async (
      n: string,
      subject = "synthetic-secret-subject",
      audience = "synthetic-client",
      exp = 300,
    ) =>
      new SignJWT({ nonce: n })
        .setProtectedHeader({ alg: "RS256" })
        .setIssuer("https://accounts.google.com")
        .setAudience(audience)
        .setSubject(subject)
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + exp)
        .sign(key.privateKey);
    const signGoogle = async () => {
      const n = nonce();
      return auth.execute({
        provider: "google",
        nonce: n,
        identityToken: await jwt(n),
      });
    };
    const zero = {
      localAccounts: 0,
      subscriptions: 0,
      permissions: 0,
      ownership: 0,
      backgroundJobs: 0,
      pendingOperations: 0,
      externalReferences: 0,
      retention: 0,
    };
    const report = async (id: string, counts = zero) =>
      management.reportDependencies(
        "synthetic-workload",
        "Synthetic-workload-secret-123!",
        {
          humanIdentityId: id,
          counts,
          evidenceReference: randomUUID(),
          observedAt: new Date().toISOString(),
        },
      );
    const classify = async (
      id = source,
      purpose: "test" | "unknown" | "production" = "test",
    ) => {
      const m = await management.inspect(token(), id);
      return management.classify(token(), {
        humanIdentityId: id,
        purpose,
        reason: "Explicit synthetic fixture review",
        expectedRevision: m.classificationRevision,
        requestId: randomUUID(),
      });
    };
    const verified = async () => {
      const c = await management.prepareRecovery(token(), source, target);
      const s = await signGoogle();
      sourceSession = s.session.sessionId;
      sourceRenewalToken = s.session.renewalToken;
      const t = await runtime.services.login.execute({
        email: "target@synthetic.example",
        password,
      });
      targetSession = t.sessionId;
      await management.proveRecovery(token(), {
        caseId: c.caseId,
        sourceSession,
        targetSession,
        identityToken: await jwt(c.nonce),
      });
      return c;
    };
    const execution = async (id: string) => {
      const p = await management.previewRecovery(token(), id);
      return {
        caseId: id,
        requestId: randomUUID(),
        reviewDigest: p.reviewDigest,
        confirmation: `transfer google ${source} to ${target}`,
        revokeSourceSessions: true,
        acceptSourceLossOfAccess: true,
      };
    };
    before(async () => {
      assert.ok(
        syntheticManagementEnabled({
          NODE_ENV: "test",
          REPOSITORY_MODE: "postgres",
          DATABASE_URL: url!,
        }),
      );
      runtime = await buildRuntime(
        loadConfig({
          NODE_ENV: "test",
          REPOSITORY_MODE: "postgres",
          DATABASE_URL: url!,
          LOG_LEVEL: "silent",
          PASSWORD_HASH_MEMORY_KIB: "8192",
          PASSWORD_HASH_ITERATIONS: "2",
        }),
      );
      db = new PostgresDatabase(url!, false, () => {}, true);
      plane = new PostgresControlPlaneRepository(db);
      humans = new PostgresHumanIdentityRepository(db);
      sessions = new PostgresSessionRepository(db);
      federated = new PostgresFederatedIdentityRepository(db);
      const nonces = new PostgresFederatedAuthenticationNonceRepository(db),
        clock = new SystemClock();
      key = await generateKeyPair("RS256");
      const verifiers = new FederatedIdentityTokenVerifiers([
        new GoogleIdentityTokenVerifier({
          clientIds: ["synthetic-client"],
          keyResolver: async () => key.publicKey,
        }),
      ]);
      management = new IdentityManagement(
        db,
        new PostgresControlCentreRepository(db),
        new AdministrationPrincipals(plane, humans, runtime.controlPlane),
        plane,
        humans,
        sessions,
        federated,
        nonces,
        verifiers,
        clock,
        true,
        runtime.controlPlane,
      );
      auth = new AuthenticateFederated(
        verifiers,
        federated,
        nonces,
        humans,
        new UuidHumanIdentityIdGenerator(),
        new UuidFederatedIdentityIdGenerator(),
        new CreateSession(
          sessions,
          new UuidSessionIdGenerator(),
          clock,
          3600,
          undefined,
          2592000,
          humans,
        ),
        clock,
        (w) => db.withTransaction(w),
      );
      app = buildApp(
        {
          ...runtime.services,
          administration: {
            ...runtime.services.administration,
            identityManagement: management,
          },
        },
        runtime.databaseHealth,
      );
    });
    after(async () => {
      await app?.close();
      await runtime?.close();
      await db?.close();
    });
    beforeEach(async () => {
      await db.query(
        "TRUNCATE human_identities,registered_products,tenants,platform_audit_events,federated_authentication_nonces CASCADE",
      );
      const a = await runtime.services.register.execute({
        email: "admin@synthetic.example",
        password,
      });
      admin = a.humanIdentityId;
      adminSession = a.session.sessionId;
      await runtime.platformAdministrationProvisioning.bootstrapAdministrator(
        admin,
        "synthetic-fixture",
      );
      const t = await runtime.services.register.execute({
        email: "target@synthetic.example",
        password,
      });
      target = t.humanIdentityId;
      targetSession = t.session.sessionId;
      const s = await signGoogle();
      source = s.humanIdentityId;
      sourceSession = s.session.sessionId;
      sourceRenewalToken = s.session.renewalToken;
      await plane.saveProduct({
        id: "synthetic-product",
        displayName: "Synthetic product",
        status: "active",
      });
      const { Argon2PasswordOperations } = await import(
        "../../src/authentication/adapters/argon2-password-operations.js"
      );
      const hash = await new Argon2PasswordOperations({
        memoryCost: 1024,
        timeCost: 1,
        parallelism: 1,
      }).hash("Synthetic-workload-secret-123!");
      await plane.saveWorkload({
        id: "synthetic-workload",
        productId: "synthetic-product",
        status: "active",
        secretHash: hash.value,
      });
      await management.registerInspector(
        token(),
        "synthetic-product",
        "synthetic-workload",
      );
      await report(source);
      await report(target);
    });
    it("assigns/unmarks purpose with audit, optimistic revisions and idempotent request binding", async () => {
      const input = {
        humanIdentityId: source,
        purpose: "test" as const,
        reason: "Owner reviewed synthetic test account",
        expectedRevision: 0,
        requestId: randomUUID(),
      };
      assert.deepEqual(
        await management.classify(token(), input),
        await management.classify(token(), input),
      );
      await assert.rejects(
        async () =>
          management.classify(token(), { ...input, purpose: "production" }),
        /already bound/,
      );
      await assert.rejects(
        async () =>
          management.classify(token(), { ...input, requestId: randomUUID() }),
        /changed/,
      );
      await classify(source, "unknown");
      const m = await management.inspect(token(), source);
      assert.equal(m.purpose, "unknown");
      assert.equal(m.lifecycle, "active");
      assert.equal(m.activity, "recently_active");
      assert.equal(
        (
          await db.query(
            "SELECT count(*)::int n FROM platform_audit_events WHERE event_type='human.purpose.changed'",
          )
        ).rows[0]?.n,
        2,
      );
    });
    it("denies ordinary users, revoked admin authority and missing credentials", async () => {
      const payload = {
        humanIdentityId: source,
        purpose: "test",
        reason: "test",
        expectedRevision: 0,
        requestId: randomUUID(),
      };
      for (const [bearer, status] of [
        ["", 401],
        [targetSession, 403],
      ]) {
        const r = await app.inject({
          method: "POST",
          url: "/administration/platform/identity-management/classify",
          payload,
          headers: bearer ? { authorization: `Bearer ${bearer}` } : {},
        });
        assert.equal(r.statusCode, status);
      }
      await db.query(
        "UPDATE platform_administration_memberships SET status='suspended' WHERE human_identity_id=$1",
        [admin],
      );
      await assert.rejects(async () => management.inspect(token(), source));
    });
    it("returns incomplete for unsupported/stale reports; preserves roles and local dependency warnings", async () => {
      await plane.saveProduct({
        id: "unreported",
        displayName: "Unreported",
        status: "active",
      });
      assert.equal(
        (await management.inspect(token(), source)).outcome,
        "assessment_incomplete",
      );
      await db.query("DELETE FROM registered_products WHERE id='unreported'");
      await report(source, { ...zero, localAccounts: 1, subscriptions: 1 });
      assert.equal(
        (await management.inspect(token(), source)).outcome,
        "dependencies_present",
      );
      assert.equal(
        (await management.inspect(token(), admin)).outcome,
        "protected_identity",
      );
      await db.query(
        "UPDATE product_dependency_reports SET expires_at=now()-interval '1 minute'",
      );
      assert.equal(
        (await management.inspect(token(), source)).outcome,
        "assessment_incomplete",
      );
    });
    it("requires explicit product inspection authority and rejects stale/out-of-scope evidence", async () => {
      await assert.rejects(async () =>
        management.reportDependencies("synthetic-workload", "bad", {
          humanIdentityId: source,
          counts: zero,
          evidenceReference: "synthetic",
          observedAt: new Date().toISOString(),
        }),
      );
      await assert.rejects(async () =>
        management.reportDependencies(
          "synthetic-workload",
          "Synthetic-workload-secret-123!",
          {
            humanIdentityId: source,
            counts: zero,
            evidenceReference: "synthetic",
            observedAt: "2000-01-01T00:00:00Z",
          },
        ),
      );
      await db.query("DELETE FROM product_dependency_reports");
      await db.query("DELETE FROM product_dependency_inspectors");
      await assert.rejects(async () => report(source));
    });
    it("protects business ownership and independently detects entitlements", async () => {
      await plane.saveTenant({
        id: "synthetic-business",
        displayName: "Synthetic Business",
        status: "active",
      });
      await plane.saveMembership({
        tenantId: "synthetic-business",
        humanIdentityId: source,
        tenantRole: "owner",
        status: "active",
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      assert.equal(
        (await management.inspect(token(), source)).outcome,
        "protected_identity",
      );
      await db.query(
        "DELETE FROM tenant_memberships WHERE human_identity_id=$1",
        [source],
      );
      await plane.saveMembership({
        tenantId: "synthetic-business",
        humanIdentityId: source,
        tenantRole: "staff",
        status: "active",
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      await plane.saveParticipation({
        tenantId: "synthetic-business",
        productId: "synthetic-product",
        status: "active",
      });
      await plane.saveEntitlement({
        tenantId: "synthetic-business",
        productId: "synthetic-product",
        humanIdentityId: source,
        status: "active",
      });
      const assessment = await management.inspect(token(), source);
      assert.ok(assessment.relationshipsPresent);
      assert.equal(assessment.outcome, "dependencies_present");
    });
    it("refuses a destination with an existing Google relationship and retains ordinary final-method unlink protection", async () => {
      await db.query(
        "INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,status,created_at,updated_at) VALUES($1,$2,'google','other-synthetic-subject','active',now(),now())",
        [randomUUID(), target],
      );
      const c = await verified();
      assert.ok(
        (await management.previewRecovery(token(), c.caseId)).blockers.includes(
          "TARGET_GOOGLE_RELATIONSHIP_EXISTS",
        ),
      );
      await assert.rejects(async () =>
        management.executeRecovery(token(), await execution(c.caseId)),
      );
      const r = await app.inject({
        method: "DELETE",
        url: "/authentication/federated/google/link",
        headers: { authorization: `Bearer ${sourceSession}` },
      });
      assert.equal(r.statusCode, 409);
      assert.equal(
        (await federated.listByHumanIdentityId(HumanIdentityId.from(source)))[0]
          ?.status,
        "active",
      );
    });
    it("shows truly no blocking dependencies after access sessions are explicitly revoked", async () => {
      await sessions.revokeByHumanIdentityId(HumanIdentityId.from(source));
      const m = await management.inspect(token(), source);
      assert.equal(m.outcome, "no_blocking_dependencies_found");
      assert.equal(m.deletionAuthorization, false);
      assert.ok(!JSON.stringify(m).includes(sourceSession));
    });
    it("executes suspension/reactivation/terminal retirement without deleting credentials or restoring old sessions", async () => {
      await classify();
      const execute = async (action: "suspend" | "reactivate" | "retire") => {
        const p = await management.previewLifecycle(token(), [source], action);
        return management.lifecycle(token(), {
          humanIdentityId: source,
          action,
          reviewDigest: p.accounts[0]!.assessment.reviewDigest,
          requestId: randomUUID(),
          confirmation: `${action} ${source}`,
          revokeSessions: true,
        });
      };
      await execute("suspend");
      await assert.rejects(async () => signGoogle());
      assert.equal(
        (
          await runtime.services.validateSession.execute(
            SessionId.from(sourceSession),
          )
        ).outcome,
        "revoked",
      );
      await execute("reactivate");
      assert.equal(
        (await sessions.findById(SessionId.from(sourceSession)))?.status,
        "revoked",
      );
      assert.equal((await signGoogle()).humanIdentityId, source);
      await execute("retire");
      await assert.rejects(async () => execute("reactivate"));
      assert.equal(
        (await federated.listByHumanIdentityId(HumanIdentityId.from(source)))
          .length,
        1,
      );
    });
    it("protects administrators and refuses lifecycle without confirmed test classification/complete evidence", async () => {
      assert.ok(
        !(await management.previewLifecycle(token(), [source], "suspend"))
          .accounts[0]!.eligible,
      );
      await classify(admin);
      assert.ok(
        !(await management.previewLifecycle(token(), [admin], "suspend"))
          .accounts[0]!.eligible,
      );
      await classify();
      await report(source, { ...zero, ownership: 1 });
      assert.ok(
        !(await management.previewLifecycle(token(), [source], "retire"))
          .accounts[0]!.eligible,
      );
    });
    it("handles mixed bulk results, transactional audit failure, safe retry and duplicate requests", async () => {
      await classify();
      const p = await management.previewLifecycle(
        token(),
        [source, admin],
        "suspend",
      );
      const items = p.accounts.map((x) => ({
        humanIdentityId: x.assessment.human.humanIdentityId,
        action: "suspend" as const,
        reviewDigest: x.assessment.reviewDigest,
        requestId: randomUUID(),
        confirmation: `suspend ${x.assessment.human.humanIdentityId}`,
        revokeSessions: true,
      }));
      const original = plane.appendAudit.bind(plane);
      plane.appendAudit = async (e) => {
        if (e.eventType === "human.suspend.completed")
          throw new Error("synthetic audit outage");
        await original(e);
      };
      const failed = await management.bulk(
        token(),
        items,
        "review 2 identities",
      );
      assert.deepEqual(
        failed.results.map((x) => x.state),
        ["blocked", "blocked"],
      );
      assert.equal(
        (await humans.findById(HumanIdentityId.from(source)))?.status,
        "active",
      );
      plane.appendAudit = original;
      const completed = await management.bulk(
        token(),
        items,
        "review 2 identities",
      );
      assert.deepEqual(
        completed.results.map((x) => x.state),
        ["completed", "blocked"],
      );
      assert.deepEqual(
        await management.bulk(token(), items, "review 2 identities"),
        completed,
      );
      assert.equal(
        (
          await db.query(
            "SELECT count(*)::int n FROM platform_audit_events WHERE event_type='human.suspend.completed'",
          )
        ).rows[0]?.n,
        1,
      );
    });
    it("transfers verified immutable Google ownership, preserves target Email/Apple, data and permissions, revokes only source sessions", async () => {
      await db.query(
        "INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,status,created_at,updated_at) VALUES($1,$2,'apple','synthetic-apple-subject','active',now(),now())",
        [randomUUID(), target],
      );
      const c = await verified();
      const relation = (
        await federated.listByHumanIdentityId(HumanIdentityId.from(source))
      )[0]!;
      const beforeCredentials = (
        await db.query("SELECT * FROM credentials ORDER BY id")
      ).rows;
      const beforeRoles = (
        await db.query(
          "SELECT * FROM platform_administration_memberships ORDER BY human_identity_id",
        )
      ).rows;
      const input = await execution(c.caseId);
      assert.deepEqual(
        await management.executeRecovery(token(), input),
        await management.executeRecovery(token(), input),
      );
      const moved = await federated.findActiveByHumanIdentityAndProvider(
        HumanIdentityId.from(target),
        FederatedIdentityProvider.from("google"),
      );
      assert.equal(moved?.id.value, relation.id.value);
      assert.equal(
        moved?.createdAt.toISOString(),
        relation.createdAt.toISOString(),
      );
      assert.equal(
        (await sessions.findById(SessionId.from(sourceSession)))?.status,
        "revoked",
      );
      assert.equal(
        (await sessions.findById(SessionId.from(targetSession)))?.status,
        "active",
      );
      assert.deepEqual(
        (await db.query("SELECT * FROM credentials ORDER BY id")).rows,
        beforeCredentials,
      );
      assert.deepEqual(
        (
          await db.query(
            "SELECT * FROM platform_administration_memberships ORDER BY human_identity_id",
          )
        ).rows,
        beforeRoles,
      );
      assert.equal(
        (await humans.findById(HumanIdentityId.from(source)))?.status,
        "active",
      );
      assert.equal((await signGoogle()).humanIdentityId, target);
      const audits = JSON.stringify(
        (await db.query("SELECT * FROM platform_audit_events")).rows,
      );
      assert.ok(
        !audits.includes("synthetic-secret-subject") &&
          !audits.includes(sourceSession),
      );
    });
    it("rejects email equality/admin-only ownership and old control sessions", async () => {
      const c = await management.prepareRecovery(token(), source, target);
      await assert.rejects(async () =>
        management.proveRecovery(token(), {
          caseId: c.caseId,
          sourceSession: adminSession,
          targetSession,
          identityToken: await jwt(c.nonce),
        }),
      );
      await assert.rejects(async () =>
        management.proveRecovery(token(), {
          caseId: c.caseId,
          sourceSession,
          targetSession,
          identityToken: await jwt(c.nonce),
        }),
      );
      assert.ok(
        (await management.previewRecovery(token(), c.caseId)).blockers.includes(
          "FRESH_CONTROL_REQUIRED",
        ),
      );
    });
    for (const kind of [
      "audience",
      "nonce",
      "subject",
      "expired",
      "signature",
    ] as const)
      it(`rejects ${kind} Google proof without disclosing the subject`, async () => {
        const c = await management.prepareRecovery(token(), source, target);
        sourceSession = (await signGoogle()).session.sessionId;
        targetSession = (
          await runtime.services.login.execute({
            email: "target@synthetic.example",
            password,
          })
        ).sessionId;
        let credential = await jwt(
          kind === "nonce" ? nonce() : c.nonce,
          kind === "subject"
            ? "other-secret-subject"
            : "synthetic-secret-subject",
          kind === "audience" ? "wrong-client" : "synthetic-client",
          kind === "expired" ? -600 : 300,
        );
        if (kind === "signature")
          credential = credential.slice(0, -10) + "aaaaaaaaaa";
        await assert.rejects(async () =>
          management.proveRecovery(token(), {
            caseId: c.caseId,
            sourceSession,
            targetSession,
            identityToken: credential,
          }),
        );
        assert.equal(
          (
            await db.query(
              "SELECT state FROM identity_management_cases WHERE id=$1",
              [c.caseId],
            )
          ).rows[0]?.state,
          "awaiting_proof",
        );
      });
    it("rejects proof replay and expires previously verified evidence", async () => {
      const c = await verified();
      await assert.rejects(async () =>
        management.proveRecovery(token(), {
          caseId: c.caseId,
          sourceSession,
          targetSession,
          identityToken: await jwt(c.nonce),
        }),
      );
      await db.query(
        "UPDATE identity_management_cases SET proof_expires_at=now()-interval '1 minute' WHERE id=$1",
        [c.caseId],
      );
      await assert.rejects(async () =>
        management.executeRecovery(token(), await execution(c.caseId)),
      );
    });
    it("requires confirmation, rechecks changed dependencies and revoked owner proof", async () => {
      const c = await verified(),
        input = await execution(c.caseId);
      await assert.rejects(async () =>
        management.executeRecovery(token(), {
          ...input,
          revokeSourceSessions: false,
        }),
      );
      await report(source, { ...zero, backgroundJobs: 1 });
      await assert.rejects(async () =>
        management.executeRecovery(token(), input),
      );
      await report(source);
      await sessions.revoke(SessionId.from(sourceSession));
      await assert.rejects(async () =>
        management.executeRecovery(token(), await execution(c.caseId)),
      );
    });
    it("rolls back ownership, session revocation, proof consumption and receipt on audit failure, then safely retries", async () => {
      const c = await verified(),
        input = await execution(c.caseId);
      const old = plane.appendAudit.bind(plane);
      plane.appendAudit = async (e) => {
        if (e.eventType === "recovery.google.transferred")
          throw new Error("synthetic failure");
        await old(e);
      };
      await assert.rejects(async () =>
        management.executeRecovery(token(), input),
      );
      assert.equal(
        (
          await federated.findActiveByHumanIdentityAndProvider(
            HumanIdentityId.from(source),
            FederatedIdentityProvider.from("google"),
          )
        )?.humanIdentityId.value,
        source,
      );
      assert.equal(
        (await sessions.findById(SessionId.from(sourceSession)))?.status,
        "active",
      );
      assert.equal(
        (
          await db.query(
            "SELECT state FROM identity_management_cases WHERE id=$1",
            [c.caseId],
          )
        ).rows[0]?.state,
        "verified",
      );
      plane.appendAudit = old;
      assert.equal(
        (await management.executeRecovery(token(), input)).state,
        "completed",
      );
    });
    it("serializes concurrent requests, rejects stale relationship writes and prevents revoked session resurrection", async () => {
      const c = await verified(),
        input = await execution(c.caseId),
        stale = (
          await federated.listByHumanIdentityId(HumanIdentityId.from(source))
        )[0]!,
        staleSession = (await sessions.findById(
          SessionId.from(sourceSession),
        ))!;
      const results = await Promise.allSettled([
        management.executeRecovery(token(), input),
        management.executeRecovery(token(), {
          ...input,
          requestId: randomUUID(),
        }),
      ]);
      assert.equal(results.filter((x) => x.status === "fulfilled").length, 1);
      await assert.rejects(async () => federated.save(stale), /changed/);
      await sessions.save(staleSession);
      assert.equal(
        (await sessions.findById(staleSession.id))?.status,
        "revoked",
      );
      await assert.rejects(async () =>
        runtime.services.renewSession.execute(sourceRenewalToken),
      );
    });
    it("fences actual legacy renewal while transfer revokes sessions and commits", async () => {
      const c = await verified(),
        input = await execution(c.caseId);
      let entered!: () => void, release!: () => void;
      const enteredPromise = new Promise<void>((r) => (entered = r)),
        releasePromise = new Promise<void>((r) => (release = r));
      const old = plane.appendAudit.bind(plane);
      plane.appendAudit = async (e) => {
        if (e.eventType === "recovery.google.transferred") {
          entered();
          await releasePromise;
        }
        await old(e);
      };
      const transfer = management.executeRecovery(token(), input);
      await enteredPromise;
      const renewal = runtime.services.renewSession
        .execute(sourceRenewalToken)
        .then(
          () => false,
          () => true,
        );
      await new Promise((r) => setTimeout(r, 50));
      release();
      await transfer;
      assert.equal(await renewal, true);
      plane.appendAudit = old;
      assert.equal(
        (await sessions.findById(SessionId.from(sourceSession)))?.status,
        "revoked",
      );
      assert.equal((await signGoogle()).humanIdentityId, target);
    });
    it("retains completed bulk items and retries only failed accounts after a partial audit outage", async () => {
      const u = await runtime.services.register.execute({
        email: "second-test@synthetic.example",
        password,
      });
      await report(u.humanIdentityId);
      await classify();
      await classify(u.humanIdentityId);
      const p = await management.previewLifecycle(
        token(),
        [source, u.humanIdentityId],
        "suspend",
      );
      const items = p.accounts.map((x) => ({
        humanIdentityId: x.assessment.human.humanIdentityId,
        action: "suspend" as const,
        reviewDigest: x.assessment.reviewDigest,
        requestId: randomUUID(),
        confirmation: `suspend ${x.assessment.human.humanIdentityId}`,
        revokeSessions: true,
      }));
      const old = plane.appendAudit.bind(plane);
      plane.appendAudit = async (e) => {
        if (
          e.eventType === "human.suspend.completed" &&
          e.subjectReference === u.humanIdentityId
        )
          throw new Error("synthetic per-account outage");
        await old(e);
      };
      assert.deepEqual(
        (
          await management.bulk(token(), items, "review 2 identities")
        ).results.map((x) => x.state),
        ["completed", "blocked"],
      );
      plane.appendAudit = old;
      assert.deepEqual(
        (
          await management.bulk(token(), items, "review 2 identities")
        ).results.map((x) => x.state),
        ["completed", "completed"],
      );
      assert.equal(
        (
          await db.query(
            "SELECT count(*)::int n FROM platform_audit_events WHERE event_type='human.suspend.completed'",
          )
        ).rows[0]?.n,
        2,
      );
    });
    it("returns new directory filters without arbitrary plus-account classification and binds pagination scope", async () => {
      await classify();
      const query = async (filter: string) =>
        app.inject({
          method: "POST",
          url: "/administration/platform/humans/query",
          headers: { authorization: `Bearer ${adminSession}` },
          payload: { filter },
        });
      assert.deepEqual(
        (await query("test")).json().humans.map((h: any) => h.humanIdentityId),
        [source],
      );
      assert.equal((await query("inactive")).json().humans.length, 0);
      const all = (await query("all")).json();
      assert.equal(
        all.humans.find((h: any) => h.humanIdentityId === source).purpose,
        "test",
      );
      assert.equal(
        all.humans.find((h: any) => h.humanIdentityId === source).activity,
        "recently_active",
      );
    });
    it("keeps all new account-changing routes hard-disabled in a production-configured runtime", async () => {
      const production = await buildRuntime(
        loadConfig({
          NODE_ENV: "production",
          REPOSITORY_MODE: "postgres",
          DATABASE_URL: url!,
          LOG_LEVEL: "silent",
        }),
      );
      const p = buildApp(production.services, production.databaseHealth);
      try {
        const paths: [string, Record<string, unknown>][] = [
          [
            "classify",
            {
              humanIdentityId: source,
              purpose: "test",
              reason: "review",
              expectedRevision: 0,
              requestId: randomUUID(),
            },
          ],
          [
            "recovery/prepare",
            {
              sourceHumanIdentityId: source,
              targetHumanIdentityId: target,
              provider: "google",
            },
          ],
          [
            "lifecycle/execute",
            {
              humanIdentityId: source,
              action: "suspend",
              reviewDigest: "0".repeat(64),
              requestId: randomUUID(),
              confirmation: `suspend ${source}`,
              revokeSessions: true,
            },
          ],
        ];
        for (const [path, payload] of paths) {
          const r = await p.inject({
            method: "POST",
            url: `/administration/platform/identity-management/${path}`,
            headers: { authorization: `Bearer ${adminSession}` },
            payload,
          });
          assert.equal(r.statusCode, 403);
          assert.equal(r.json().error.code, "IDENTITY_MANAGEMENT_DISABLED");
        }
      } finally {
        await p.close();
        await production.close();
      }
    });
  },
);
