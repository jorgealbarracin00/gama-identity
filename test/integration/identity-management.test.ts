import assert from "node:assert/strict";
import { before, after, beforeEach, describe, it } from "node:test";
import { createHash, randomBytes, randomUUID } from "node:crypto";
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
import { recoveryOverviewSignals } from "../../src/control-plane/application/recovery-overview.js";
import {
  IdentityManagement,
  activityClassification,
  potentialTestAlias,
  syntheticManagementEnabled,
  digest,
} from "../../src/control-plane/application/identity-management.js";
import { GoogleIdentityTokenVerifier } from "../../src/authentication/federated/adapters/google-identity-token-verifier.js";
import { AppleIdentityTokenVerifier } from "../../src/authentication/federated/adapters/apple-identity-token-verifier.js";
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
      { NODE_ENV: "test", DATABASE_URL: "postgresql://localhost/x_management_test?host=remote.example" },
      { NODE_ENV: "test", DATABASE_URL: "postgresql://127.0.0.1/x_management_test?port=5432" },
      { NODE_ENV: "test", DATABASE_URL: "postgresql://localhost/x_management_test?host=%2Fremote%2Fsocket" },
      { NODE_ENV: "test", DATABASE_URL: "https://localhost/x_management_test" },
      { NODE_ENV: "test", DATABASE_URL: "socket://localhost/x_management_test" },
      { NODE_ENV: "test", DATABASE_URL: "postgresql://localhost/x_management_test#ignored" },
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
      new SignJWT({ nonce: n, auth_time: Math.floor(Date.now()/1000) })
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
    const appleCredential = async (subject: string) => {
      const n = nonce();
      return {nonce: n, identityToken: await new SignJWT({nonce: createHash("sha256").update(n).digest("base64url"), email: "verified-owner@synthetic.example", email_verified: true})
        .setProtectedHeader({alg:"RS256"}).setIssuer("https://appleid.apple.com").setAudience("synthetic-apple-client").setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(key.privateKey)};
    };
    const seedAppleOwner = async (id: string, subject: string, status = "active") => {
      await db.query("INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,provider_email,status,created_at,updated_at) VALUES($1,$2,'apple',$3,'original-owner@synthetic.example',$4,now(),now())", [randomUUID(), id, subject, status]);
    };
    const appleOwner = async (body: Record<string, unknown>, bearer = adminSession) => app.inject({method:"POST",url:"/administration/platform/identity-management/recovery/owner/apple",headers:bearer ? {authorization:`Bearer ${bearer}`} : {},payload:body});
    const ownerSnapshot = async () => ({
      humans: (await db.query("SELECT id,status,write_revision FROM human_identities ORDER BY id")).rows,
      providers: (await db.query("SELECT id,human_identity_id,provider,status,provider_email,provider_email_verified,provider_email_private,write_revision FROM federated_identities ORDER BY id")).rows,
      counts: (await db.query("SELECT (SELECT count(*) FROM sessions)::int sessions,(SELECT count(*) FROM credentials)::int credentials,(SELECT count(*) FROM federated_authentication_nonces)::int nonces,(SELECT count(*) FROM platform_audit_events)::int audits,(SELECT count(*) FROM tenant_memberships)::int memberships,(SELECT count(*) FROM product_entitlements)::int entitlements")).rows,
    });
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
          maximumAuthenticationAgeSeconds:300,
          keyResolver: async () => key.publicKey,
        }),
        new AppleIdentityTokenVerifier({clientIds:["synthetic-apple-client"],keyResolver:async()=>key.publicKey}),
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
          authenticateFederated: auth,
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
    it("reports independently authoritative categories and classification actor/time without treating unavailable product evidence as clear", async () => {
      await classify();
      const m=await management.inspect(token(),source);
      assert.equal(m.classifiedBy,admin); assert.ok(m.classifiedAt);
      assert.equal(m.categories.find(x=>x.category==='product_entitlements')?.status,'verified_clear');
      assert.equal(m.categories.find(x=>x.category==='authentication_providers')?.status,'dependencies_present');
      await db.query('DELETE FROM product_dependency_reports WHERE human_identity_id=$1',[source]);
      const incomplete=await management.inspect(token(),source);
      assert.equal(incomplete.categories.find(x=>x.category==='subscriptions')?.status,'unknown');
      assert.equal(incomplete.categories.find(x=>x.category==='product_local_data')?.count,null);
    });
    it("native Google control binds exact case subject without creating a source session or Human", async () => {
      const c=await management.prepareRecovery(token(),source,target);
      const t=await runtime.services.login.execute({email:'target@synthetic.example',password});
      targetSession=t.sessionId;
      const before=(await db.query('SELECT count(*)::int n FROM sessions WHERE human_identity_id=$1',[source])).rows[0]!.n;
      await assert.rejects(()=>management.proveNativeRecovery(token(),{caseId:c.caseId,targetSession,identityToken:'invalid'}));
      await management.proveNativeRecovery(token(),{caseId:c.caseId,targetSession,identityToken:await jwt(c.nonce)});
      assert.equal((await db.query('SELECT count(*)::int n FROM sessions WHERE human_identity_id=$1',[source])).rows[0]!.n,before);
      const p=await management.previewRecovery(token(),c.caseId);assert.deepEqual(p.blockers,[]);
      await management.executeRecovery(token(),await execution(c.caseId));
      assert.equal((await humans.findById(HumanIdentityId.from(target)))?.id.value,target);
      assert.equal((await federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(target),FederatedIdentityProvider.from('google')))?.humanIdentityId.value,target);
    });
    const compensationVerified=async()=>{
      const c=await verified(),receipt=await management.executeRecovery(token(),await execution(c.caseId));
      const cp=await management.prepareCompensation(token(),String(receipt.requestId));
      const t=await runtime.services.login.execute({email:'target@synthetic.example',password});targetSession=t.sessionId;
      await management.proveCompensation(token(),{caseId:cp.caseId,targetSession,identityToken:await jwt(cp.nonce)});
      await report(source);await report(target);
      const p=await management.previewCompensation(token(),cp.caseId);
      return {cp,receipt,p,input:{caseId:cp.caseId,requestId:randomUUID(),reviewDigest:p.reviewDigest,confirmation:`return google ${target} to ${source} receipt ${receipt.requestId}`,revokeTargetSessions:true,acceptFreshSignIn:true}};
    };
    it("existing-only Apple administrator step-up preserves the Human and methods, accepts an older valid admin session and rejects replay", async () => {
      await seedAppleOwner(admin, "synthetic-apple-admin");
      await db.query("UPDATE sessions SET authenticated_at=now()-interval '10 minutes' WHERE id=$1", [adminSession]);
      const credential = await appleCredential("synthetic-apple-admin"), before = await ownerSnapshot();
      const response = await appleOwner(credential);
      assert.equal(response.statusCode, 200); assert.equal(response.headers["cache-control"], "no-store");
      assert.equal(response.json().session.humanIdentityId, admin);
      assert.equal(response.json().account.email, "verified-owner@synthetic.example");
      assert.equal((await sessions.findById(SessionId.from(response.json().session.sessionId)))?.authenticationMethod, "apple");
      assert.deepEqual((await ownerSnapshot()).humans, before.humans);
      assert.equal((await federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(admin), FederatedIdentityProvider.from("apple")))?.humanIdentityId.value, admin);
      assert.equal((await runtime.services.login.execute({email:"admin@synthetic.example",password})).humanIdentityId, admin);
      const successful = await ownerSnapshot();
      assert.equal((await appleOwner(credential)).statusCode, 403);
      assert.deepEqual(await ownerSnapshot(), successful);
      const audits = (await db.query("SELECT event_data FROM platform_audit_events WHERE event_type='recovery.owner.apple.authenticated'")).rows;
      assert.equal(audits.length, 1); assert.equal(audits[0]!.event_data.scope, "administrator_step_up");
      assert.ok(!JSON.stringify(audits).includes(credential.identityToken) && !JSON.stringify(audits).includes("synthetic-apple-admin"));
    });
    it("existing-only Apple owner authentication rejects an unknown subject without creating a Human, relationship, session or nonce record", async () => {
      const before = await ownerSnapshot();
      assert.equal((await appleOwner(await appleCredential("unregistered-apple-owner"))).statusCode, 403);
      assert.deepEqual(await ownerSnapshot(), before);
    });
    it("Apple owner authentication binds the exact server-derived primary and never accepts another linked Human by email", async () => {
      await seedAppleOwner(target, "synthetic-apple-primary");
      const credential = await appleCredential("synthetic-apple-primary"), before = await ownerSnapshot();
      assert.equal((await appleOwner(credential)).statusCode, 403);
      assert.deepEqual(await ownerSnapshot(), before);
      const c = await management.prepareRecovery(token(), source, target);
      const response = await appleOwner({...credential, caseId:c.caseId, kind:"recovery"});
      assert.equal(response.statusCode, 200); assert.equal(response.json().session.humanIdentityId, target);
      assert.equal((await humans.findById(HumanIdentityId.from(target)))?.status, "active");
      assert.equal((await runtime.services.login.execute({email:"target@synthetic.example",password})).humanIdentityId, target);
    });
    for (const inactive of ["provider", "human"] as const) it(`Apple owner authentication rejects an inactive ${inactive} without metadata or session writes`, async () => {
      await seedAppleOwner(target, "synthetic-inactive-apple-primary", inactive === "provider" ? "disabled" : "active");
      const c = await management.prepareRecovery(token(), source, target);
      if (inactive === "human") await db.query("UPDATE human_identities SET status='suspended' WHERE id=$1", [target]);
      const before = await ownerSnapshot();
      assert.equal((await appleOwner({...await appleCredential("synthetic-inactive-apple-primary"), caseId:c.caseId})).statusCode, 403);
      assert.deepEqual(await ownerSnapshot(), before);
    });
    it("Apple owner authentication rejects foreign, expired, cancelled and already verified cases before accepting any credential", async () => {
      await seedAppleOwner(target, "synthetic-apple-primary");
      const other = await runtime.services.register.execute({email:"other-apple-admin@synthetic.example", password});
      await runtime.platformAdministrationProvisioning.bootstrapAdministrator(other.humanIdentityId, "synthetic-other-admin");
      const foreign = await management.prepareRecovery(SessionId.from(other.session.sessionId), source, target);
      let before = await ownerSnapshot();
      assert.equal((await appleOwner({...await appleCredential("synthetic-apple-primary"), caseId:foreign.caseId})).statusCode, 404);
      assert.deepEqual(await ownerSnapshot(), before);
      const own = await management.prepareRecovery(token(), source, target);
      await db.query("UPDATE identity_management_cases SET expires_at=now()-interval '1 second' WHERE id=$1", [own.caseId]);
      before = await ownerSnapshot();
      assert.equal((await appleOwner({...await appleCredential("synthetic-apple-primary"), caseId:own.caseId})).statusCode, 409);
      assert.deepEqual(await ownerSnapshot(), before);
      for (const state of ["cancelled", "verified"]) {
        await db.query("UPDATE identity_management_cases SET state=$2,expires_at=now()+interval '10 minutes' WHERE id=$1", [own.caseId, state]);
        before = await ownerSnapshot();
        assert.equal((await appleOwner({...await appleCredential("synthetic-apple-primary"), caseId:own.caseId})).statusCode, 409);
        assert.deepEqual(await ownerSnapshot(), before);
      }
    });
    it("Apple owner route requires administrator authority, strict Apple-only input and the disabled production gate", async () => {
      const credential = await appleCredential("unknown-apple-owner"), before = await ownerSnapshot();
      assert.equal((await appleOwner(credential, "")).statusCode, 401);
      assert.equal((await appleOwner(credential, "forged")).statusCode, 401);
      assert.equal((await appleOwner(credential, targetSession)).statusCode, 403);
      for (const extra of [{expectedHumanIdentityId:target}, {provider:"google"}, {humanIdentityId:admin}]) assert.equal((await appleOwner({...credential, ...extra})).statusCode, 400);
      const closed = Object.create(management) as IdentityManagement; Object.defineProperty(closed, "executionEnabled", {value:false});
      const productionApp = buildApp({...runtime.services, authenticateFederated:auth, administration:{...runtime.services.administration, identityManagement:closed}}, runtime.databaseHealth);
      try {
        const response = await productionApp.inject({method:"POST",url:"/administration/platform/identity-management/recovery/owner/apple",headers:{authorization:`Bearer ${adminSession}`},payload:credential});
        assert.equal(response.statusCode, 403); assert.equal(response.json().error.code, "IDENTITY_MANAGEMENT_DISABLED");
      } finally {await productionApp.close();}
      assert.deepEqual(await ownerSnapshot(), before);
    });
    it("Apple owner authentication rolls back nonce, metadata and new session atomically if successful audit persistence fails", async () => {
      await seedAppleOwner(admin, "synthetic-apple-admin");
      const credential = await appleCredential("synthetic-apple-admin"), before = await ownerSnapshot(), append = plane.appendAudit.bind(plane);
      plane.appendAudit = async event => {if (event.eventType === "recovery.owner.apple.authenticated") throw new Error("synthetic Apple owner audit failure"); await append(event);};
      try {assert.equal((await appleOwner(credential)).statusCode, 500);} finally {plane.appendAudit = append;}
      assert.deepEqual(await ownerSnapshot(), before);
      assert.equal((await appleOwner(credential)).statusCode, 200);
    });
    it("Apple owner authentication serializes concurrent nonce reuse into one session and one successful audit", async () => {
      await seedAppleOwner(admin, "synthetic-apple-admin");
      const credential = await appleCredential("synthetic-apple-admin");
      const before = (await db.query("SELECT count(*)::int n FROM sessions")).rows[0]!.n;
      const responses = await Promise.all([appleOwner(credential), appleOwner(credential)]);
      assert.deepEqual(responses.map(r=>r.statusCode).sort(), [200,403]);
      assert.equal((await db.query("SELECT count(*)::int n FROM sessions")).rows[0]!.n, before + 1);
      assert.equal((await db.query("SELECT id FROM platform_audit_events WHERE event_type='recovery.owner.apple.authenticated'")).rows.length, 1);
    });
    it("Apple owner authentication derives the compensation primary from its exact actor-owned receipt and supplies supported fresh control", async () => {
      await seedAppleOwner(target, "synthetic-apple-primary");
      const c = await verified(), receipt = await management.executeRecovery(token(), await execution(c.caseId));
      const compensation = await management.prepareCompensation(token(), String(receipt.requestId));
      const response = await appleOwner({...await appleCredential("synthetic-apple-primary"), caseId:compensation.caseId, kind:"compensation"});
      assert.equal(response.statusCode, 200); assert.equal(response.json().session.humanIdentityId, target);
      const proof = await management.proveCompensation(token(), {caseId:compensation.caseId, targetSession:response.json().session.sessionId, identityToken:await jwt(compensation.nonce)});
      assert.equal(proof.controlVerified, true);
      assert.deepEqual((await management.previewCompensation(token(), compensation.caseId)).blockers, []);
      assert.equal((await federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(target), FederatedIdentityProvider.from("apple")))?.humanIdentityId.value, target);
    });
    const seedHandoff = async (caseId: string, kind: "recovery" | "compensation", state: "awaiting_callback" | "processing" | "verified") => {
      const id = randomUUID();
      await db.query("INSERT INTO identity_management_google_handoffs(id,case_id,case_kind,recovery_case_id,compensation_case_id,actor_id,target_id,admin_session_hash,target_session_hash,state_digest,code_verifier,state,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now(),now()+interval '5 minutes')", [
        id, caseId, kind, kind === "recovery" ? caseId : null, kind === "compensation" ? caseId : null,
        admin, target, digest(adminSession), digest(targetSession), digest(randomUUID()), state === "awaiting_callback" ? "A".repeat(43) : null, state,
      ]);
      return id;
    };
    it("fresh recovery preparation supersedes only its prior owner case, retains proof history and cancels all associated handoff stages", async () => {
      const previous = await verified(), oldInput = await execution(previous.caseId);
      for (const state of ["awaiting_callback", "processing", "verified"] as const) await seedHandoff(previous.caseId, "recovery", state);
      const replacement = await verified();
      assert.equal((await db.query("SELECT state FROM identity_management_cases WHERE id=$1", [previous.caseId])).rows[0]!.state, "cancelled");
      assert.equal((await db.query("SELECT session_hash FROM identity_management_control_proofs WHERE case_id=$1", [previous.caseId])).rows.length, 2);
      const oldHandoffs = (await db.query("SELECT state,code_verifier FROM identity_management_google_handoffs WHERE case_id=$1", [previous.caseId])).rows;
      assert.equal(oldHandoffs.length, 3); assert.ok(oldHandoffs.every(h => h.state === "cancelled" && h.code_verifier === null));
      assert.deepEqual((await management.previewRecovery(token(), replacement.caseId)).blockers, []);
      await assert.rejects(async () => management.proveRecovery(token(), {caseId: previous.caseId, sourceSession, targetSession, identityToken: await jwt(previous.nonce)}), /new recovery verification/);
      await assert.rejects(() => management.executeRecovery(token(), oldInput), /FRESH_CONTROL_REQUIRED/);
      assert.equal((await db.query("SELECT id FROM platform_audit_events WHERE event_type='recovery.control.superseded' AND subject_reference=$1", [previous.caseId])).rows.length, 1);
      assert.equal((await federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(source), FederatedIdentityProvider.from("google")))?.humanIdentityId.value, source);
    });
    it("concurrent recovery retries retain exactly one own pending case without cancelling other actors or pairs", async () => {
      const previous = await management.prepareRecovery(token(), source, target);
      const otherTarget = (await runtime.services.register.execute({email: "other-target@synthetic.example", password})).humanIdentityId;
      const otherPair = await management.prepareRecovery(token(), source, otherTarget);
      const otherAdmin = await runtime.services.register.execute({email: "other-recovery-admin@synthetic.example", password});
      await runtime.platformAdministrationProvisioning.bootstrapAdministrator(otherAdmin.humanIdentityId, "synthetic-other-admin");
      const foreign = await management.prepareRecovery(SessionId.from(otherAdmin.session.sessionId), source, target);
      const retries = await Promise.all([management.prepareRecovery(token(), source, target), management.prepareRecovery(token(), source, target)]);
      const rows = (await db.query("SELECT id,state FROM identity_management_cases")).rows;
      assert.equal(rows.find(r => r.id === previous.caseId)!.state, "cancelled");
      assert.equal(rows.find(r => r.id === otherPair.caseId)!.state, "awaiting_proof");
      assert.equal(rows.find(r => r.id === foreign.caseId)!.state, "awaiting_proof");
      assert.equal(rows.filter(r => retries.some(c => c.caseId === r.id) && r.state === "awaiting_proof").length, 1);
      assert.equal(rows.filter(r => retries.some(c => c.caseId === r.id) && r.state === "cancelled").length, 1);
    });
    it("recovery supersession and handoff cleanup roll back atomically when the audit fails", async () => {
      const previous = await verified(), handoffId = await seedHandoff(previous.caseId, "recovery", "awaiting_callback");
      const beforeCases = (await db.query("SELECT * FROM identity_management_cases ORDER BY id")).rows;
      const beforeProofs = (await db.query("SELECT * FROM identity_management_control_proofs ORDER BY session_hash")).rows;
      const append = plane.appendAudit.bind(plane);
      plane.appendAudit = async event => {if (event.eventType === "recovery.control.superseded") throw new Error("synthetic supersession audit failure"); await append(event);};
      try {await assert.rejects(() => management.prepareRecovery(token(), source, target), /synthetic supersession audit failure/);}
      finally {plane.appendAudit = append;}
      assert.deepEqual((await db.query("SELECT * FROM identity_management_cases ORDER BY id")).rows, beforeCases);
      assert.deepEqual((await db.query("SELECT * FROM identity_management_control_proofs ORDER BY session_hash")).rows, beforeProofs);
      const handoff = (await db.query("SELECT state,code_verifier FROM identity_management_google_handoffs WHERE id=$1", [handoffId])).rows[0]!;
      assert.equal(handoff.state, "awaiting_callback"); assert.equal(handoff.code_verifier, "A".repeat(43));
      assert.deepEqual((await management.previewRecovery(token(), previous.caseId)).blockers, []);
    });
    it("fresh compensation preparation supersedes its exact receipt request while retaining history and rejecting old operations", async () => {
      const {cp, receipt, input} = await compensationVerified();
      for (const state of ["awaiting_callback", "processing", "verified"] as const) await seedHandoff(cp.caseId, "compensation", state);
      const beforeProofs = (await db.query("SELECT session_hash FROM identity_management_control_proofs")).rows.length;
      const replacement = await management.prepareCompensation(token(), String(receipt.requestId));
      assert.equal((await db.query("SELECT state FROM identity_recovery_compensations WHERE id=$1", [cp.caseId])).rows[0]!.state, "cancelled");
      assert.equal((await db.query("SELECT session_hash FROM identity_management_control_proofs")).rows.length, beforeProofs);
      assert.ok((await db.query("SELECT state,code_verifier FROM identity_management_google_handoffs WHERE case_id=$1", [cp.caseId])).rows.every(h => h.state === "cancelled" && h.code_verifier === null));
      await assert.rejects(async () => management.proveCompensation(token(), {caseId: cp.caseId, targetSession, identityToken: await jwt(cp.nonce)}), /new compensation verification/);
      await assert.rejects(() => management.executeCompensation(token(), input), /FRESH_CONTROL_REQUIRED/);
      targetSession = (await runtime.services.login.execute({email: "target@synthetic.example", password})).sessionId;
      await management.proveCompensation(token(), {caseId: replacement.caseId, targetSession, identityToken: await jwt(replacement.nonce)});
      assert.deepEqual((await management.previewCompensation(token(), replacement.caseId)).blockers, []);
      assert.equal((await db.query("SELECT id FROM platform_audit_events WHERE event_type='recovery.compensation.superseded' AND subject_reference=$1", [cp.caseId])).rows.length, 1);
      assert.equal((await federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(target), FederatedIdentityProvider.from("google")))?.humanIdentityId.value, target);
    });
    it("concurrent compensation retries preserve another actor's request and leave one own pending request", async () => {
      const {cp, receipt} = await compensationVerified();
      const otherAdmin = (await runtime.services.register.execute({email: "foreign-compensation-admin@synthetic.example", password})).humanIdentityId;
      const foreignId = randomUUID();
      await db.query("INSERT INTO identity_recovery_compensations(id,original_request_id,actor_human_identity_id,nonce,state,created_at,expires_at) VALUES($1,$2,$3,$4,'awaiting_proof',now(),now()+interval '15 minutes')", [foreignId, receipt.requestId, otherAdmin, nonce()]);
      const retries = await Promise.all([management.prepareCompensation(token(), String(receipt.requestId)), management.prepareCompensation(token(), String(receipt.requestId))]);
      const rows = (await db.query("SELECT id,state FROM identity_recovery_compensations")).rows;
      assert.equal(rows.find(r => r.id === cp.caseId)!.state, "cancelled");
      assert.equal(rows.find(r => r.id === foreignId)!.state, "awaiting_proof");
      assert.equal(rows.filter(r => retries.some(c => c.caseId === r.id) && r.state === "awaiting_proof").length, 1);
      assert.equal(rows.filter(r => retries.some(c => c.caseId === r.id) && r.state === "cancelled").length, 1);
    });
    it("compensation supersession and handoff cleanup roll back atomically on audit failure", async () => {
      const {cp, receipt} = await compensationVerified(), handoffId = await seedHandoff(cp.caseId, "compensation", "awaiting_callback");
      const before = (await db.query("SELECT * FROM identity_recovery_compensations ORDER BY id")).rows;
      const append = plane.appendAudit.bind(plane);
      plane.appendAudit = async event => {if (event.eventType === "recovery.compensation.superseded") throw new Error("synthetic compensation supersession failure"); await append(event);};
      try {await assert.rejects(() => management.prepareCompensation(token(), String(receipt.requestId)), /synthetic compensation supersession failure/);}
      finally {plane.appendAudit = append;}
      assert.deepEqual((await db.query("SELECT * FROM identity_recovery_compensations ORDER BY id")).rows, before);
      const handoff = (await db.query("SELECT state,code_verifier FROM identity_management_google_handoffs WHERE id=$1", [handoffId])).rows[0]!;
      assert.equal(handoff.state, "awaiting_callback"); assert.equal(handoff.code_verifier, "A".repeat(43));
      assert.deepEqual((await management.previewCompensation(token(), cp.caseId)).blockers, []);
    });
    it("Overview marks recovery ready only after actual fresh proof and full safeguards; production, unknown dependencies and expiry remain explicit blockers",async()=>{
      const c=await verified();
      const proofPreview=await management.previewRecovery(token(),c.caseId);
      assert.ok(proofPreview.proofExpiresAt);
      assert.ok(new Date(proofPreview.proofExpiresAt).getTime()<=Date.now()+300000);
      assert.ok(new Date(proofPreview.proofExpiresAt).getTime()<new Date(c.expiresAt).getTime());
      const ready=await recoveryOverviewSignals(db,management,token(),admin,new SystemClock());
      assert.equal(ready.length,1);assert.equal(ready[0]!.title,'Recovery ready for review');assert.equal(ready[0]!.destination,'recovery');
      const consoleOverview=await app.inject({method:'POST',url:'/administration/platform/overview',headers:{authorization:`Bearer ${adminSession}`},payload:{}});
      assert.equal(consoleOverview.statusCode,200);assert.ok(consoleOverview.json().issues.some((i:{title:string})=>i.title==='Recovery ready for review'));
      const production=Object.create(management) as IdentityManagement;Object.defineProperty(production,'executionEnabled',{value:false});
      const closed=await recoveryOverviewSignals(db,production,token(),admin,new SystemClock());assert.equal(closed[0]!.title,'Recovery blocked');assert.match(closed[0]!.detail,/Production recovery execution is disabled/);
      await db.query('DELETE FROM product_dependency_reports WHERE human_identity_id=$1',[source]);
      const unknown=await recoveryOverviewSignals(db,management,token(),admin,new SystemClock());assert.equal(unknown[0]!.title,'Recovery blocked');assert.match(unknown[0]!.detail,/dependency inspection is incomplete/);
      await report(source);await db.query("UPDATE identity_management_cases SET proof_expires_at=now()-interval '1 second',expires_at=now()-interval '1 second' WHERE id=$1",[c.caseId]);
      const expired=await recoveryOverviewSignals(db,management,token(),admin,new SystemClock());assert.equal(expired[0]!.title,'Recovery blocked');assert.match(expired[0]!.detail,/request has expired/);
      assert.ok(!JSON.stringify(ready).includes('synthetic-secret-subject')&&!JSON.stringify(ready).includes(targetSession));
    });
    for (const owner of ["source", "target"] as const) {
      for (const invalidation of ["revoked", "expired"] as const) {
        it(`Preview and Overview block ${invalidation} ordinary ${owner} account-control proof`, async () => {
          const c = await verified();
          assert.deepEqual((await management.previewRecovery(token(), c.caseId)).blockers, []);
          const proofSession = owner === "source" ? sourceSession : targetSession;
          if (invalidation === "revoked") await sessions.revoke(SessionId.from(proofSession));
          else await db.query("UPDATE sessions SET expires_at=now()-interval '1 second' WHERE id=$1", [proofSession]);
          const preview = await management.previewRecovery(token(), c.caseId);
          assert.ok(preview.blockers.includes("CONTROL_REVOKED"));
          const issues = await recoveryOverviewSignals(db, management, token(), admin, new SystemClock());
          assert.equal(issues[0]!.title, "Recovery blocked");
          assert.match(issues[0]!.detail, /account-control session is no longer valid/);
          await assert.rejects(() => management.executeRecovery(token(), {
            caseId: c.caseId, requestId: randomUUID(), reviewDigest: preview.reviewDigest,
            confirmation: `transfer google ${source} to ${target}`,
            revokeSourceSessions: true, acceptSourceLossOfAccess: true,
          }), /CONTROL_REVOKED/);
          assert.equal((await federated.findActiveByHumanIdentityAndProvider(
            HumanIdentityId.from(source), FederatedIdentityProvider.from("google"),
          ))?.humanIdentityId.value, source);
          assert.ok(!JSON.stringify(issues).includes(proofSession));
        });
      }
    }
    it("Preview verifies each stored owner proof expiry and the exact Google relationship", async () => {
      const c = await verified();
      await db.query("UPDATE identity_management_control_proofs SET expires_at=now()-interval '1 second' WHERE case_id=$1 AND human_identity_id=$2", [c.caseId, source]);
      assert.ok((await management.previewRecovery(token(), c.caseId)).blockers.includes("CONTROL_EXPIRED"));
      const issues = await recoveryOverviewSignals(db, management, token(), admin, new SystemClock());
      assert.equal(issues[0]!.title, "Recovery blocked");
      assert.match(issues[0]!.detail, /Account-control evidence is missing or expired/);
      await db.query("UPDATE identity_management_cases SET relationship_id=NULL WHERE id=$1", [c.caseId]);
      assert.ok((await management.previewRecovery(token(), c.caseId)).blockers.includes("RELATIONSHIP_CHANGED"));
    });
    it("Overview bounds actor-owned recovery summaries and explains missing proof without exposing other administrators' cases",async()=>{
      const foreign=(await runtime.services.register.execute({email:'other-admin@synthetic.example',password})).humanIdentityId;
      await plane.insertPlatformAdministrationMembershipIfAbsent({humanIdentityId:foreign,platformRole:'administrator',status:'active',createdAt:new Date(),updatedAt:new Date()});
      const foreignCase=randomUUID();
      for(let i=0;i<13;i++)await db.query("INSERT INTO identity_management_cases(id,actor_human_identity_id,source_human_identity_id,target_human_identity_id,provider,nonce,state,created_at,expires_at) VALUES($1,$2,$3,$4,'google',$5,'awaiting_proof',now(),now()+interval '10 minutes')",[randomUUID(),admin,source,target,nonce()]);
      await db.query("INSERT INTO identity_management_cases(id,actor_human_identity_id,source_human_identity_id,target_human_identity_id,provider,nonce,state,created_at,expires_at) VALUES($1,$2,$3,$4,'google',$5,'awaiting_proof',now(),now()+interval '10 minutes')",[foreignCase,foreign,source,target,nonce()]);
      const issues=await recoveryOverviewSignals(db,management,token(),admin,new SystemClock());assert.equal(issues.length,10);assert.ok(issues.every(i=>i.title==='Recovery blocked'&&/verification are missing or expired/.test(i.detail)));assert.ok(!JSON.stringify(issues).includes(foreignCase));
    });
    it("Overview uses the same receipt-bound compensation safeguards and blocks a revoked primary proof",async()=>{
      const {cp,p}=await compensationVerified();
      assert.ok(p.proofExpiresAt);
      assert.ok(new Date(p.proofExpiresAt).getTime()<=Date.now()+300000);
      assert.ok(new Date(p.proofExpiresAt).getTime()<new Date(cp.expiresAt).getTime());
      const ready=await recoveryOverviewSignals(db,management,token(),admin,new SystemClock());assert.equal(ready.length,1);assert.ok(ready[0]!.id.includes(cp.caseId));assert.equal(ready[0]!.title,'Recovery ready for review');
      await sessions.revoke(SessionId.from(targetSession));
      const revoked=await recoveryOverviewSignals(db,management,token(),admin,new SystemClock());assert.equal(revoked[0]!.title,'Recovery blocked');assert.match(revoked[0]!.detail,/session is no longer valid/);
    });
    it("treats pending compensation as an unresolved recovery dependency for lifecycle management",async()=>{
      const {cp}=await compensationVerified();
      await classify(source);
      const p=await management.previewLifecycle(token(),[source],'retire');
      assert.ok(p.accounts[0]!.blockers.includes('RELATIONSHIPS_REQUIRE_REVIEW'));
      assert.equal(p.accounts[0]!.assessment.pendingRecoveryReferences,1);
      await db.query("UPDATE identity_recovery_compensations SET expires_at=now()-interval '1 second' WHERE id=$1",[cp.caseId]);
      const after=await management.previewLifecycle(token(),[source],'retire');
      assert.equal(after.accounts[0]!.assessment.pendingRecoveryReferences,0);
    });
    it("receipt-bound compensation requires new control, restores only Google and never revives revoked sessions", async()=>{
      const {cp,receipt,p,input}=await compensationVerified();assert.deepEqual(p.blockers,[]);assert.equal(p.automaticRollback,false);
      const result=await management.executeCompensation(token(),input);
      assert.deepEqual(result,await management.executeCompensation(token(),input));
      assert.equal(result.oldSessionsRestored,false);
      assert.equal((await federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(source),FederatedIdentityProvider.from('google')))?.id.value,receipt.relationshipId);
      assert.equal((await humans.findById(HumanIdentityId.from(source)))?.status,'active');
      for(const id of [source,target])assert.ok((await sessions.listByHumanIdentityId(HumanIdentityId.from(id))).every(s=>s.status==='revoked'));
      assert.equal((await runtime.services.login.execute({email:'target@synthetic.example',password})).humanIdentityId,target);
      assert.equal((await signGoogle()).humanIdentityId,source);
      assert.equal((await db.query("SELECT count(*)::int n FROM platform_audit_events WHERE event_type='recovery.google.compensated'")).rows[0]!.n,1);
      await assert.rejects(()=>management.prepareCompensation(token(),String(receipt.requestId)),/existing compensation/);
      const recorded=JSON.stringify((await db.query('SELECT * FROM platform_audit_events')).rows);assert.ok(!recorded.includes('synthetic-secret-subject')&&!recorded.includes(targetSession));
    });
    it("compensation blocks changed ownership, absent proof, stale review, bad confirmation and unknown dependencies",async()=>{
      const {cp,input}=await compensationVerified();
      await assert.rejects(()=>management.executeCompensation(token(),{...input,confirmation:'return google'}),/Confirm the exact/);
      await db.query('DELETE FROM product_dependency_reports WHERE human_identity_id=$1',[source]);
      const p=await management.previewCompensation(token(),cp.caseId);assert.ok(p.blockers.includes('SOURCE_DEPENDENCIES_UNKNOWN'));
      await assert.rejects(()=>management.executeCompensation(token(),input),/SOURCE_DEPENDENCIES_UNKNOWN/);
      await report(source);await report(target);
      await db.query("UPDATE federated_identities SET write_revision=write_revision+1 WHERE human_identity_id=$1 AND provider='google'",[target]);
      assert.ok((await management.previewCompensation(token(),cp.caseId)).blockers.includes('RELATIONSHIP_CHANGED'));
      await assert.rejects(()=>management.executeCompensation(token(),input),/RELATIONSHIP_CHANGED/);
    });
    // Post-V2.2 compensation safety regressions use only this disposable
    // PostgreSQL fixture. They do not broaden production execution authority.
    it("compensation safety rejects a newly added source credential without changing ownership or sessions", async () => {
      const {cp, input} = await compensationVerified();
      await db.query("INSERT INTO credentials(id,human_identity_id,normalized_email,password_hash,status,created_at,updated_at) SELECT $1,$2,'new-source-control@synthetic.example',password_hash,'active',now(),now() FROM credentials WHERE human_identity_id=$3 LIMIT 1", [randomUUID(), source, target]);
      assert.ok((await management.previewCompensation(token(), cp.caseId)).blockers.includes("SOURCE_AUTHENTICATION_CHANGED"));
      const before = await ownerSnapshot();
      await assert.rejects(() => management.executeCompensation(token(), input), /SOURCE_AUTHENTICATION_CHANGED/);
      assert.deepEqual(await ownerSnapshot(), before);
      assert.equal((await db.query("SELECT state FROM identity_recovery_compensations WHERE id=$1", [cp.caseId])).rows[0]!.state, "verified");
    });
    it("compensation safety rejects a new positive product dependency rather than treating it as incomplete or empty", async () => {
      const {cp, input} = await compensationVerified();
      await report(source, {...zero, localAccounts: 1});
      const preview = await management.previewCompensation(token(), cp.caseId);
      assert.ok(preview.blockers.includes("SOURCE_DEPENDENCIES_PRESENT"));
      assert.equal(preview.source.unknownCoverage, false);
      const before = await ownerSnapshot();
      await assert.rejects(() => management.executeCompensation(token(), input), /SOURCE_DEPENDENCIES_PRESENT/);
      assert.deepEqual(await ownerSnapshot(), before);
    });
    it("compensation safety rejects an exact Google relationship replacement and preserves both relationship histories", async () => {
      const {cp, receipt, input} = await compensationVerified();
      await db.query("UPDATE federated_identities SET status='disabled',write_revision=write_revision+1 WHERE id=$1", [receipt.relationshipId]);
      const replacement = randomUUID();
      await db.query("INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,status,created_at,updated_at) VALUES($1,$2,'google','synthetic-replacement-subject','active',now(),now())", [replacement, target]);
      assert.ok((await management.previewCompensation(token(), cp.caseId)).blockers.includes("RELATIONSHIP_CHANGED"));
      const before = await ownerSnapshot();
      await assert.rejects(() => management.executeCompensation(token(), input), /RELATIONSHIP_CHANGED/);
      assert.deepEqual(await ownerSnapshot(), before);
      assert.equal((await db.query("SELECT id FROM federated_identities WHERE id=ANY($1::text[])", [[receipt.relationshipId, replacement]])).rows.length, 2);
    });
    it("compensation safety rejects a revoked exact primary proof after a previously clear review", async () => {
      const {cp, input} = await compensationVerified();
      await sessions.revoke(SessionId.from(targetSession));
      assert.ok((await management.previewCompensation(token(), cp.caseId)).blockers.includes("CONTROL_REVOKED"));
      const before = await ownerSnapshot();
      await assert.rejects(() => management.executeCompensation(token(), input), /CONTROL_REVOKED/);
      assert.deepEqual(await ownerSnapshot(), before);
    });
    it("compensation safety expires a stored verified proof even while the owner session remains active", async () => {
      const {cp, input} = await compensationVerified();
      await db.query("UPDATE identity_recovery_compensations SET proof_expires_at=now()-interval '1 second' WHERE id=$1", [cp.caseId]);
      assert.equal((await sessions.findById(SessionId.from(targetSession)))?.status, "active");
      assert.ok((await management.previewCompensation(token(), cp.caseId)).blockers.includes("FRESH_CONTROL_REQUIRED"));
      const before = await ownerSnapshot();
      await assert.rejects(() => management.executeCompensation(token(), input), /FRESH_CONTROL_REQUIRED/);
      assert.deepEqual(await ownerSnapshot(), before);
    });
    it("compensation safety invalidates a saved review when the primary gains another credential", async () => {
      const {cp, input} = await compensationVerified();
      await db.query("INSERT INTO credentials(id,human_identity_id,normalized_email,password_hash,status,created_at,updated_at) SELECT $1,$2,'additional-primary-control@synthetic.example',password_hash,'active',now(),now() FROM credentials WHERE human_identity_id=$2 LIMIT 1", [randomUUID(), target]);
      const preview = await management.previewCompensation(token(), cp.caseId);
      assert.deepEqual(preview.blockers, []);
      assert.notEqual(preview.reviewDigest, input.reviewDigest);
      const before = await ownerSnapshot();
      await assert.rejects(() => management.executeCompensation(token(), input), /Evidence changed/);
      assert.deepEqual(await ownerSnapshot(), before);
    });
    it("compensation safety waits for a coordinated central dependency writer then rejects its committed new reference", async () => {
      const {input} = await compensationVerified();
      let ready!: () => void, release!: () => void;
      const written = new Promise<void>(resolve => { ready = resolve; });
      const barrier = new Promise<void>(resolve => { release = resolve; });
      // Actual authenticated report method participates in the shared central
      // transaction fence. The exclusive compensation must see its commit.
      const writer = db.withTransaction(async () => {
        await report(source, {...zero, pendingOperations: 1});
        ready(); await barrier;
      });
      await written;
      let finished = false;
      const execution = management.executeCompensation(token(), input).then(
        value => { finished = true; return {value}; },
        error => { finished = true; return {error}; },
      );
      try {
        await new Promise(resolve => setTimeout(resolve, 25));
        assert.equal(finished, false);
      } finally { release(); }
      await writer;
      const result = await execution;
      assert.ok("error" in result);
      assert.match(String(result.error), /SOURCE_DEPENDENCIES_PRESENT/);
      assert.equal((await federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(target), FederatedIdentityProvider.from("google")))?.humanIdentityId.value, target);
      assert.equal((await sessions.findById(SessionId.from(targetSession)))?.status, "active");
      assert.equal((await db.query("SELECT id FROM platform_audit_events WHERE event_type='recovery.google.compensated'")).rows.length, 0);
      assert.equal((await db.query("SELECT id FROM identity_management_operations WHERE id=$1", [input.requestId])).rows.length, 0);
    });
    it("compensation audit failure rolls back provider, sessions, case and receipt atomically",async()=>{
      const {cp,input}=await compensationVerified();
      const before=(await db.query('SELECT id,human_identity_id,status,write_revision FROM federated_identities ORDER BY id')).rows;
      await db.query("CREATE FUNCTION v22_fail_compensation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='recovery.google.compensated' THEN RAISE EXCEPTION 'synthetic compensation audit failure'; END IF; RETURN NEW; END $$");
      await db.query('CREATE TRIGGER v22_fail_compensation_audit BEFORE INSERT ON platform_audit_events FOR EACH ROW EXECUTE FUNCTION v22_fail_compensation_audit()');
      try {await assert.rejects(()=>management.executeCompensation(token(),input),/synthetic compensation audit failure/);
        assert.deepEqual((await db.query('SELECT id,human_identity_id,status,write_revision FROM federated_identities ORDER BY id')).rows,before);
        assert.equal((await sessions.findById(SessionId.from(targetSession)))?.status,'active');
        assert.equal((await db.query('SELECT state FROM identity_recovery_compensations WHERE id=$1',[cp.caseId])).rows[0]!.state,'verified');
        assert.equal((await db.query('SELECT 1 FROM identity_management_operations WHERE id=$1',[input.requestId])).rows.length,0);
      }finally{await db.query('DROP TRIGGER v22_fail_compensation_audit ON platform_audit_events');await db.query('DROP FUNCTION v22_fail_compensation_audit()');}
      assert.equal((await management.executeCompensation(token(),input)).state,'completed');
    });
    it("attributes trusted new sessions and preserves method and freshness on renewal; compensation rejects Google-only primary proof",async()=>{
      assert.equal((await sessions.findById(SessionId.from(targetSession)))?.authenticationMethod,'email_password');
      assert.equal((await sessions.findById(SessionId.from(sourceSession)))?.authenticationMethod,'google');
      const renewed=await runtime.services.renewSession.execute(sourceRenewalToken);
      const r=await sessions.findById(SessionId.from(renewed.sessionId));assert.equal(r?.authenticationMethod,'google');
      assert.equal(r?.authenticatedAt.toISOString(),(await sessions.findById(SessionId.from(sourceSession)))?.authenticatedAt.toISOString());
      const c=await verified(),receipt=await management.executeRecovery(token(),await execution(c.caseId)),cp=await management.prepareCompensation(token(),String(receipt.requestId));
      const google=await signGoogle();
      await assert.rejects(async()=>management.proveCompensation(token(),{caseId:cp.caseId,targetSession:google.session.sessionId,identityToken:await jwt(cp.nonce)}),/separately from Google/);
      assert.equal((await db.query('SELECT state FROM identity_recovery_compensations WHERE id=$1',[cp.caseId])).rows[0]!.state,'awaiting_proof');
    });
    it("native and compensation control reject mismatched subjects, replay, ordinary users and expiry",async()=>{
      const c=await management.prepareRecovery(token(),source,target);
      const t=await runtime.services.login.execute({email:'target@synthetic.example',password});targetSession=t.sessionId;
      await assert.rejects(()=>management.proveNativeRecovery(SessionId.from(targetSession),{caseId:c.caseId,targetSession,identityToken:'invalid'}));
      await assert.rejects(async()=>management.proveNativeRecovery(token(),{caseId:c.caseId,targetSession,identityToken:await jwt(c.nonce,'different-subject')}),/does not belong/);
      const credential=await jwt(c.nonce);await management.proveNativeRecovery(token(),{caseId:c.caseId,targetSession,identityToken:credential});
      await assert.rejects(()=>management.proveNativeRecovery(token(),{caseId:c.caseId,targetSession,identityToken:credential}),/new recovery verification/);
      const receipt=await management.executeRecovery(token(),await execution(c.caseId));
      const cp=await management.prepareCompensation(token(),String(receipt.requestId));
      const current=await runtime.services.login.execute({email:'target@synthetic.example',password});targetSession=current.sessionId;
      await assert.rejects(async()=>management.proveCompensation(token(),{caseId:cp.caseId,targetSession,identityToken:await jwt(cp.nonce,'different-subject')}),/no longer matches/);
      await db.query("UPDATE identity_recovery_compensations SET expires_at=now()-interval '1 second' WHERE id=$1",[cp.caseId]);
      await assert.rejects(async()=>management.proveCompensation(token(),{caseId:cp.caseId,targetSession,identityToken:await jwt(cp.nonce)}),/new compensation verification/);
      assert.equal((await federated.findActiveByHumanIdentityAndProvider(HumanIdentityId.from(target),FederatedIdentityProvider.from('google')))?.id.value,receipt.relationshipId);
    });
    it("concurrent compensation commits once and rejects the competing exact-case operation",async()=>{
      const {input}=await compensationVerified();
      const results=await Promise.allSettled([management.executeCompensation(token(),input),management.executeCompensation(token(),{...input,requestId:randomUUID()})]);
      assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
      assert.equal((await db.query("SELECT count(*)::int n FROM platform_audit_events WHERE event_type='recovery.google.compensated'")).rows[0]!.n,1);
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
        paths.push(
          ['recovery/native-prove',{caseId:randomUUID(),targetSession,identityToken:'invalid'}],
          ['recovery/prove',{caseId:randomUUID(),sourceSession,targetSession,identityToken:'invalid'}],
          ['recovery/execute',{caseId:randomUUID(),requestId:randomUUID(),reviewDigest:'0'.repeat(64),confirmation:'no',revokeSourceSessions:true,acceptSourceLossOfAccess:true}],
          ['recovery/compensation/prepare',{originalRequestId:randomUUID()}],
          ['recovery/compensation/prove',{caseId:randomUUID(),targetSession,identityToken:'invalid'}],
          ['recovery/compensation/execute',{caseId:randomUUID(),requestId:randomUUID(),reviewDigest:'0'.repeat(64),confirmation:'no',revokeTargetSessions:true,acceptFreshSignIn:true}],
          ['bulk/execute',{items:[{humanIdentityId:source,action:'suspend',reviewDigest:'0'.repeat(64),requestId:randomUUID(),confirmation:`suspend ${source}`,revokeSessions:true}],confirmation:'review 1 identities'}],
          ['dependencies/inspector',{productId:'synthetic-product',workloadId:'synthetic-workload'}]
        );
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
