import assert from "node:assert/strict";
import { before, beforeEach, after, describe, it } from "node:test";
import { createHash } from "node:crypto";
import { PostgresDatabase } from "../../src/infrastructure/postgres/database.js";
import { buildRuntime, type ApplicationRuntime } from "../../src/api/services.js";
import { loadConfig } from "../../src/config/env.js";
import { buildApp } from "../../src/api/app.js";
import { runMigrations } from "../../src/infrastructure/postgres/migrations.js";
import { PostgresGoogleVerificationStore } from "../../src/infrastructure/postgres/postgres-google-verification-store.js";
import { scope } from "../operational/google-verification-scope.js";
import { FederatedIdentityProvider, FederatedProviderSubject } from "../../src/authentication/federated/domain/federated-identity.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { PostgresSessionRepository } from "../../src/infrastructure/postgres/postgres-session-repository.js";
import { CreateSession } from "../../src/sessions/application/use-cases.js";
import { UuidSessionIdGenerator } from "../../src/shared/identifiers.js";
import { SystemClock } from "../../src/shared/clock.js";
import { Session } from "../../src/sessions/domain/session.js";
import { TestOnlyScopedRecovery } from "../recovery/scoped-recovery-harness.js";

const url=process.env.POSTGRES_VERIFICATION_TEST_DATABASE_URL;
describe("PostgreSQL scoped verification and isolated recovery",{skip:!url,concurrency:false},()=>{
  let db:PostgresDatabase,runtime:ApplicationRuntime,sessionId:string,harness:TestOnlyScopedRecovery;
  const clock=new SystemClock();let nonce=0;
  const proof=(subject="test-secret-google-subject")=>({provider:FederatedIdentityProvider.from("google"),providerSubject:FederatedProviderSubject.from(subject),nonceHash:createHash("sha256").update(`nonce-${++nonce}`).digest("base64url"),expiresAt:new Date(Date.now()+300_000),metadata:{email:"fixture@example.test",emailVerified:true,emailPrivate:null}});
  const inspect=()=>runtime.services.administration.googleVerification!.administer(SessionId.from(sessionId),{mode:"inspect"});
  const prepare=()=>runtime.services.administration.googleVerification!.administer(SessionId.from(sessionId),{mode:"prepare"});
  const observe=(p=proof())=>runtime.services.administration.googleVerification!.observe(SessionId.from(sessionId),p);
  const owner=async()=>(await db.query("SELECT human_identity_id FROM federated_identities WHERE provider='google'")).rows[0]!.human_identity_id;
  before(async()=>{db=new PostgresDatabase(url!);await runMigrations(db);runtime=await buildRuntime(loadConfig({REPOSITORY_MODE:"postgres",DATABASE_URL:url!,LOG_LEVEL:"silent",IDENTITY_GOOGLE_VERIFICATION_SCOPE:JSON.stringify({source:scope.source,target:scope.target}),IDENTITY_DEFAULT_APP_ID:scope.appId,IDENTITY_TRUSTED_APPS:JSON.stringify([{id:scope.appId,displayName:"Fixture Preview",baseUrl:"https://fixture.example.test"}]),IDENTITY_WEB_APPS:JSON.stringify([{appId:scope.appId,purpose:"preview",allowedPrincipalIds:[scope.target],google:{clientId:"fixture-google-client",clientSecret:"fixture-google-secret",redirectUri:"https://fixture.example.test/api/auth/google/callback"}}])}));harness=new TestOnlyScopedRecovery(db,runtime,clock);await harness.install();});
  beforeEach(async()=>{
    await db.query(`TRUNCATE recovery_test_grants,google_identity_verification_cases,identity_security_attempts,email_action_challenges,federated_authentication_nonces,federated_identities,sessions,credentials,platform_audit_events,tenant_provisioning_requests,platform_administration_memberships,product_entitlements,product_participations,tenant_memberships,product_workloads,tenants,registered_products,human_identities CASCADE`);
    await db.query("INSERT INTO human_identities(id,status,created_at,updated_at) VALUES($1,'active',now(),now()),($2,'active',now(),now())",[scope.target,scope.source]);
    await db.query(`INSERT INTO credentials(id,human_identity_id,normalized_email,password_hash,status,created_at,updated_at,email_verified_at) VALUES('fixture-credential',$1,'fixture@example.test','fixture-secret-hash','active',now(),now(),now())`,[scope.target]);
    await db.query(`INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,status,created_at,updated_at) VALUES('fixture-apple',$1,'apple','test-secret-apple-subject','active',now(),now()),('fixture-google',$2,'google','test-secret-google-subject','active',now(),now())`,[scope.target,scope.source]);
    await db.query("INSERT INTO platform_administration_memberships(human_identity_id,platform_role,status,created_at,updated_at) VALUES($1,'administrator','active',now(),now())",[scope.target]);
    sessionId=(await new CreateSession(new PostgresSessionRepository(db),new UuidSessionIdGenerator(),clock,3600).execute(HumanIdentityId.from(scope.target))).sessionId;
  });
  after(async()=>{await runtime?.close();await db?.close();});
  it("authorizes/audits read-only inventory and persists proof across store instances",async()=>{
    const app=buildApp(runtime.services);try{
      const result=await app.inject({method:"POST",url:"/administration/platform/google-recovery",headers:{authorization:`Bearer ${sessionId}`},payload:{mode:"inspect"}});assert.equal(result.statusCode,200);assert.equal(result.headers["cache-control"],"no-store");assert.equal(result.json().source.extras.appleRevocationReferences,0);assert.doesNotMatch(result.body,/test-secret|fixture-secret|password_hash|provider_subject|renewal_token/);
      await prepare();assert.equal(await observe(),true);const report=await inspect();assert.equal(report.controlsVerified,true);assert.equal(report.productionRecoveryEnabled,false);assert.equal(await owner(),scope.source);
      const stored=await db.withTransaction(()=>new PostgresGoogleVerificationStore(db, scope).latestForUpdate());assert.equal(stored!.matched,true);
      const audits=await db.query("SELECT event_data FROM platform_audit_events");assert.doesNotMatch(JSON.stringify(audits.rows),/test-secret|fixture-secret|fixture@example/);
      assert.equal((await db.query("SELECT count(*) FROM sessions")).rows[0]!.count,"1");
    }finally{await app.close();}
  });
  it("rolls back observation/nonce on audit failure and retries safely",async()=>{
    await prepare();await db.query(`CREATE OR REPLACE FUNCTION fail_proof_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='platform.google-verification.proof-observed' THEN RAISE EXCEPTION 'synthetic audit outage'; END IF; RETURN NEW; END $$;CREATE TRIGGER fail_proof_audit BEFORE INSERT ON platform_audit_events FOR EACH ROW EXECUTE FUNCTION fail_proof_audit()`);
    const p=proof();try{await assert.rejects(observe(p));assert.equal((await inspect()).observation!.matched,null);assert.equal((await db.query("SELECT count(*) FROM federated_authentication_nonces")).rows[0]!.count,"0");assert.equal(await owner(),scope.source);}finally{await db.query("DROP TRIGGER fail_proof_audit ON platform_audit_events");}
    assert.equal(await observe(p),true);
  });
  it("serializes concurrent prepare and rejects one repeated proof",async()=>{
    const cases=await Promise.all([prepare(),prepare()]);assert.equal(cases[0]!.observation!.id,cases[1]!.observation!.id);const p=proof();const results=await Promise.allSettled([observe(p),observe(p)]);assert.equal(results.filter(r=>r.status==="fulfilled").length,1);assert.equal((await db.query("SELECT count(*) FROM google_identity_verification_cases")).rows[0]!.count,"1");assert.equal(await owner(),scope.source);
  });
  it("selects the newest observation even when wall-clock timestamps tie",async()=>{
    const first=await prepare();await runtime.services.administration.googleVerification!.administer(SessionId.from(sessionId),{mode:"cancel",caseId:first.observation!.id});const second=await prepare();
    await db.query("UPDATE google_identity_verification_cases SET created_at='2026-01-01T00:00:00Z'");
    assert.equal((await inspect()).observation!.id,second.observation!.id);assert.notEqual(first.observation!.id,second.observation!.id);
  });
  it("never reinterprets a prior pair's receipt after operator scope changes",async()=>{
    await prepare();await observe();const other=new PostgresGoogleVerificationStore(db,{...scope,source:"33333333-3333-4333-8333-333333333333"});assert.equal(await db.withTransaction(()=>other.latestForUpdate()),null);assert.equal((await inspect()).observation!.matched,true);
  });
  it("refuses production grants both in HTTP and ledger constraints",async()=>{
    const report=await prepare();await assert.rejects(runtime.services.administration.googleVerification!.administer(SessionId.from(sessionId),{mode:"approve",caseId:report.observation!.id}));await assert.rejects(db.query("UPDATE google_identity_verification_cases SET payload=jsonb_set(payload,'{state}','\"approved\"')"));assert.equal(await owner(),scope.source);
  });
  it("audits all extra service references and authority without entitlement guesses",async()=>{
    await db.query("INSERT INTO tenants(id,display_name,status) VALUES('extra-tenant','Test Tenant','active')");await db.query("INSERT INTO tenant_memberships(tenant_id,human_identity_id,tenant_role,status,created_at,updated_at) VALUES('extra-tenant',$1,'owner','suspended',now(),now())",[scope.source]);await db.query("INSERT INTO tenant_provisioning_requests(idempotency_key,tenant_id,display_name,initial_owner_human_identity_id,created_at) VALUES('00000000-0000-0000-0000-000000000099','extra-tenant','Test Tenant',$1,now())",[scope.source]);await db.query("INSERT INTO product_apple_revocations(operation_id,human_identity_id,client_id,encrypted_token) VALUES('00000000-0000-0000-0000-000000000001',$1,'test-client','test-secret-ciphertext')",[scope.source]);
    const report=await inspect();assert.equal(report.source.extras.provisioningReferences,1);assert.equal(report.source.extras.appleRevocationReferences,1);assert.equal(report.source.tenantMemberships[0]!.status,"suspended");assert.equal(report.source.productAssociations.length,0);assert.doesNotMatch(JSON.stringify(report),/ciphertext/);
  });
  it("requires explicit isolated approval and external dependency evidence",async()=>{
    await prepare();await observe();await assert.rejects(harness.grant(sessionId,"",true));await assert.rejects(harness.grant(sessionId,"synthetic-approval",false));assert.equal(await owner(),scope.source);
  });
  for(const fault of ["disconnect","sessions","audit"] as const) it(`isolated recovery rolls back ${fault} failure`,async()=>{
    const sourceSession=await new CreateSession(new PostgresSessionRepository(db),new UuidSessionIdGenerator(),clock,3600).execute(HumanIdentityId.from(scope.source));
    await prepare();await observe();const grant=await harness.grant(sessionId,"synthetic-approval",true);const p=proof();await assert.rejects(harness.execute(sessionId,p,grant,fault));
    assert.equal((await db.query("SELECT status FROM sessions WHERE id=$1",[sourceSession.sessionId])).rows[0]!.status,"active");assert.equal(await owner(),scope.source);assert.equal((await db.query("SELECT status FROM sessions WHERE id=$1",[sessionId])).rows[0]!.status,"active");assert.equal((await db.query("SELECT completed FROM recovery_test_grants WHERE id=$1",[grant])).rows[0]!.completed,false);assert.equal(await harness.execute(sessionId,p,grant),"completed");
  });
  it("isolated forward recovery preserves primary access and both Humans; reverse is separately approved and keeps history",async()=>{
    const sourceSession=await new CreateSession(new PostgresSessionRepository(db),new UuidSessionIdGenerator(),clock,3600).execute(HumanIdentityId.from(scope.source));
    await prepare();await observe();const grant=await harness.grant(sessionId,"synthetic-forward-approval",true);assert.equal(await harness.execute(sessionId,proof(),grant),"completed");assert.equal(await owner(),scope.target);assert.equal((await db.query("SELECT status FROM sessions WHERE id=$1",[sourceSession.sessionId])).rows[0]!.status,"revoked");assert.equal((await db.query("SELECT status FROM sessions WHERE id=$1",[sessionId])).rows[0]!.status,"active");assert.equal((await db.query("SELECT count(*) FROM human_identities WHERE status='active'")).rows[0]!.count,"2");assert.equal((await db.query("SELECT human_identity_id FROM credentials")).rows[0]!.human_identity_id,scope.target);
    const reverse=await harness.grant(sessionId,"synthetic-reverse-approval",true,grant);assert.equal(await harness.execute(sessionId,proof(),reverse),"completed");assert.equal(await owner(),scope.source);assert.equal((await db.query("SELECT status FROM sessions WHERE id=$1",[sessionId])).rows[0]!.status,"revoked");assert.equal((await db.query("SELECT count(*) FROM platform_audit_events WHERE event_type='authentication.google-recovery.completed'")).rows[0]!.count,"2");assert.equal((await db.query("SELECT status FROM credentials")).rows[0]!.status,"active");
  });
  it("isolated concurrency permits only one transfer and prevents stale session resurrection",async()=>{
    const sourceSession=await new CreateSession(new PostgresSessionRepository(db),new UuidSessionIdGenerator(),clock,3600).execute(HumanIdentityId.from(scope.source));const stale=(await new PostgresSessionRepository(db).findById(SessionId.from(sourceSession.sessionId)))!;
    await prepare();await observe();const grant=await harness.grant(sessionId,"synthetic-approval",true);const results=await Promise.all([harness.execute(sessionId,proof(),grant),harness.execute(sessionId,proof(),grant)]);assert.deepEqual(results.sort(),["already_completed","completed"]);await assert.rejects(harness.saveSessionWithoutResurrection(Session.reconstitute(stale.snapshot())));assert.equal((await db.query("SELECT status FROM sessions WHERE id=$1",[sourceSession.sessionId])).rows[0]!.status,"revoked");
  });
  it("isolated transfer rejects expired grants and future authentication times",async()=>{
    await prepare();await observe();const grant=await harness.grant(sessionId,"synthetic-approval",true);
    await db.query("UPDATE recovery_test_grants SET expires=now()-interval '1 second' WHERE id=$1",[grant]);await assert.rejects(harness.execute(sessionId,proof(),grant));
    await db.query("UPDATE recovery_test_grants SET expires=now()+interval '5 minutes' WHERE id=$1",[grant]);await db.query("UPDATE sessions SET authenticated_at=now()+interval '1 hour' WHERE id=$1",[sessionId]);await assert.rejects(harness.execute(sessionId,proof(),grant));assert.equal(await owner(),scope.source);
  });
  it("isolated transfer and cooperating legacy renewal race cannot leave a live duplicate session",async()=>{
    const sourceSession=await new CreateSession(new PostgresSessionRepository(db),new UuidSessionIdGenerator(),clock,3600).execute(HumanIdentityId.from(scope.source));await prepare();await observe();const grant=await harness.grant(sessionId,"synthetic-approval",true);
    const results=await Promise.allSettled([harness.execute(sessionId,proof(),grant),harness.fence(()=>runtime.services.renewSession.execute(sourceSession.renewalToken))]);
    if(results[0]!.status==="fulfilled") {assert.equal(await owner(),scope.target);assert.equal((await db.query("SELECT count(*) FROM sessions WHERE human_identity_id=$1 AND status<>'revoked'",[scope.source])).rows[0]!.count,"0");}
    else {assert.equal(await owner(),scope.source);assert.equal(results[1]!.status,"fulfilled");}
  });
  it("isolated transfer rejects wrong subject, caller and changed dependency review",async()=>{
    await prepare();await observe();const grant=await harness.grant(sessionId,"synthetic-approval",true);await assert.rejects(harness.execute(sessionId,proof("other-subject"),grant));await assert.rejects(harness.execute("not-a-session",proof(),grant));await db.query("INSERT INTO tenants(id,display_name,status) VALUES('changed-tenant','Changed','active')");await db.query("INSERT INTO tenant_memberships(tenant_id,human_identity_id,tenant_role,status,created_at,updated_at) VALUES('changed-tenant',$1,'staff','active',now(),now())",[scope.source]);await assert.rejects(harness.execute(sessionId,proof(),grant));assert.equal(await owner(),scope.source);
  });
});
