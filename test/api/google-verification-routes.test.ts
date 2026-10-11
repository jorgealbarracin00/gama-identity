import { scope } from "../operational/google-verification-scope.js";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildApp } from "../../src/api/app.js";
import { buildTestServices, CredentialIds, FederatedIdentityIds, RenewalTokens, SessionIds } from "../operational/test-doubles.js";
import { HumanIdentity } from "../../src/identity/domain/human-identity.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { EmailCredential } from "../../src/authentication/credentials/domain/email-credential.js";
import { NormalizedEmail } from "../../src/authentication/credentials/domain/email.js";
import { PasswordHash } from "../../src/authentication/credentials/domain/password.js";
import { FederatedIdentity, FederatedIdentityProvider, FederatedProviderSubject } from "../../src/authentication/federated/domain/federated-identity.js";
import { FederatedIdentityTokenVerifiers } from "../../src/authentication/federated/application/token-verifier.js";
import { ManageFederatedAuthenticationMethods } from "../../src/authentication/federated/application/manage-federated-authentication-methods.js";
import { LinkGoogleWeb } from "../../src/authentication/federated/application/link-google-web.js";
import { CreateSession } from "../../src/sessions/application/use-cases.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { Session } from "../../src/sessions/domain/session.js";
import { AdministrationPrincipals } from "../../src/control-plane/application/administration-principals.js";
import { GoogleRecoveryVerification } from "../../src/control-plane/application/google-recovery-verification.js";
import { MemoryGoogleVerificationStore } from "../../src/control-plane/adapters/memory-google-verification-store.js";
import { SerialExecutor } from "../../src/shared/serial-executor.js";

const path = "/administration/platform/google-recovery";
export async function verificationFixture() {
  const f = buildTestServices();
  const serial = new SerialExecutor();
  const atomic = <T>(work: () => Promise<T>) => serial.execute(work);
  for (const id of [scope.source,scope.target]) await f.identities.save(HumanIdentity.create({ next: () => HumanIdentityId.from(id) }, f.clock));
  const credential = EmailCredential.create(new CredentialIds(), HumanIdentityId.from(scope.target), NormalizedEmail.from("primary@example.test"), PasswordHash.from("synthetic-hash"), f.clock);
  await f.credentials.save(credential);
  const ids = new FederatedIdentityIds();
  for (const [human, provider, subject] of [[scope.target,"apple","private-apple-subject"],[scope.source,"google","private-google-subject"]]) {
    await f.federatedIdentities.save(FederatedIdentity.create(ids,HumanIdentityId.from(human!),FederatedIdentityProvider.from(provider!),FederatedProviderSubject.from(subject!), {email:"same@example.test",emailVerified:true,emailPrivate:null},f.clock));
  }
  await f.controlPlaneRepository.savePlatformAdministrationMembership({ humanIdentityId:scope.target,platformRole:"administrator",status:"active",createdAt:f.clock.now(),updatedAt:f.clock.now() });
  const createSession = new CreateSession(f.sessions,new SessionIds(),f.clock,3600,new RenewalTokens(),86_400);
  const primarySession = await createSession.execute(HumanIdentityId.from(scope.target));
  const store = new MemoryGoogleVerificationStore();
  const verification = new GoogleRecoveryVerification(scope, new AdministrationPrincipals(f.controlPlaneRepository,f.identities,f.services.controlPlane),f.identities,f.credentials,f.federatedIdentities,f.sessions,f.federatedNonces,f.controlPlaneRepository,store,f.clock,atomic);
  f.googleVerifier.accept("private-google-token",{subject:"private-google-subject",email:"different@example.test"});
  const methods = new ManageFederatedAuthenticationMethods(new FederatedIdentityTokenVerifiers([f.googleVerifier]),f.federatedIdentities,f.federatedNonces,f.identities,f.credentials,f.sessions,f.controlPlaneRepository,ids,f.clock,atomic,{allowedPrincipalIds:new Set([scope.target]),allowReconciliation:false},verification);
  const app = buildApp({...f.services,administration:{...f.services.administration,googleVerification:verification},webAuthenticationApps:new Map([[scope.appId,{googleLink:new LinkGoogleWeb({exchange:async()=>"private-google-token"},methods)}]])});
  const headers = {authorization:`Bearer ${primarySession.sessionId}`};
  const post = (payload:object, customHeaders:Record<string,string>=headers) => app.inject({method:"POST",url:path,headers:customHeaders,payload});
  let nonce = 0;
  const link = () => app.inject({method:"POST",url:"/authentication/federated/google/web/link",headers,payload:{appId:scope.appId,authorizationCode:"private-code",codeVerifier:"x".repeat(43),nonce:`private-observation-nonce-at-least-32-${++nonce}`}});
  return {...f,app,store,verification,post,link,primarySession,createSession,credential};
}

describe("scoped Google verification production boundary", () => {
  it("records exact verified source ownership and both control proofs without changing accounts or sessions",async()=>{
    const f=await verificationFixture(); try {
      const before={human:(await f.identities.findById(HumanIdentityId.from(scope.source)))!.snapshot(),methods:(await f.federatedIdentities.listByHumanIdentityId(HumanIdentityId.from(scope.source))).map(m=>m.snapshot()),session:(await f.sessions.findById(SessionId.from(f.primarySession.sessionId)))!.snapshot()};
      assert.equal((await f.post({mode:"prepare"})).statusCode,200);
      const conflict=await f.link(); assert.equal(conflict.statusCode,409);assert.equal(conflict.json().error.code,"FEDERATED_IDENTITY_LINK_CONFLICT");
      const inspect=await f.post({mode:"inspect"}); assert.equal(inspect.statusCode,200);assert.equal(inspect.headers["cache-control"],"no-store");
      assert.equal(inspect.json().controlsVerified,true);assert.equal(inspect.json().observation.matched,true);assert.equal(inspect.json().productionRecoveryEnabled,false);assert.equal(inspect.json().historicalConflictSubjectConfirmed,false);
      assert.deepEqual((await f.identities.findById(HumanIdentityId.from(scope.source)))!.snapshot(),before.human);
      assert.deepEqual((await f.federatedIdentities.listByHumanIdentityId(HumanIdentityId.from(scope.source))).map(m=>m.snapshot()),before.methods);
      assert.deepEqual((await f.sessions.findById(SessionId.from(f.primarySession.sessionId)))!.snapshot(),before.session);
      assert.equal((await f.sessions.listByHumanIdentityId(HumanIdentityId.from(scope.source))).length,0);
      assert.ok(inspect.json().blockers.includes("EXTERNAL_PRODUCT_DEPENDENCIES_UNVERIFIED"));
      assert.doesNotMatch(inspect.body, /private-google|private-code|observation-nonce|providerSubject|renewalToken|passwordHash|synthetic-hash|sessionId/);
      const audit=JSON.stringify(f.controlPlaneRepository.auditEvents);assert.doesNotMatch(audit,/private-google|private-apple|private-code|same@example|synthetic-hash/);
    } finally {await f.app.close();}
  });
  it("never turns wrong/unknown Google subjects with matching email into links",async()=>{
    const f=await verificationFixture(); try {
      await f.post({mode:"prepare"});f.googleVerifier.accept("private-google-token",{subject:"unowned-other-subject",email:"same@example.test"});
      assert.equal((await f.link()).statusCode,409);const inspect=(await f.post({mode:"inspect"})).json();assert.equal(inspect.controlsVerified,false);assert.equal(inspect.observation.matched,false);assert.equal(inspect.observation.relationshipId,null);
      assert.equal(await f.federatedIdentities.findByProviderSubject(FederatedIdentityProvider.from("google"),FederatedProviderSubject.from("unowned-other-subject")),null);
    } finally {await f.app.close();}
  });
  it("does not disclose or mutate an unrelated Google account with the same email",async()=>{
    const f=await verificationFixture();try{
      const other=HumanIdentity.create({next:()=>HumanIdentityId.from("unrelated-human")},f.clock);await f.identities.save(other);
      const relationship=FederatedIdentity.create(new FederatedIdentityIds(),other.id,FederatedIdentityProvider.from("google"),FederatedProviderSubject.from("unrelated-private-subject"),{email:"same@example.test",emailVerified:true,emailPrivate:null},f.clock);
      // Avoid fixture relationship-ID collisions while keeping the real repository contract.
      const saved=FederatedIdentity.reconstitute({...relationship.snapshot(),id:(await import("../../src/authentication/federated/domain/federated-identity-id.js")).FederatedIdentityId.from("unrelated-relationship")});await f.federatedIdentities.save(saved);const before=saved.snapshot();
      await f.post({mode:"prepare"});f.googleVerifier.accept("private-google-token",{subject:"unrelated-private-subject",email:"same@example.test"});assert.equal((await f.link()).statusCode,409);
      const report=await f.post({mode:"inspect"});assert.equal(report.json().observation.matched,false);assert.equal(report.json().observation.relationshipId,null);assert.doesNotMatch(report.body,/unrelated-human|unrelated-private-subject|unrelated-relationship/);
      assert.deepEqual((await f.federatedIdentities.findByProviderSubject(FederatedIdentityProvider.from("google"),FederatedProviderSubject.from("unrelated-private-subject")))!.snapshot(),before);
    }finally{await f.app.close();}
  });
  for(const mode of ["inspect","prepare","approve","cancel"]) it(`denies missing session for ${mode}`,async()=>{
    const f=await verificationFixture();try {assert.equal((await f.post({mode,caseId:"a"},{ })).statusCode,401);}finally{await f.app.close();}
  });
  for(const change of ["revoked-session","revoked-admin","suspended-human","other-admin"] as const) it(`denies ${change}`,async()=>{
    const f=await verificationFixture();try {
      if(change==="revoked-session") await f.sessions.revoke(SessionId.from(f.primarySession.sessionId));
      if(change==="revoked-admin") await f.controlPlaneRepository.savePlatformAdministrationMembership({humanIdentityId:scope.target,platformRole:"administrator",status:"retired",createdAt:f.clock.now(),updatedAt:f.clock.now()});
      if(change==="suspended-human") {const human=(await f.identities.findById(HumanIdentityId.from(scope.target)))!;human.suspend(f.clock);await f.identities.save(human);}
      if(change==="other-admin") {const session=(await f.sessions.findById(SessionId.from(f.primarySession.sessionId)))!;await f.sessions.save(Session.reconstitute({...session.snapshot(),humanIdentityId:HumanIdentityId.from(scope.source)}));await f.controlPlaneRepository.savePlatformAdministrationMembership({humanIdentityId:scope.source,platformRole:"administrator",status:"active",createdAt:f.clock.now(),updatedAt:f.clock.now()});}
      assert.ok([401,403].includes((await f.post({mode:"inspect"})).statusCode));assert.equal(f.store.cases.length,0);
    }finally{await f.app.close();}
  });
  it("requires fresh authentication and rejects renewed old authentication",async()=>{
    const f=await verificationFixture();try {
      f.clock.set(new Date("2026-01-01T00:06:00Z"));assert.equal((await f.post({mode:"prepare"})).json().error.code,"RECOVERY_REAUTHENTICATION_REQUIRED");
      const renewed=await f.services.renewSession.execute(f.primarySession.renewalToken);const result=await f.post({mode:"prepare"},{authorization:`Bearer ${renewed.sessionId}`});assert.equal(result.statusCode,403);assert.equal(result.json().error.code,"RECOVERY_REAUTHENTICATION_REQUIRED");
    }finally{await f.app.close();}
  });
  it("inventories renewable expired-access sessions, tenant authority without entitlements, and other references",async()=>{
    const f=await verificationFixture();try {
      const session=await f.createSession.execute(HumanIdentityId.from(scope.source));const raw=(await f.sessions.findById(SessionId.from(session.sessionId)))!;
      await f.sessions.save(Session.reconstitute({...raw.snapshot(),expiresAt:new Date("2025-12-31T23:59:59Z")}));
      await f.controlPlaneRepository.saveMembership({tenantId:"tenant-with-no-product",humanIdentityId:scope.source,tenantRole:"owner",status:"active",createdAt:f.clock.now(),updatedAt:f.clock.now()});
      f.store.dependencies.set(scope.source,{provisioningReferences:1,emailChallenges:2,appleRevocationReferences:3});
      const result=(await f.post({mode:"inspect"})).json();assert.equal(result.source.sessions.activeAccess,0);assert.equal(result.source.sessions.renewalEligible,1);assert.equal(result.source.sessions.expiredAccess,1);assert.equal(result.source.productAssociations.length,0);assert.ok(result.source.tenantMemberships[0].capabilities.includes("ownership.manage"));assert.ok(result.blockers.includes("SOURCE_AUTHORITY_OR_PRODUCT_ASSOCIATION"));assert.ok(result.blockers.includes("SOURCE_OTHER_DEPENDENCIES"));assert.ok(result.blockers.includes("SOURCE_SESSIONS_REQUIRE_SEPARATE_APPROVAL"));
    }finally{await f.app.close();}
  });
  it("rejects injected scope/secrets and permanently denies production approval",async()=>{
    const f=await verificationFixture();try {
      for(const field of ["source","target","providerSubject","token","sql"]) assert.equal((await f.post({mode:"inspect",[field]:"injected"})).statusCode,400);
      const prepared=(await f.post({mode:"prepare"})).json();assert.equal((await f.post({mode:"approve",caseId:prepared.observation.id,reviewDigest:prepared.reviewDigest})).json().error.code,"RECOVERY_DISABLED");
      assert.equal(f.store.cases[0]!.state,"awaiting_proof");
    }finally{await f.app.close();}
  });
  it("cancels without touching account state, preserves receipts and re-arms explicitly",async()=>{
    const f=await verificationFixture();try {
      const first=(await f.post({mode:"prepare"})).json().observation;
      assert.equal((await f.post({mode:"cancel",caseId:"00000000-0000-0000-0000-000000000000"})).statusCode,409);
      assert.equal((await f.post({mode:"cancel",caseId:first.id})).statusCode,200);const next=(await f.post({mode:"prepare"})).json().observation;assert.notEqual(first.id,next.id);assert.equal(f.store.cases.length,2);
    }finally{await f.app.close();}
  });
  it("does not silently drop an expired case into ordinary linking",async()=>{
    const f=await verificationFixture();try {
      await f.post({mode:"prepare"});f.clock.set(new Date("2026-01-01T00:16:00Z"));const raw=(await f.sessions.findById(SessionId.from(f.primarySession.sessionId)))!;await f.sessions.save(Session.reconstitute({...raw.snapshot(),authenticatedAt:f.clock.now()}));
      f.googleVerifier.accept("private-google-token",{subject:"unowned-other-subject"});assert.equal((await f.link()).json().error.code,"RECOVERY_CASE_EXPIRED");assert.equal(f.store.cases[0]!.matched,null);
    }finally{await f.app.close();}
  });
  it("proof freshness expires and observation rechecks revoked administrator authority",async()=>{
    const f=await verificationFixture();try {
      await f.post({mode:"prepare"});assert.equal((await f.link()).statusCode,409);f.clock.set(new Date("2026-01-01T00:06:00Z"));assert.equal((await f.post({mode:"inspect"})).json().controlsVerified,false);
      await f.controlPlaneRepository.savePlatformAdministrationMembership({humanIdentityId:scope.target,platformRole:"administrator",status:"retired",createdAt:f.clock.now(),updatedAt:f.clock.now()});assert.equal((await f.link()).statusCode,403);
    }finally{await f.app.close();}
  });
});
