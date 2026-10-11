import assert from 'node:assert/strict';
import {before,after,beforeEach,describe,it} from 'node:test';
import {randomUUID} from 'node:crypto';
import {generateKeyPair,SignJWT} from 'jose';
import {buildRuntime,type ApplicationRuntime} from '../../src/api/services.js';
import {buildApp} from '../../src/api/app.js';
import {loadConfig} from '../../src/config/env.js';
import {PostgresDatabase} from '../../src/infrastructure/postgres/database.js';
import {PostgresControlPlaneRepository} from '../../src/infrastructure/postgres/postgres-control-plane-repository.js';
import {PostgresControlCentreRepository} from '../../src/infrastructure/postgres/postgres-control-centre-repository.js';
import {PostgresHumanIdentityRepository} from '../../src/infrastructure/postgres/postgres-human-identity-repository.js';
import {PostgresSessionRepository} from '../../src/infrastructure/postgres/postgres-session-repository.js';
import {PostgresFederatedIdentityRepository,PostgresFederatedAuthenticationNonceRepository} from '../../src/infrastructure/postgres/postgres-federated-identity-repository.js';
import {AdministrationPrincipals} from '../../src/control-plane/application/administration-principals.js';
import {IdentityManagement,syntheticManagementEnabled} from '../../src/control-plane/application/identity-management.js';
import {GoogleRecoveryHandoff,googleRecoveryHandoffConfigSchema} from '../../src/control-plane/application/google-recovery-handoff.js';
import {GoogleIdentityTokenVerifier} from '../../src/authentication/federated/adapters/google-identity-token-verifier.js';
import {FederatedIdentityTokenVerifiers} from '../../src/authentication/federated/application/token-verifier.js';
import {SessionId} from '../../src/sessions/domain/session-id.js';
import {SystemClock} from '../../src/shared/clock.js';
import type {FastifyInstance} from 'fastify';
const url=process.env.POSTGRES_HANDOFF_TEST_DATABASE_URL,password='Synthetic-Handoff-123!';
const config={clientId:'synthetic-recovery-client',clientSecret:'synthetic-recovery-secret',redirectUri:'https://identity.example.test/authentication/recovery/google/callback'};
describe('Google recovery callback configuration',()=>{
 it('requires dedicated HTTPS callback without arbitrary paths or fragments',()=>{
  assert.ok(googleRecoveryHandoffConfigSchema.safeParse(config).success);
  for(const redirectUri of ['http://identity.example.test/authentication/recovery/google/callback','https://identity.example.test/api/auth/google/callback',config.redirectUri+'?redirect=evil',config.redirectUri+'#secret'])assert.equal(googleRecoveryHandoffConfigSchema.safeParse({...config,redirectUri}).success,false);
 });
});
describe('Native Google ownership handoff real PG orchestration with signed test-provider proof',{skip:!url},()=>{
 let runtime:ApplicationRuntime,db:PostgresDatabase,plane:PostgresControlPlaneRepository,management:IdentityManagement,handoff:GoogleRecoveryHandoff,app:FastifyInstance;
 let admin:string,target:string,source:string,adminSession:string,key:Awaited<ReturnType<typeof generateKeyPair>>,expectedNonce='',subject='synthetic-google-source',exchanges=0,failFinalAudit=false;
 before(async()=>{
  assert.ok(syntheticManagementEnabled({NODE_ENV:'test',REPOSITORY_MODE:'postgres',DATABASE_URL:url!}));
  runtime=await buildRuntime(loadConfig({NODE_ENV:'test',REPOSITORY_MODE:'postgres',DATABASE_URL:url!,LOG_LEVEL:'silent',PASSWORD_HASH_MEMORY_KIB:'8192',PASSWORD_HASH_ITERATIONS:'2'}));
  db=new PostgresDatabase(url!,false,()=>{},true);plane=new PostgresControlPlaneRepository(db);
  const humans=new PostgresHumanIdentityRepository(db),sessions=new PostgresSessionRepository(db),principals=new AdministrationPrincipals(plane,humans,runtime.controlPlane),clock=new SystemClock();
  key=await generateKeyPair('RS256');
  management=new IdentityManagement(db,new PostgresControlCentreRepository(db),principals,plane,humans,sessions,new PostgresFederatedIdentityRepository(db),new PostgresFederatedAuthenticationNonceRepository(db),new FederatedIdentityTokenVerifiers([new GoogleIdentityTokenVerifier({clientIds:[config.clientId],keyResolver:async()=>key.publicKey})]),clock,true,runtime.controlPlane);
  const request:typeof fetch=async(_url,options)=>{
   exchanges++; assert.equal(String(_url),'https://oauth2.googleapis.com/token');
   const body=options?.body as URLSearchParams;assert.equal(body.get('client_id'),config.clientId);assert.equal(body.get('code'),'one-time-code');assert.match(body.get('code_verifier')??'',/^[A-Za-z0-9_-]{43}$/);
   const identityToken=await new SignJWT({nonce:expectedNonce}).setProtectedHeader({alg:'RS256'}).setIssuer('https://accounts.google.com').setAudience(config.clientId).setSubject(subject).setIssuedAt().setExpirationTime('5m').sign(key.privateKey);
   return new Response(JSON.stringify({id_token:identityToken}),{status:200,headers:{'content-type':'application/json'}});
  };
  handoff=new GoogleRecoveryHandoff(db,management,sessions,humans,principals,plane,clock,config,request);
  const append=plane.appendAudit.bind(plane);plane.appendAudit=async event=>{if(failFinalAudit&&event.eventType==='recovery.google-handoff.verified'){failFinalAudit=false;throw new Error('Synthetic audit outage');}await append(event);};
  app=buildApp({...runtime.services,administration:{...runtime.services.administration,identityManagement:management,googleRecoveryHandoff:handoff}},runtime.databaseHealth);
 });
 beforeEach(async()=>{
  await db.query('TRUNCATE human_identities,registered_products,tenants,platform_audit_events,federated_authentication_nonces CASCADE');
  const a=await runtime.services.register.execute({email:'admin@handoff.test',password});admin=a.humanIdentityId;adminSession=a.session.sessionId;await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin,'handoff-test');
  target=(await runtime.services.register.execute({email:'primary@handoff.test',password})).humanIdentityId;
  source=randomUUID();await db.query("INSERT INTO human_identities(id,status,created_at,updated_at)VALUES($1,'active',now(),now())",[source]);
  await db.query("INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,status,created_at,updated_at)VALUES($1,$2,'google','synthetic-google-source','active',now(),now())",[randomUUID(),source]);
  exchanges=0;subject='synthetic-google-source';failFinalAudit=false;
 });
 after(async()=>{await app?.close();await db?.close();await runtime?.close();});
 const start=async()=>{
  const c=await management.prepareRecovery(SessionId.from(adminSession),source,target);
  const owner=await runtime.services.login.execute({email:'primary@handoff.test',password});
  const r=await app.inject({method:'POST',url:'/administration/platform/identity-management/recovery/google/start',headers:{authorization:`Bearer ${adminSession}`},payload:{caseId:c.caseId,targetSession:owner.sessionId}});
  assert.equal(r.statusCode,200);const h=r.json(),oauth=new URL(h.authorizationURL);expectedNonce=c.nonce;
  assert.equal(oauth.searchParams.get('nonce'),c.nonce);assert.equal(oauth.searchParams.get('code_challenge_method'),'S256');assert.equal(oauth.searchParams.get('scope'),'openid email');
  return {...h,state:oauth.searchParams.get('state')!,caseId:c.caseId};
 };
 it('verifies fresh primary and exact source Google proof without creating a source session or exposing tokens',async()=>{
  const h=await start(),count=await db.query('SELECT id FROM sessions WHERE human_identity_id=$1',[source]);
  const r=await app.inject({method:'GET',url:`/authentication/recovery/google/callback?state=${h.state}&code=one-time-code`});
  assert.equal(r.statusCode,302);assert.equal(r.headers.location,`gamaconsole://recovery?handoffId=${h.handoffId}&status=verified`);assert.equal(exchanges,1);
  const result=await handoff.result(SessionId.from(adminSession),h.handoffId);assert.equal(result.state,'verified');
  assert.equal((await db.query('SELECT id FROM sessions WHERE human_identity_id=$1',[source])).rows.length,count.rows.length);
  const row=(await db.query('SELECT * FROM identity_management_google_handoffs')).rows[0]!;assert.equal(row.code_verifier,null);assert.ok(!JSON.stringify(row).includes(adminSession));assert.ok(!JSON.stringify(row).includes('synthetic-google-source'));
 });
 it('rejects unknown callback state and consumes a valid state only once',async()=>{
  const h=await start();await assert.rejects(()=>handoff.callback({state:'A'.repeat(43),code:'one-time-code'}));assert.equal(exchanges,0);
  await handoff.callback({state:h.state,code:'one-time-code'});await assert.rejects(()=>handoff.callback({state:h.state,code:'one-time-code'}));assert.equal(exchanges,1);
 });
 it('restarts verification with exact scoped metadata supersession and rejects the prior browser callback',async()=>{
  const previous=await start(),replacement=await start();
  assert.equal((await handoff.result(SessionId.from(adminSession),previous.handoffId)).state,'cancelled');
  assert.equal((await db.query('SELECT state,code_verifier FROM identity_management_google_handoffs WHERE id=$1',[previous.handoffId])).rows[0]!.code_verifier,null);
  await assert.rejects(()=>handoff.callback({state:previous.state,code:'one-time-code'}));assert.equal(exchanges,0);
  assert.equal((await handoff.callback({state:replacement.state,code:'one-time-code'})).state,'verified');
  // This fixture deliberately has no authoritative product inspector; retry must
  // clear the old request dependency while retaining the unrelated coverage guard.
  assert.deepEqual((await management.previewRecovery(SessionId.from(adminSession),replacement.caseId)).blockers,['SOURCE_DEPENDENCIES_UNKNOWN']);
  assert.equal((await db.query('SELECT state FROM identity_management_cases WHERE id=$1',[previous.caseId])).rows[0]!.state,'cancelled');
  assert.equal(exchanges,1);
 });
 it('does not accept a different provider subject or turn failure into a verified case',async()=>{
  const h=await start();subject='another-google-owner';const result=await handoff.callback({state:h.state,code:'one-time-code'});assert.equal(result.state,'failed');assert.equal((await db.query('SELECT state FROM identity_management_cases WHERE id=$1',[h.caseId])).rows[0]!.state,'awaiting_proof');
 });
 it('handles user cancellation with one-use state and no token exchange',async()=>{const h=await start();assert.equal((await handoff.callback({state:h.state,error:'access_denied'})).state,'failed');assert.equal(exchanges,0);});
 it('uses the same legitimate browser orchestration for receipt-bound compensation without replaying original proof',async()=>{
  const h=await start();await handoff.callback({state:h.state,code:'one-time-code'});
  await plane.saveProduct({id:'handoff-test-product',displayName:'Synthetic dependency coverage',status:'active'});
  const {Argon2PasswordOperations}=await import('../../src/authentication/adapters/argon2-password-operations.js');const hash=await new Argon2PasswordOperations({memoryCost:1024,timeCost:1,parallelism:1}).hash('Synthetic-product-secret!');
  await plane.saveWorkload({id:'handoff-test-workload',productId:'handoff-test-product',status:'active',secretHash:hash.value});
  await management.registerInspector(SessionId.from(adminSession),'handoff-test-product','handoff-test-workload');
  for(const humanIdentityId of [source,target])await management.reportDependencies('handoff-test-workload','Synthetic-product-secret!',{humanIdentityId,counts:{localAccounts:0,subscriptions:0,permissions:0,ownership:0,backgroundJobs:0,pendingOperations:0,externalReferences:0,retention:0},evidenceReference:'synthetic-clear',observedAt:new Date().toISOString()});
  const preview=await management.previewRecovery(SessionId.from(adminSession),h.caseId);assert.deepEqual(preview.blockers,[]);
  const receipt=await management.executeRecovery(SessionId.from(adminSession),{caseId:h.caseId,requestId:randomUUID(),reviewDigest:preview.reviewDigest,confirmation:`transfer google ${source} to ${target}`,revokeSourceSessions:true,acceptSourceLossOfAccess:true}) as {requestId:string};
  const c=await management.prepareCompensation(SessionId.from(adminSession),receipt.requestId),owner=await runtime.services.login.execute({email:'primary@handoff.test',password});
  const browser=await handoff.start(SessionId.from(adminSession),{caseId:c.caseId,targetSession:owner.sessionId,kind:'compensation'});expectedNonce=c.nonce;
  const state=new URL(browser.authorizationURL).searchParams.get('state')!;
  assert.equal((await handoff.callback({state,code:'one-time-code'})).state,'verified');
  assert.equal((await handoff.result(SessionId.from(adminSession),browser.handoffId)).caseId,c.caseId);
  assert.equal((await db.query('SELECT state FROM identity_recovery_compensations WHERE id=$1',[c.caseId])).rows[0]!.state,'verified');
  assert.equal(exchanges,2);
 });
 it('blocks primary mismatch and missing/forged administrator credentials',async()=>{
  const c=await management.prepareRecovery(SessionId.from(adminSession),source,target);
  const mismatch=await handoff.start(SessionId.from(adminSession),{caseId:c.caseId,targetSession:adminSession}).then(()=>null,e=>e);assert.equal(mismatch.code,'CONTROL_INVALID');
  for(const headers of [{},{authorization:'Bearer forged'}]){const r=await app.inject({method:'POST',url:'/administration/platform/identity-management/recovery/google/start',headers,payload:{caseId:c.caseId,targetSession:adminSession}});assert.ok([401,403].includes(r.statusCode));}
 });
 it('reconciles a committed proof after final handoff audit persistence failed',async()=>{
  const h=await start();failFinalAudit=true;await assert.rejects(()=>handoff.callback({state:h.state,code:'one-time-code'}));
  assert.equal((await db.query('SELECT state FROM identity_management_google_handoffs')).rows[0]!.state,'processing');assert.equal((await db.query('SELECT state FROM identity_management_cases WHERE id=$1',[h.caseId])).rows[0]!.state,'verified');
  assert.equal((await handoff.result(SessionId.from(adminSession),h.handoffId)).state,'verified');assert.equal(exchanges,1);assert.equal((await db.query("SELECT id FROM platform_audit_events WHERE event_type='recovery.google-handoff.reconciled'")).rows.length,1);
 });
 it('expires interrupted processing without inventing proof or retrying an authorization code',async()=>{
  const h=await start();await db.query("UPDATE identity_management_google_handoffs SET state='processing',code_verifier=NULL,created_at=now()-interval '10 minutes',expires_at=now()-interval '5 minutes' WHERE id=$1",[h.handoffId]);
  assert.equal((await handoff.result(SessionId.from(adminSession),h.handoffId)).state,'failed');assert.equal(exchanges,0);
 });
 it('expires an unused callback transactionally, clears its PKCE verifier and prevents token exchange',async()=>{
  const h=await start();
  await db.query("UPDATE identity_management_google_handoffs SET created_at=now()-interval '10 minutes',expires_at=now()-interval '5 minutes' WHERE id=$1",[h.handoffId]);
  assert.equal((await handoff.result(SessionId.from(adminSession),h.handoffId)).state,'failed');
  const row=(await db.query('SELECT state,code_verifier FROM identity_management_google_handoffs WHERE id=$1',[h.handoffId])).rows[0]!;
  assert.equal(row.state,'failed');assert.equal(row.code_verifier,null);
  await assert.rejects(()=>handoff.callback({state:h.state,code:'one-time-code'}));assert.equal(exchanges,0);
  assert.equal((await handoff.result(SessionId.from(adminSession),h.handoffId)).state,'failed');
  assert.equal((await db.query("SELECT id FROM platform_audit_events WHERE event_type='recovery.google-handoff.expired' AND subject_reference=$1",[h.handoffId])).rows.length,1);
 });
 it('keeps production disabled even with an otherwise configured callback',async()=>{
  const managementProduction=Object.create(management) as IdentityManagement;Object.defineProperty(managementProduction,'executionEnabled',{value:false});
  const humans=new PostgresHumanIdentityRepository(db),sessions=new PostgresSessionRepository(db),principals=new AdministrationPrincipals(plane,humans,runtime.controlPlane);
  const closed=new GoogleRecoveryHandoff(db,managementProduction,sessions,humans,principals,plane,new SystemClock(),config);
  await assert.rejects(()=>closed.start(SessionId.from(adminSession),{caseId:randomUUID(),targetSession:adminSession}),e=>(e as any).code==='IDENTITY_MANAGEMENT_DISABLED');
  await assert.rejects(()=>closed.result(SessionId.from(adminSession),randomUUID()),e=>(e as any).code==='IDENTITY_MANAGEMENT_DISABLED');
 });
 it('reports the dedicated callback setup as a specific blocker when absent',async()=>{
  const humans=new PostgresHumanIdentityRepository(db),sessions=new PostgresSessionRepository(db),principals=new AdministrationPrincipals(plane,humans,runtime.controlPlane);
  const missing=new GoogleRecoveryHandoff(db,management,sessions,humans,principals,plane,new SystemClock(),undefined);
  await assert.rejects(()=>missing.start(SessionId.from(adminSession),{caseId:randomUUID(),targetSession:adminSession}),e=>(e as any).code==='GOOGLE_HANDOFF_NOT_CONFIGURED');
 });
});
