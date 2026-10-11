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
 let admin:string,target:string,source:string,adminSession:string,key:Awaited<ReturnType<typeof generateKeyPair>>,expectedNonce='',subject='synthetic-google-source',exchanges=0,failFinalAudit=false,failCleanupAudit=false,exchangeBarrier:Promise<void>|undefined;
 before(async()=>{
  assert.ok(syntheticManagementEnabled({NODE_ENV:'test',REPOSITORY_MODE:'postgres',DATABASE_URL:url!}));
  runtime=await buildRuntime(loadConfig({NODE_ENV:'test',REPOSITORY_MODE:'postgres',DATABASE_URL:url!,LOG_LEVEL:'silent',PASSWORD_HASH_MEMORY_KIB:'8192',PASSWORD_HASH_ITERATIONS:'2'}));
  db=new PostgresDatabase(url!,false,()=>{},true);plane=new PostgresControlPlaneRepository(db);
  const humans=new PostgresHumanIdentityRepository(db),sessions=new PostgresSessionRepository(db),principals=new AdministrationPrincipals(plane,humans,runtime.controlPlane),clock=new SystemClock();
  key=await generateKeyPair('RS256');
  management=new IdentityManagement(db,new PostgresControlCentreRepository(db),principals,plane,humans,sessions,new PostgresFederatedIdentityRepository(db),new PostgresFederatedAuthenticationNonceRepository(db),new FederatedIdentityTokenVerifiers([new GoogleIdentityTokenVerifier({clientIds:[config.clientId],maximumAuthenticationAgeSeconds:300,keyResolver:async()=>key.publicKey})]),clock,true,runtime.controlPlane);
  const request:typeof fetch=async(_url,options)=>{
   exchanges++; assert.equal(String(_url),'https://oauth2.googleapis.com/token');
   const body=options?.body as URLSearchParams;assert.equal(body.get('client_id'),config.clientId);assert.equal(body.get('code'),'one-time-code');assert.match(body.get('code_verifier')??'',/^[A-Za-z0-9_-]{43}$/);
   if(exchangeBarrier)await exchangeBarrier;
   const identityToken=await new SignJWT({nonce:expectedNonce,auth_time:Math.floor(Date.now()/1000)}).setProtectedHeader({alg:'RS256'}).setIssuer('https://accounts.google.com').setAudience(config.clientId).setSubject(subject).setIssuedAt().setExpirationTime('5m').sign(key.privateKey);
   return new Response(JSON.stringify({id_token:identityToken}),{status:200,headers:{'content-type':'application/json'}});
  };
  handoff=new GoogleRecoveryHandoff(db,management,sessions,humans,principals,plane,clock,config,request);
  const append=plane.appendAudit.bind(plane);plane.appendAudit=async event=>{if(failFinalAudit&&event.eventType==='recovery.google-handoff.verified'){failFinalAudit=false;throw new Error('Synthetic audit outage');}if(failCleanupAudit&&event.eventType==='recovery.google-handoff.expired'){failCleanupAudit=false;throw new Error('Synthetic cleanup audit outage');}await append(event);};
  app=buildApp({...runtime.services,administration:{...runtime.services.administration,identityManagement:management,googleRecoveryHandoff:handoff}},runtime.databaseHealth);
 });
 beforeEach(async()=>{
  await db.query('TRUNCATE human_identities,registered_products,tenants,platform_audit_events,federated_authentication_nonces CASCADE');
  const a=await runtime.services.register.execute({email:'admin@handoff.test',password});admin=a.humanIdentityId;adminSession=a.session.sessionId;await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin,'handoff-test');
  target=(await runtime.services.register.execute({email:'primary@handoff.test',password})).humanIdentityId;
  source=randomUUID();await db.query("INSERT INTO human_identities(id,status,created_at,updated_at)VALUES($1,'active',now(),now())",[source]);
  await db.query("INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,status,created_at,updated_at)VALUES($1,$2,'google','synthetic-google-source','active',now(),now())",[randomUUID(),source]);
  exchanges=0;subject='synthetic-google-source';failFinalAudit=false;failCleanupAudit=false;exchangeBarrier=undefined;
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
  assert.equal((await handoff.cancel(SessionId.from(adminSession),h.handoffId)).state,'verified');
  assert.equal((await db.query('SELECT state FROM identity_management_cases WHERE id=$1',[h.caseId])).rows[0]!.state,'completed');
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
  assert.deepEqual(await closed.expireAbandoned(),{enabled:false,expired:0});
  await assert.rejects(()=>closed.cancel(SessionId.from(adminSession),randomUUID()),e=>(e as any).code==='IDENTITY_MANAGEMENT_DISABLED');
 });
 it('cancels only this administrator unfinished case, clears PKCE and retains audit/proof history',async()=>{
  const h=await start();
  const response=await app.inject({method:'POST',url:'/administration/platform/identity-management/recovery/google/cancel',headers:{authorization:`Bearer ${adminSession}`},payload:{handoffId:h.handoffId}});
  assert.equal(response.statusCode,200);assert.equal(response.json().state,'cancelled');assert.equal(response.headers['cache-control'],'no-store');
  assert.equal((await db.query('SELECT state FROM identity_management_cases WHERE id=$1',[h.caseId])).rows[0]!.state,'cancelled');
  assert.equal((await db.query('SELECT code_verifier FROM identity_management_google_handoffs WHERE id=$1',[h.handoffId])).rows[0]!.code_verifier,null);
  assert.equal((await handoff.cancel(SessionId.from(adminSession),h.handoffId)).state,'cancelled');
  await assert.rejects(()=>handoff.callback({state:h.state,code:'one-time-code'}));assert.equal(exchanges,0);
  assert.equal((await db.query("SELECT count(*) FROM platform_audit_events WHERE event_type='recovery.google-handoff.cancelled'")).rows[0]!.count,'1');
 });
 it('denies missing, ordinary and other-administrator cancellation without leaking case details',async()=>{
  const h=await start(),ordinary=await runtime.services.login.execute({email:'primary@handoff.test',password});
  for(const authorization of [undefined,`Bearer ${ordinary.sessionId}`]){
   const r=await app.inject({method:'POST',url:'/administration/platform/identity-management/recovery/google/cancel',headers:authorization?{authorization}:{},payload:{handoffId:h.handoffId}});
   assert.equal(r.statusCode,authorization?403:401);
  }
  const other=await runtime.services.register.execute({email:'other-admin@handoff.test',password});await runtime.platformAdministrationProvisioning.bootstrapAdministrator(other.humanIdentityId,'handoff-test');
  await assert.rejects(()=>handoff.cancel(SessionId.from(other.session.sessionId),h.handoffId),e=>(e as any).code==='HANDOFF_NOT_FOUND');
  assert.equal((await db.query('SELECT state FROM identity_management_cases WHERE id=$1',[h.caseId])).rows[0]!.state,'awaiting_proof');
 });
 it('cancellation racing a claimed provider exchange prevents proof from becoming executable',async()=>{
  const h=await start();let release!:()=>void;exchangeBarrier=new Promise<void>(resolve=>{release=resolve;});
  const callback=handoff.callback({state:h.state,code:'one-time-code'});
  for(let i=0;i<100&&exchanges===0;i++)await new Promise(resolve=>setTimeout(resolve,5));
  assert.equal(exchanges,1);
  assert.equal((await handoff.cancel(SessionId.from(adminSession),h.handoffId)).state,'cancelled');
  release();assert.equal((await callback).state,'cancelled');
  assert.equal((await db.query('SELECT state FROM identity_management_google_handoffs WHERE id=$1',[h.handoffId])).rows[0]!.state,'cancelled');
  assert.equal((await db.query('SELECT count(*) FROM identity_management_control_proofs')).rows[0]!.count,'0');
  assert.equal((await db.query('SELECT human_identity_id FROM federated_identities WHERE provider=\'google\'')).rows[0]!.human_identity_id,source);
 });
 it('expiry during a claimed network exchange cannot commit proof even while owner sessions remain fresh',async()=>{
  const h=await start();let release!:()=>void;exchangeBarrier=new Promise<void>(resolve=>{release=resolve;});
  const callback=handoff.callback({state:h.state,code:'one-time-code'});
  for(let i=0;i<100&&exchanges===0;i++)await new Promise(resolve=>setTimeout(resolve,5));
  assert.equal(exchanges,1);
  await db.query("UPDATE identity_management_google_handoffs SET created_at=now()-interval '6 minutes',expires_at=now()-interval '2 minutes' WHERE id=$1",[h.handoffId]);
  assert.deepEqual(await handoff.expireAbandoned(),{enabled:true,expired:1});
  release();assert.equal((await callback).state,'failed');
  assert.equal((await db.query('SELECT count(*) FROM identity_management_control_proofs')).rows[0]!.count,'0');
  assert.equal((await db.query('SELECT state FROM identity_management_cases WHERE id=$1',[h.caseId])).rows[0]!.state,'awaiting_proof');
  assert.equal((await db.query("SELECT count(*) FROM platform_audit_events WHERE event_type='recovery.google-handoff.verified'")).rows[0]!.count,'0');
 });
 it('a same-case restart supersedes a claimed callback before it can commit proof',async()=>{
  const h=await start();let release!:()=>void;exchangeBarrier=new Promise<void>(resolve=>{release=resolve;});
  const callback=handoff.callback({state:h.state,code:'one-time-code'});
  for(let i=0;i<100&&exchanges===0;i++)await new Promise(resolve=>setTimeout(resolve,5));assert.equal(exchanges,1);
  const owner=await runtime.services.login.execute({email:'primary@handoff.test',password});
  const replacement=await handoff.start(SessionId.from(adminSession),{caseId:h.caseId,targetSession:owner.sessionId});
  release();assert.equal((await callback).state,'cancelled');
  assert.equal((await db.query('SELECT count(*) FROM identity_management_control_proofs')).rows[0]!.count,'0');
  exchangeBarrier=undefined;
  assert.equal((await handoff.callback({state:new URL(replacement.authorizationURL).searchParams.get('state')!,code:'one-time-code'})).state,'verified');
  assert.equal((await handoff.result(SessionId.from(adminSession),replacement.handoffId)).state,'verified');
  assert.deepEqual(JSON.parse(new URL(replacement.authorizationURL).searchParams.get('claims')!),{id_token:{auth_time:{essential:true}}});
 });
 it('cancellation after verification invalidates unfinished proof without deleting it',async()=>{
  const h=await start();await handoff.callback({state:h.state,code:'one-time-code'});
  const before=(await db.query('SELECT count(*) FROM identity_management_control_proofs')).rows[0]!.count;
  assert.equal((await handoff.cancel(SessionId.from(adminSession),h.handoffId)).state,'cancelled');
  assert.equal((await db.query('SELECT count(*) FROM identity_management_control_proofs')).rows[0]!.count,before);
  assert.ok((await management.previewRecovery(SessionId.from(adminSession),h.caseId)).blockers.includes('FRESH_CONTROL_REQUIRED'));
 });
 it('automatically scrubs abandoned expired PKCE without polling or deleting history',async()=>{
  const h=await start();
  await db.query("UPDATE identity_management_google_handoffs SET created_at=now()-interval '10 minutes',expires_at=now()-interval '5 minutes' WHERE id=$1",[h.handoffId]);
  const before=await db.query('SELECT count(*) FROM platform_audit_events');
  assert.deepEqual(await handoff.expireAbandoned(),{enabled:true,expired:1});
  assert.deepEqual((await db.query('SELECT state,code_verifier FROM identity_management_google_handoffs WHERE id=$1',[h.handoffId])).rows,[{state:'failed',code_verifier:null}]);
  assert.equal((await db.query('SELECT state FROM identity_management_cases WHERE id=$1',[h.caseId])).rows[0]!.state,'awaiting_proof');
  assert.equal(Number((await db.query('SELECT count(*) FROM platform_audit_events')).rows[0]!.count),Number(before.rows[0]!.count)+1);
  assert.deepEqual(await handoff.expireAbandoned(),{enabled:true,expired:0});
  await assert.rejects(()=>handoff.callback({state:h.state,code:'one-time-code'}));assert.equal(exchanges,0);
 });
 it('bounds batches and concurrent sweepers, preserving unexpired handoffs',async()=>{
  const h=await start();
  for(let i=0;i<3;i++)await db.query(`INSERT INTO identity_management_google_handoffs(id,case_id,case_kind,recovery_case_id,compensation_case_id,actor_id,target_id,admin_session_hash,target_session_hash,state_digest,code_verifier,state,created_at,expires_at)
   SELECT $1,case_id,case_kind,recovery_case_id,compensation_case_id,actor_id,target_id,admin_session_hash,target_session_hash,$2,code_verifier,'awaiting_callback',now()-interval '10 minutes',now()-interval '5 minutes' FROM identity_management_google_handoffs WHERE id=$3`,[randomUUID(),String(i).repeat(64),h.handoffId]);
  const results=await Promise.all([handoff.expireAbandoned(2),handoff.expireAbandoned(2)]);
  assert.equal(results.reduce((n,r)=>n+r.expired,0),3);assert.ok(results.every(r=>r.expired<=2));
  assert.equal((await db.query("SELECT count(*) FROM identity_management_google_handoffs WHERE state='failed' AND code_verifier IS NULL")).rows[0]!.count,'3');
  assert.equal((await db.query('SELECT state FROM identity_management_google_handoffs WHERE id=$1',[h.handoffId])).rows[0]!.state,'awaiting_callback');
  assert.equal((await db.query("SELECT count(*) FROM platform_audit_events WHERE event_type='recovery.google-handoff.expired'")).rows[0]!.count,'3');
 });
 it('rolls PKCE cleanup back if its audit cannot commit and succeeds on safe retry',async()=>{
  const h=await start();await db.query("UPDATE identity_management_google_handoffs SET created_at=now()-interval '10 minutes',expires_at=now()-interval '5 minutes' WHERE id=$1",[h.handoffId]);
  failCleanupAudit=true;await assert.rejects(()=>handoff.expireAbandoned(),/Synthetic cleanup audit outage/);
  const failed=(await db.query('SELECT state,code_verifier FROM identity_management_google_handoffs WHERE id=$1',[h.handoffId])).rows[0]!;
  assert.equal(failed.state,'awaiting_callback');assert.ok(failed.code_verifier);
  assert.equal((await handoff.expireAbandoned()).expired,1);
 });
 it('scrubs interrupted processing after restart and rejects invalid cleanup bounds',async()=>{
  const h=await start();await db.query("UPDATE identity_management_google_handoffs SET state='processing',code_verifier=NULL,created_at=now()-interval '10 minutes',expires_at=now()-interval '5 minutes' WHERE id=$1",[h.handoffId]);
  const humans=new PostgresHumanIdentityRepository(db),sessions=new PostgresSessionRepository(db),principals=new AdministrationPrincipals(plane,humans,runtime.controlPlane);
  const restarted=new GoogleRecoveryHandoff(db,management,sessions,humans,principals,plane,new SystemClock(),config);
  assert.equal((await restarted.expireAbandoned()).expired,1);assert.equal((await handoff.result(SessionId.from(adminSession),h.handoffId)).state,'failed');assert.equal(exchanges,0);
  for(const limit of [0,501,1.5])await assert.rejects(()=>handoff.expireAbandoned(limit),e=>(e as any).code==='INVALID_REQUEST');
 });
 it('reports the dedicated callback setup as a specific blocker when absent',async()=>{
  const humans=new PostgresHumanIdentityRepository(db),sessions=new PostgresSessionRepository(db),principals=new AdministrationPrincipals(plane,humans,runtime.controlPlane);
  const missing=new GoogleRecoveryHandoff(db,management,sessions,humans,principals,plane,new SystemClock(),undefined);
  await assert.rejects(()=>missing.start(SessionId.from(adminSession),{caseId:randomUUID(),targetSession:adminSession}),e=>(e as any).code==='GOOGLE_HANDOFF_NOT_CONFIGURED');
 });
});
