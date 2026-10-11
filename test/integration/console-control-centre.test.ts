import assert from 'node:assert/strict';
import {before,after,beforeEach,describe,it} from 'node:test';
import {randomUUID} from 'node:crypto';
import {buildRuntime,type ApplicationRuntime} from '../../src/api/services.js';
import {buildApp} from '../../src/api/app.js';
import {loadConfig} from '../../src/config/env.js';
import {PostgresDatabase} from '../../src/infrastructure/postgres/database.js';
import {runMigrations} from '../../src/infrastructure/postgres/migrations.js';
import {PostgresControlPlaneRepository} from '../../src/infrastructure/postgres/postgres-control-plane-repository.js';
import {directoryFingerprint,pageCursor,readCursor,resolvedDisplayName} from '../../src/control-plane/application/console-control-centre.js';
import {SessionId} from '../../src/sessions/domain/session-id.js';
import type {FastifyInstance} from 'fastify';
const url=process.env.POSTGRES_CONSOLE_TEST_DATABASE_URL;
describe('Console V2 deterministic helpers',()=>{
 it('uses preferred name then verified email then an unavailable-name label, without inventing a name',()=>{
  assert.equal(resolvedDisplayName(' Preferred ', 'person@example.test','abcdefghi').displayName,'Preferred');
  assert.deepEqual(resolvedDisplayName(null,'some.name@example.test','abcdefghi'),{displayName:'some.name@example.test',displayNameSource:'verified_email'});
  assert.equal(resolvedDisplayName(null,null,'abcdefghi').displayName,'Name unavailable');
 });
 it('binds keyset cursors to every filter and sort',()=>{
  const s=directoryFingerprint({query:'Alice',sort:'name'}),c=pageCursor(s,'alice','human');
  assert.deepEqual(readCursor(c,s),{key:'alice',id:'human'});
  for(const filter of [{query:'Bob',sort:'name' as const},{query:'Alice',sort:'created' as const},{query:'Alice',status:'suspended',sort:'name' as const}])assert.throws(()=>readCursor(c,directoryFingerprint(filter)));
  assert.throws(()=>readCursor('malformed',s));
 });
});
describe('Console V2 PostgreSQL authorization, product separation and recovery review',{skip:!url},()=>{
 let db:PostgresDatabase,runtime:ApplicationRuntime,app:FastifyInstance,control:PostgresControlPlaneRepository;
 let admin:string,adminSession:string,user:string,userSession:string,source:string;
 const request=async(path:string,payload:Record<string,unknown>={},token=adminSession,method:'POST'|'GET'|'PUT'='POST')=>app.inject({method,url:path,...(method==='GET'?{}:{payload}),headers:token?{authorization:`Bearer ${token}`}:{}});
 const pair=()=>({sourceHumanIdentityId:source,targetHumanIdentityId:user,provider:'google'});
 before(async()=>{db=new PostgresDatabase(url!);await runMigrations(db);runtime=await buildRuntime(loadConfig({REPOSITORY_MODE:'postgres',DATABASE_URL:url!,LOG_LEVEL:'silent',IDENTITY_DEFAULT_APP_ID:'fixture-product',IDENTITY_TRUSTED_APPS:JSON.stringify([{id:'fixture-product',displayName:'Fixture Product',baseUrl:'https://fixture.example.test'}])}));control=new PostgresControlPlaneRepository(db);app=buildApp(runtime.services,runtime.databaseHealth);});
 after(async()=>{await app?.close();await runtime?.close();await db?.close();});
 beforeEach(async()=>{
  await db.query('TRUNCATE human_identities,registered_products,tenants,platform_audit_events,federated_authentication_nonces CASCADE');
  const a=await runtime.services.register.execute({email:'admin@fixture.example',password:'Fixture-password-123!'});admin=a.humanIdentityId;adminSession=a.session.sessionId;await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin,'test-fixture');
  const u=await runtime.services.register.execute({email:'verified@fixture.example',password:'Fixture-password-123!'});user=u.humanIdentityId;userSession=u.session.sessionId;
  await db.query('UPDATE credentials SET email_verified_at=now() WHERE human_identity_id=$1',[user]);
  source=randomUUID();await db.query("INSERT INTO human_identities(id,status,created_at,updated_at) VALUES($1,'active',now(),now())",[source]);
  await db.query("INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,provider_email,provider_email_verified,status,created_at,updated_at) VALUES($1,$2,'google','fixture-secret-provider-subject','verified@fixture.example',true,'active',now(),now())",[randomUUID(),source]);
 });
 it('enforces current platform authority for every administration route',async()=>{
  const paths=[['overview',{}],['humans/query',{}],['humans/details',{humanIdentityId:user}],['products/inspect',{}],['activity/query',{}],['recovery/preview',pair()],['recovery/query',{}],['recovery/requests',{...pair(),requestId:randomUUID()}],['products/register',{id:'test-product',displayName:'Test Product'}],['humans/lifecycle',{humanIdentityId:source,action:'delete'}],['recovery/execute',{requestId:randomUUID()}],['recovery/cancel',{requestId:randomUUID()}]] as const;
  for(const [path,payload] of paths){const p='/administration/platform/'+path;assert.equal((await request(p,payload,'')).statusCode,401);assert.equal((await request(p,payload,userSession)).statusCode,403);}
  await db.query("UPDATE platform_administration_memberships SET status='suspended' WHERE human_identity_id=$1",[admin]);
  assert.equal((await request('/administration/platform/overview')).statusCode,403);
 });
 it('denies suspended Humans and revoked or expired sessions without touching session rows',async()=>{
  const before=await db.query('SELECT * FROM sessions ORDER BY id');
  assert.equal((await request('/administration/platform/overview')).statusCode,200);
  assert.deepEqual((await db.query('SELECT * FROM sessions ORDER BY id')).rows,before.rows);
  await runtime.services.logout.execute(SessionId.from(adminSession));assert.equal((await request('/administration/platform/overview')).statusCode,401);
  await db.query("UPDATE sessions SET status='active',expires_at=now()-interval '1 minute' WHERE id=$1",[adminSession]);assert.equal((await request('/administration/platform/overview')).statusCode,401);
  await db.query("UPDATE sessions SET expires_at=now()+interval '1 hour' WHERE id=$1",[adminSession]);await db.query("UPDATE human_identities SET status='suspended' WHERE id=$1",[admin]);assert.equal((await request('/administration/platform/overview')).statusCode,403);
 });
 it('returns verified email fallback and retains historical provider metadata without secrets',async()=>{
  const response=await request('/administration/platform/humans/query',{query:'verified@fixture.example'});assert.equal(response.statusCode,200);
  const humans=response.json().humans;assert.equal(humans.length,2);assert.equal(humans.find((h:any)=>h.humanIdentityId===user).displayName,'verified@fixture.example');
  assert.ok(!/provider_subject|providerSubject|fixture-secret|password_hash|passwordHash|renewal_token|renewalToken|sessionId/.test(response.body));assert.equal(response.headers['cache-control'],'no-store');
  await db.query("UPDATE federated_identities SET status='disabled' WHERE human_identity_id=$1",[source]);
  assert.equal((await request('/administration/platform/humans/details',{humanIdentityId:source})).json().human.authenticationMethods[0].status,'disabled');
 });
 it('pages and filters SQL projections with stable ties for every sort',async()=>{
  for(let i=0;i<53;i++)await db.query("INSERT INTO human_identities(id,status,created_at,updated_at) VALUES($1,'active','2025-01-01','2025-01-01')",[`fixture-${String(i).padStart(3,'0')}`]);
  for(const sort of ['created','activity','id','name']){
   const first=await request('/administration/platform/humans/query',{query:'fixture-',sort});assert.equal(first.statusCode,200);assert.equal(first.json().humans.length,50);assert.ok(first.json().nextCursor);
   const second=await request('/administration/platform/humans/query',{query:'fixture-',sort,cursor:first.json().nextCursor});assert.equal(second.json().humans.length,3);assert.equal(second.json().nextCursor,null);assert.equal(new Set([...first.json().humans,...second.json().humans].map((h:any)=>h.humanIdentityId)).size,53);
   assert.equal((await request('/administration/platform/humans/query',{query:'other',sort,cursor:first.json().nextCursor})).statusCode,400);
  }
  const onlyGoogle=await request('/administration/platform/humans/query',{provider:'google'});assert.deepEqual(onlyGoogle.json().humans.map((h:any)=>h.humanIdentityId),[source]);
  assert.equal((await request('/administration/platform/humans/query',{status:'retired'})).json().humans.length,0);
 });
 it('allows only the Human to edit their global name, with optimistic concurrency and clearing',async()=>{
  const profile=await request('/profile',{},userSession,'GET');assert.equal(profile.json().revision,0);
  assert.equal((await request('/profile',{preferredDisplayName:' Preferred Name ',expectedRevision:0},userSession,'PUT')).json().preferredDisplayName,'Preferred Name');
  assert.equal((await request('/profile',{preferredDisplayName:'overwrite',expectedRevision:0},userSession,'PUT')).statusCode,409);
  assert.equal((await request('/profile',{humanIdentityId:source,preferredDisplayName:'takeover',expectedRevision:0},userSession,'PUT')).statusCode,400);
  assert.equal((await request('/administration/platform/humans/query',{query:'preferred name'})).json().humans[0].displayName,'Preferred Name');
  assert.equal((await request('/profile',{preferredDisplayName:null,expectedRevision:1},userSession,'PUT')).json().revision,2);
  assert.equal((await request('/profile',{preferredDisplayName:'bad\u0000name',expectedRevision:2},userSession,'PUT')).statusCode,400);
  assert.equal((await request('/profile',{preferredDisplayName:'x'.repeat(121),expectedRevision:2},userSession,'PUT')).statusCode,400);
 });
 it('reuses preferred names in the existing Explorer without changing its authentication contract',async()=>{
  await request('/profile',{preferredDisplayName:'Existing Explorer Name',expectedRevision:0},userSession,'PUT');
  const search=await request('/administration/platform/identities/inspect',{mode:'search',query:'Explorer Name'});assert.equal(search.statusCode,200);assert.ok(search.body.includes(user));
  const detail=await request('/administration/platform/identities/inspect',{mode:'details',humanIdentityIds:[user]});assert.equal(detail.statusCode,200);assert.ok(detail.body.includes('Existing Explorer Name'));
 });
 it('resolves concurrent profile saves to exactly one winner',async()=>{
  const result=await Promise.all(['First','Second'].map(name=>request('/profile',{preferredDisplayName:name,expectedRevision:0},userSession,'PUT')));assert.deepEqual(result.map(r=>r.statusCode).sort(),[200,409]);
 });
 it('rolls profile writes back if audit persistence fails',async()=>{
  await db.query("ALTER TABLE platform_audit_events ADD CONSTRAINT fixture_profile_audit_failure CHECK(event_type<>'human.profile.updated') NOT VALID");
  try{assert.equal((await request('/profile',{preferredDisplayName:'must roll back',expectedRevision:0},userSession,'PUT')).statusCode,500);assert.equal((await db.query('SELECT * FROM human_profiles WHERE human_identity_id=$1',[user])).rowCount,0);}finally{await db.query('ALTER TABLE platform_audit_events DROP CONSTRAINT fixture_profile_audit_failure');}
 });
 it('separates participation, entitlement and business membership across multiple products',async()=>{
  for(const id of ['first-product','second-product']){await control.saveProduct({id,displayName:id,status:'active'});await control.saveWorkload({id:id+'-workload',productId:id,secretHash:'unused-fixture-hash',status:'active'});await db.query("INSERT INTO human_product_participations VALUES($1,$2,$3,'active',now(),now())",[user,id,id+'-workload']);}
  const detail=(await request('/administration/platform/humans/details',{humanIdentityId:user})).json();assert.equal(detail.human.products.length,2);assert.equal(detail.human.memberships.length,0);assert.ok(detail.human.products.every((p:any)=>p.entitlements.length===0));
  const products=(await request('/administration/platform/products/inspect')).json().products;assert.ok(products.every((p:any)=>p.participants===1&&p.entitledHumans===0&&p.businesses===0));
  assert.equal((await request('/administration/platform/humans/query',{productId:'first-product'})).json().humans.length,1);
 });
 it('does not infer Human participation from a business entitlement',async()=>{
  await control.saveProduct({id:'fixture-product',displayName:'Fixture',status:'active'});await control.saveTenant({id:'fixture-business',displayName:'Business',status:'active'});await control.saveParticipation({tenantId:'fixture-business',productId:'fixture-product',status:'active'});
  await control.saveMembership({tenantId:'fixture-business',humanIdentityId:user,tenantRole:'staff',status:'active',createdAt:new Date(),updatedAt:new Date()});await control.saveEntitlement({tenantId:'fixture-business',productId:'fixture-product',humanIdentityId:user,status:'active'});
  const p=(await request('/administration/platform/products/inspect')).json().products[0];assert.equal(p.participants,0);assert.equal(p.entitledHumans,1);assert.equal(p.businesses,1);
  const h=(await request('/administration/platform/humans/details',{humanIdentityId:user})).json().human;assert.equal(h.products[0].participationStatus,null);
 });
 it('registers participation only for the authenticated Human and authenticated workload, idempotently',async()=>{
  await control.saveProduct({id:'fixture-product',displayName:'Fixture',status:'active'});
  const hasher=(await import('../../src/authentication/adapters/argon2-password-operations.js')).Argon2PasswordOperations;
  const secret='Fixture-workload-secret-at-least-24';await control.saveWorkload({id:'fixture-workload',productId:'fixture-product',secretHash:(await new hasher({memoryCost:8192,timeCost:1,parallelism:1}).hash(secret)).value,status:'active'});
  const options={method:'POST' as const,url:'/control/human-participation',payload:{},headers:{authorization:`Bearer ${userSession}`,'x-gama-workload-id':'fixture-workload','x-gama-workload-secret':secret}};
  assert.equal((await request('/control/human-participation',{},userSession)).statusCode,401);
  assert.equal((await app.inject({...options,payload:{humanIdentityId:source}})).statusCode,400);
  const results=await Promise.all([app.inject(options),app.inject(options)]);assert.ok(results.every(r=>r.statusCode===200));assert.equal(results.filter(r=>r.json().created).length,1);
  assert.equal((await db.query('SELECT * FROM tenant_memberships WHERE human_identity_id=$1',[user])).rowCount,0);assert.equal((await db.query('SELECT * FROM product_entitlements WHERE human_identity_id=$1',[user])).rowCount,0);
  assert.equal((await db.query("SELECT * FROM platform_audit_events WHERE event_type='human.product.participation.registered'")).rowCount,1);
  assert.equal((await app.inject({...options,headers:{...options.headers,'x-gama-workload-secret':'wrong-fixture-secret'}})).statusCode,401);
  await db.query("UPDATE human_product_participations SET status='suspended' WHERE human_identity_id=$1",[user]);
  const inactive=await app.inject(options);assert.equal(inactive.statusCode,409);assert.equal(inactive.json().error.code,'PARTICIPATION_INACTIVE');

 });
 it('registers metadata without claiming an operational authentication integration',async()=>{
  const input={id:'new-product',displayName:'New Product'};assert.equal((await request('/administration/platform/products/register',input)).statusCode,200);assert.equal((await request('/administration/platform/products/register',input)).statusCode,200);
  assert.equal((await request('/administration/platform/products/register',{...input,displayName:'Wrong'})).statusCode,409);
  const p=(await request('/administration/platform/products/inspect')).json().products[0];assert.equal(p.authenticationConfigurationPresent,false);assert.equal(p.participants,0);assert.equal(p.participationCoverage,'no_authenticated_reporting_workload');
  await db.query("UPDATE sessions SET authenticated_at=now()-interval '10 minutes' WHERE id=$1",[adminSession]);assert.equal((await request('/administration/platform/products/register',{id:'other',displayName:'Other'})).statusCode,403);
 });
 it('shows only evidence-backed issues and explicitly reports missing coverage',async()=>{
  const response=await request('/administration/platform/overview');assert.equal(response.statusCode,200);assert.equal(response.json().summary.humans,3);assert.equal(response.json().summary.duplicateEmailGroups,1);assert.equal(response.json().summary.knownParticipants,0);assert.equal(response.json().issues.length,1);assert.equal(response.json().issues[0].destination,'duplicates');assert.equal(response.json().coverage.productLocalDependencies,'unknown');
 });
 it('returns redacted audit records with bounded pages and exact event filtering',async()=>{
  for(let i=0;i<55;i++)await control.appendAudit({id:randomUUID(),eventType:'fixture.operation',actorReference:`human-identity:${admin}`,subjectReference:user,eventData:{providerSubject:'secret',password:'secret',token:'secret'},occurredAt:new Date('2025-01-01')});
  const first=await request('/administration/platform/activity/query',{eventType:'fixture.operation'});assert.equal(first.json().events.length,50);assert.ok(!/providerSubject|password|token|eventData|secret/.test(first.body));
  const second=await request('/administration/platform/activity/query',{eventType:'fixture.operation',cursor:first.json().nextCursor});assert.equal(second.json().events.length,5);assert.equal(new Set([...first.json().events,...second.json().events].map((e:any)=>e.id)).size,55);
 });
 it('fails every PII projection closed on audit outage',async()=>{
  await db.query("ALTER TABLE platform_audit_events ADD CONSTRAINT fixture_inspection_audit_failure CHECK(event_type NOT IN('platform.humans.inspected','platform.human.inspected','platform.overview.inspected','platform.products.inspected','platform.activity.inspected','identity.recovery.previewed','identity.recovery.requests.inspected')) NOT VALID");
  try{for(const [path,payload] of [['humans/query',{}],['humans/details',{humanIdentityId:user}],['overview',{}],['products/inspect',{}],['activity/query',{}],['recovery/preview',pair()],['recovery/query',{}]] as const){const r=await request('/administration/platform/'+path,payload);assert.equal(r.statusCode,500);assert.ok(!r.body.includes('verified@fixture.example'));}}finally{await db.query('ALTER TABLE platform_audit_events DROP CONSTRAINT fixture_inspection_audit_failure');}
 });
 it('previews reusable Google, Apple and Email cases without converting email equality into proof',async()=>{
  for(const provider of ['google','apple','email_password']){const r=await request('/administration/platform/recovery/preview',{...pair(),provider});assert.equal(r.statusCode,200);assert.equal(r.json().ownershipVerified,false);assert.equal(r.json().executionEnabled,false);assert.equal(r.json().externalDependencies,'unknown');assert.ok(r.json().blockers.some((b:any)=>b.code==='OWNERSHIP_PROOF_REQUIRED'));}
 });
 it('inventories expired-access renewable sessions and roles without entitlements',async()=>{
  await db.query('UPDATE sessions SET human_identity_id=$1,expires_at=now()-interval \'1 minute\' WHERE id=$2',[source,userSession]);
  await control.saveTenant({id:'business',displayName:'Business',status:'active'});await control.saveMembership({tenantId:'business',humanIdentityId:source,tenantRole:'owner',status:'active',createdAt:new Date(),updatedAt:new Date()});
  const r=await request('/administration/platform/recovery/preview',pair());assert.equal(r.json().sourceDependencies.activeSessions,0);assert.equal(r.json().sourceDependencies.renewableSessions,1);assert.equal(r.json().source.products.length,0);assert.ok(r.json().blockers.some((b:any)=>b.code==='DEPENDENCIES_PRESENT'));assert.ok(r.json().blockers.some((b:any)=>b.code==='SESSION_REVOCATION_APPROVAL_REQUIRED'));
 });
 it('creates a durable idempotent review request and cancels it without an execution grant',async()=>{
  const input={...pair(),requestId:randomUUID()};const results=await Promise.all([request('/administration/platform/recovery/requests',input),request('/administration/platform/recovery/requests',input)]);assert.ok(results.every(r=>r.statusCode===200));assert.equal(results[0]!.json().id,results[1]!.json().id);assert.equal((await db.query('SELECT * FROM identity_recovery_requests')).rowCount,1);
  assert.equal((await request('/administration/platform/recovery/requests',{...input,provider:'apple'})).statusCode,409);
  assert.equal((await request('/administration/platform/overview')).json().summary.pendingRecoveryRequests,1);
  const cancelled=await request('/administration/platform/recovery/cancel',{requestId:input.requestId});assert.equal(cancelled.json().state,'cancelled');assert.equal((await request('/administration/platform/overview')).json().summary.pendingRecoveryRequests,0);
  await assert.rejects(db.query("UPDATE identity_recovery_requests SET state='approved'"));
 });
 it('preserves original reviewed evidence on retries and cancellation after inventory changes',async()=>{
  const input={...pair(),requestId:randomUUID()};const original=(await request('/administration/platform/recovery/requests',input)).json();assert.match(original.reviewDigest,/^[a-f0-9]{64}$/);
  await request('/profile',{preferredDisplayName:'Changed after review',expectedRevision:0},userSession,'PUT');
  const current=(await request('/administration/platform/recovery/preview',pair())).json();assert.notEqual(current.reviewDigest,original.reviewDigest);
  assert.equal((await request('/administration/platform/recovery/requests',input)).json().reviewDigest,original.reviewDigest);
  assert.equal((await request('/administration/platform/recovery/cancel',{requestId:input.requestId})).json().reviewDigest,original.reviewDigest);
  assert.equal((await db.query("SELECT 1 FROM platform_audit_events WHERE event_type='identity.recovery.request.retried'")).rowCount,1);
 });
 it('rejects invalid timestamp cursors before querying PostgreSQL',async()=>{
  for(const [path,scope] of [['activity/query','activity:'],['recovery/query','recovery-requests']])assert.equal((await request('/administration/platform/'+path,{cursor:pageCursor(scope!,'2026-99-99T99:99:99.000000Z','x')})).statusCode,400);
 });
 it('requires fresh administrator authentication for durable recovery requests',async()=>{
  await db.query("UPDATE sessions SET authenticated_at=now()-interval '10 minutes' WHERE id=$1",[adminSession]);assert.equal((await request('/administration/platform/recovery/requests',{...pair(),requestId:randomUUID()})).statusCode,403);assert.equal((await request('/administration/platform/recovery/preview',pair())).statusCode,200);
 });
 it('keeps account execution, deletion, retirement, suspension and session revocation disabled',async()=>{
  const snapshot=async()=>Promise.all(['human_identities','credentials','federated_identities','sessions','tenant_memberships','product_entitlements'].map(async t=>(await db.query(`SELECT to_jsonb(x) AS value FROM ${t} x ORDER BY to_jsonb(x)::text`)).rows));const before=await snapshot();
  for(const action of ['delete','retire','suspend','reactivate','revoke_sessions'])assert.equal((await request('/administration/platform/humans/lifecycle',{humanIdentityId:source,action})).statusCode,403);
  assert.equal((await request('/administration/platform/recovery/execute',{requestId:randomUUID()})).statusCode,403);
  assert.deepEqual(await snapshot(),before);
 });
 it('rolls recovery request creation back if its audit fails',async()=>{
  await db.query("ALTER TABLE platform_audit_events ADD CONSTRAINT fixture_request_audit_failure CHECK(event_type<>'identity.recovery.requested') NOT VALID");
  try{assert.equal((await request('/administration/platform/recovery/requests',{...pair(),requestId:randomUUID()})).statusCode,500);assert.equal((await db.query('SELECT * FROM identity_recovery_requests')).rowCount,0);}finally{await db.query('ALTER TABLE platform_audit_events DROP CONSTRAINT fixture_request_audit_failure');}
 });
 it('rejects caller-picked provider subjects, unbounded bodies and invalid filters',async()=>{
  for(const payload of [{query:'x'.repeat(321)},{sort:'DROP TABLE human_identities'},{provider:'password_hash'},{status:'anything'},{cursor:'bad'},{query:'',providerSubject:'secret'}])assert.equal((await request('/administration/platform/humans/query',payload)).statusCode,400);
  assert.equal((await request('/administration/platform/recovery/preview',{...pair(),providerSubject:'secret'})).statusCode,400);assert.equal((await request('/administration/platform/recovery/preview',{...pair(),targetHumanIdentityId:source})).statusCode,400);
 });
});
