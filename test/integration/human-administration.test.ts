import assert from 'node:assert/strict';
import {before,after,beforeEach,describe,it} from 'node:test';
import {randomUUID,randomBytes} from 'node:crypto';
import {buildRuntime,type ApplicationRuntime} from '../../src/api/services.js';
import {buildApp} from '../../src/api/app.js';
import {loadConfig} from '../../src/config/env.js';
import {PostgresDatabase} from '../../src/infrastructure/postgres/database.js';
import {runMigrations} from '../../src/infrastructure/postgres/migrations.js';
import {SessionId} from '../../src/sessions/domain/session-id.js';
import type {HumanAdministration,HumanAdministrativeCommand,AdministrativeHumanAction,HumanDeletionScope} from '../../src/control-plane/application/human-administration.js';
import type {FastifyInstance} from 'fastify';
const url=process.env.POSTGRES_ACCOUNT_TEST_DATABASE_URL;
const password='Synthetic-password-123!';
describe('Production configuration: isolated PostgreSQL account administration, deletion and product cleanup',{skip:!url},()=>{
 let runtime:ApplicationRuntime,db:PostgresDatabase,service:HumanAdministration,app:FastifyInstance;
 let admin:string,adminSession:string,target:string,targetSession:string,targetRenewal:string,other:string;
 const token=()=>SessionId.from(adminSession);
 const command=async(action:AdministrativeHumanAction='delete',human=target,scope:HumanDeletionScope='identity_only'):Promise<HumanAdministrativeCommand>=>{
  const p=await service.preview(token(),human,action,scope);
  return {action,humanIdentityId:human,scope,requestId:randomUUID(),reviewDigest:p.reviewDigest,confirmation:p.confirmation};
 };
 const snapshot=async(id:string)=>{
  const result:Record<string,unknown>={};
  for(const table of ['human_identities','credentials','federated_identities','sessions','tenant_memberships','product_entitlements','human_profiles']){
   result[table]=(await db.query(`SELECT * FROM ${table} WHERE ${table==='human_identities'?'id':'human_identity_id'}=$1 ORDER BY 1`,[id])).rows;
  }return result;
 };
 before(async()=>{
  assert.equal(new URL(url!).hostname,'127.0.0.1');assert.ok(new URL(url!).pathname.endsWith('_management_test'));
  runtime=await buildRuntime(loadConfig({NODE_ENV:'production',REPOSITORY_MODE:'postgres',DATABASE_URL:url!,LOG_LEVEL:'silent',PASSWORD_HASH_MEMORY_KIB:'8192',PASSWORD_HASH_ITERATIONS:'2',IDENTITY_EMAIL_LINKING_ENABLED:'true',IDENTITY_EMAIL_UNLINKING_ENABLED:'true',IDENTITY_PASSWORD_MANAGEMENT_ENABLED:'true',IDENTITY_HUMAN_CLASSIFICATION_ENABLED:'true',IDENTITY_HUMAN_SUSPENSION_ENABLED:'true',IDENTITY_HUMAN_REACTIVATION_ENABLED:'true',IDENTITY_HUMAN_SESSION_REVOCATION_ENABLED:'true',IDENTITY_HUMAN_RETIREMENT_ENABLED:'true',IDENTITY_HUMAN_DELETION_ENABLED:'true',IDENTITY_HUMAN_BULK_ENABLED:'true',IDENTITY_WORKLOAD_ADMINISTRATION_ENABLED:'true'}));
  assert.equal(runtime.services.administration.identityManagement!.executionEnabled,false);
  assert.equal(runtime.services.administration.identityManagement!.recoveryEnabled,false);
  db=new PostgresDatabase(url!,false,()=>{},true);service=runtime.services.administration.humans!;app=buildApp(runtime.services);
 });
 after(async()=>{await app?.close();await runtime?.close();await db?.close();});
 beforeEach(async()=>{
  await db.query('TRUNCATE human_identities,registered_products,tenants,platform_audit_events,federated_authentication_nonces,identity_security_attempts CASCADE');
  const a=await runtime.services.register.execute({email:'admin@synthetic.example',password});admin=a.humanIdentityId;adminSession=a.session.sessionId;
  await db.query('UPDATE credentials SET email_verified_at=now() WHERE human_identity_id=$1',[admin]);
  await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin,'synthetic-fixture');
  const t=await runtime.services.register.execute({email:'customer@synthetic.example',password});target=t.humanIdentityId;targetSession=t.session.sessionId;targetRenewal=t.session.renewalToken;
  other=(await runtime.services.register.execute({email:'unrelated@synthetic.example',password})).humanIdentityId;
  await db.query("INSERT INTO registered_products(id,display_name,status) VALUES('synthetic-product','Synthetic','active'),('unrelated-product','Other','active')");
  await db.query("INSERT INTO tenants(id,display_name,status) VALUES('shared-business','Protected shared business','active')");
  await db.query("INSERT INTO tenant_memberships(tenant_id,human_identity_id,status,tenant_role,created_at,updated_at) VALUES('shared-business',$1,'active','owner',now(),now()),('shared-business',$2,'active','staff',now(),now())",[other,target]);
  await db.query("INSERT INTO product_participations(tenant_id,product_id,status) VALUES('shared-business','synthetic-product','active'),('shared-business','unrelated-product','active')");
  await db.query("INSERT INTO product_entitlements(tenant_id,product_id,human_identity_id,status) VALUES('shared-business','synthetic-product',$1,'active'),('shared-business','unrelated-product',$2,'active')",[target,other]);
  await db.query("INSERT INTO human_profiles(human_identity_id,preferred_display_name,revision,updated_at) VALUES($1,'Synthetic customer',1,now())",[target]);
  await db.query("INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,provider_email,status,created_at,updated_at) VALUES($1,$2,'google','synthetic-sensitive-subject','customer@synthetic.example','active',now(),now())",[randomUUID(),target]);
 });
 it('Demos A/B: signed Apple/Google ordinary sign-in stays independent; explicit Connect preserves the chosen Human',async()=>{
  const {generateKeyPair,SignJWT}=await import('jose');const key=await generateKeyPair('RS256');
  const {GoogleIdentityTokenVerifier}=await import('../../src/authentication/federated/adapters/google-identity-token-verifier.js');
  const {AppleIdentityTokenVerifier}=await import('../../src/authentication/federated/adapters/apple-identity-token-verifier.js');
  const {FederatedIdentityTokenVerifiers}=await import('../../src/authentication/federated/application/token-verifier.js');
  const {AuthenticateFederated}=await import('../../src/authentication/federated/application/authenticate-federated.js');
  const {ManageFederatedAuthenticationMethods}=await import('../../src/authentication/federated/application/manage-federated-authentication-methods.js');
  const {PostgresFederatedIdentityRepository,PostgresFederatedAuthenticationNonceRepository}=await import('../../src/infrastructure/postgres/postgres-federated-identity-repository.js');
  const {PostgresHumanIdentityRepository}=await import('../../src/infrastructure/postgres/postgres-human-identity-repository.js');
  const {PostgresSessionRepository}=await import('../../src/infrastructure/postgres/postgres-session-repository.js');
  const {PostgresEmailCredentialRepository}=await import('../../src/infrastructure/postgres/postgres-email-credential-repository.js');
  const {PostgresControlPlaneRepository}=await import('../../src/infrastructure/postgres/postgres-control-plane-repository.js');
  const {SystemClock}=await import('../../src/shared/clock.js');
  const {UuidHumanIdentityIdGenerator,UuidFederatedIdentityIdGenerator,UuidSessionIdGenerator}=await import('../../src/shared/identifiers.js');
  const {CreateSession}=await import('../../src/sessions/application/use-cases.js');
  const {createHash}=await import('node:crypto');
  const clock=new SystemClock(),humans=new PostgresHumanIdentityRepository(db),sessions=new PostgresSessionRepository(db),federated=new PostgresFederatedIdentityRepository(db),nonces=new PostgresFederatedAuthenticationNonceRepository(db);
  const verifiers=new FederatedIdentityTokenVerifiers([new GoogleIdentityTokenVerifier({clientIds:['synthetic-client'],keyResolver:async()=>key.publicKey}),new AppleIdentityTokenVerifier({clientIds:['synthetic-client'],keyResolver:async()=>key.publicKey})]);
  const auth=new AuthenticateFederated(verifiers,federated,nonces,humans,new UuidHumanIdentityIdGenerator(),new UuidFederatedIdentityIdGenerator(),new CreateSession(sessions,new UuidSessionIdGenerator(),clock,3600,undefined,2592000,humans),clock,w=>db.withTransaction(w));
  const methods=new ManageFederatedAuthenticationMethods(verifiers,federated,nonces,humans,new PostgresEmailCredentialRepository(db),sessions,new PostgresControlPlaneRepository(db),new UuidFederatedIdentityIdGenerator(),clock,w=>db.withTransaction(w));
  const proof=async(provider:'apple'|'google',subject:string)=>{
   const nonce=randomBytes(32).toString('base64url');
   return {provider,nonce,identityToken:await new SignJWT({nonce:provider==='apple'?createHash('sha256').update(nonce).digest('base64url'):nonce,email:'same@synthetic.example',email_verified:true}).setProtectedHeader({alg:'RS256'}).setIssuer(provider==='apple'?'https://appleid.apple.com':'https://accounts.google.com').setAudience('synthetic-client').setSubject(subject).setIssuedAt().setExpirationTime('5m').sign(key.privateKey)};
  };
  const apple=await auth.execute(await proof('apple','synthetic-independent-apple')),google=await auth.execute(await proof('google','synthetic-independent-google'));
  assert.notEqual(apple.humanIdentityId,google.humanIdentityId);assert.equal((await auth.execute(await proof('google','synthetic-independent-google'))).humanIdentityId,google.humanIdentityId);
  const before=(await db.query('SELECT count(*)::int n FROM human_identities')).rows[0]!.n;
  await methods.link(SessionId.from(apple.session.sessionId),await proof('google','synthetic-explicit-google'));
  assert.equal((await auth.execute(await proof('google','synthetic-explicit-google'))).humanIdentityId,apple.humanIdentityId);
  assert.equal((await db.query('SELECT count(*)::int n FROM human_identities')).rows[0]!.n,before);
  await assert.rejects(()=>proof('google','synthetic-independent-google').then(p=>methods.link(SessionId.from(apple.session.sessionId),p)),(e:any)=>e.code==='FEDERATED_IDENTITY_LINK_CONFLICT');
  assert.equal((await auth.execute(await proof('google','synthetic-independent-google'))).humanIdentityId,google.humanIdentityId);
  await methods.link(SessionId.from(targetSession),await proof('apple','synthetic-explicit-apple'));
  assert.equal((await auth.execute(await proof('apple','synthetic-explicit-apple'))).humanIdentityId,target);
  await methods.unlink(SessionId.from(apple.session.sessionId),'google');
  assert.equal((await auth.execute(await proof('apple','synthetic-independent-apple'))).humanIdentityId,apple.humanIdentityId);
 });
 it('default-disabled development composition denies all new mutation gates without changing existing records',async()=>{
  const closed=await buildRuntime(loadConfig({NODE_ENV:'development',REPOSITORY_MODE:'postgres',DATABASE_URL:url!,LOG_LEVEL:'silent'}));
  const before=await snapshot(target);
  try{
   assert.equal(closed.services.administration.humans!.enabled,false);
   await assert.rejects(()=>closed.services.administration.humans!.execute(token(),awaitCommand),(e:any)=>e.code==='HUMAN_ADMINISTRATION_DISABLED');
   await assert.rejects(()=>closed.services.administration.identityManagement!.prepareRecovery(token(),target,other),(e:any)=>e.code==='IDENTITY_MANAGEMENT_DISABLED');
   await assert.rejects(()=>closed.services.accountManagement!.disconnectEmail(SessionId.from(targetSession)),(e:any)=>e.code==='ACCOUNT_MANAGEMENT_DISABLED');
   await assert.rejects(()=>closed.services.administration.workloads!.create(token(),{}),(e:any)=>e.code==='INVALID_REQUEST'||e.code==='WORKLOAD_ADMINISTRATION_DISABLED');
   assert.deepEqual(await snapshot(target),before);
  }finally{await closed.close();}
 });
 const awaitCommand={humanIdentityId:'synthetic',action:'delete' as const,scope:'identity_only' as const,requestId:randomUUID(),reviewDigest:'0'.repeat(64),confirmation:'synthetic'};
 it('migration 018 ledger and SQL are idempotent without changing existing rows',async()=>{
  const before=await snapshot(target);const {readFile}=await import('node:fs/promises');
  await runMigrations(db);
  assert.deepEqual(await snapshot(target),before);
  assert.deepEqual((await db.query('SELECT version FROM schema_migrations ORDER BY version')).rows.map(r=>r.version),Array.from({length:18},(_,i)=>String(i+1).padStart(3,'0')));
  const sql=await readFile('migrations/018_account_management.sql','utf8');await db.withTransaction(()=>db.query(sql));assert.deepEqual(await snapshot(target),before);
 });
 it('rejects missing/ordinary authority, unknown fields, oversized bulk and stale authentication',async()=>{
  for(const [bearer,status]of [['',401],[targetSession,403]]){
   const r=await app.inject({method:'POST',url:'/administration/platform/humans/manage/preview',headers:bearer?{authorization:`Bearer ${bearer}`}:{},payload:{humanIdentityId:target,action:'delete'}});assert.equal(r.statusCode,status);
  }
  const c=await command();assert.equal((await app.inject({method:'POST',url:'/administration/platform/humans/manage/execute',headers:{authorization:`Bearer ${adminSession}`},payload:{...c,force:true}})).statusCode,400);
  assert.equal((await app.inject({method:'POST',url:'/administration/platform/humans/manage/bulk',headers:{authorization:`Bearer ${adminSession}`},payload:{items:Array(51).fill(c),confirmation:'review 51 identities'}})).statusCode,400);
  const before=await snapshot(target);await db.query("UPDATE sessions SET authenticated_at=now()-interval '6 minutes' WHERE id=$1",[adminSession]);
  await assert.rejects(()=>service.execute(token(),c),(e:any)=>e.code==='REAUTHENTICATION_REQUIRED');assert.deepEqual(await snapshot(target),before);
 });
 it('live administrator revocation denies a previously prepared action',async()=>{
  const c=await command();const before=await snapshot(target);await db.query("UPDATE platform_administration_memberships SET status='retired' WHERE human_identity_id=$1",[admin]);
  await assert.rejects(()=>service.execute(token(),c));assert.deepEqual(await snapshot(target),before);
 });
 it('classifies and suspends/reactivates a nonempty production customer without transferring data',async()=>{
  const m=runtime.services.administration.identityManagement!;
  const a=await m.inspect(token(),target);await m.classify(token(),{humanIdentityId:target,purpose:'production',reason:'Explicit synthetic review',expectedRevision:a.classificationRevision,requestId:randomUUID()});
  await service.execute(token(),await command('suspend'));assert.equal((await db.query('SELECT status FROM human_identities WHERE id=$1',[target])).rows[0]!.status,'suspended');
  await service.execute(token(),await command('reactivate'));assert.equal((await db.query('SELECT status FROM human_identities WHERE id=$1',[target])).rows[0]!.status,'active');
  assert.equal((await db.query('SELECT count(*)::int n FROM product_entitlements WHERE human_identity_id=$1',[target])).rows[0]!.n,1);
 });
 it('protects last functioning administrator and unresolved sole live business ownership',async()=>{
  assert.ok((await service.preview(token(),admin,'delete')).blockers.includes('LAST_FUNCTIONING_ADMINISTRATOR'));
  assert.ok((await service.preview(token(),other,'delete')).blockers.includes('SOLE_BUSINESS_OWNER'));
  await db.query("UPDATE tenant_memberships SET status='retired' WHERE human_identity_id=$1",[other]);
  assert.ok(!(await service.preview(token(),other,'delete')).blockers.includes('SOLE_BUSINESS_OWNER'));
 });
 it('deidentifies a nonempty customer, preserving unrelated identities, shared business and audit history',async()=>{
  const before=await snapshot(other),adminBefore=await snapshot(admin);const c=await command();
  const results=await Promise.all([service.execute(token(),c),service.execute(token(),c)]);
  assert.deepEqual(results[0],results[1]);assert.equal((results[0]as any).operationState,'completed_central_scope');
  assert.deepEqual(await snapshot(other),before);assert.deepEqual(await snapshot(admin),adminBefore);
  assert.equal((await db.query("SELECT status FROM tenants WHERE id='shared-business'")).rows[0]!.status,'active');
  const rows=await db.query('SELECT status FROM human_identities WHERE id=$1',[target]);assert.equal(rows.rows[0]!.status,'retired');
  for(const table of ['credentials','human_profiles','tenant_memberships','product_entitlements'])assert.equal((await db.query(`SELECT count(*)::int n FROM ${table} WHERE human_identity_id=$1`,[target])).rows[0]!.n,0);
  const f=(await db.query('SELECT provider_subject,provider_email,status FROM federated_identities WHERE human_identity_id=$1',[target])).rows[0]!;assert.ok(f.provider_subject.startsWith('deleted:'));assert.equal(f.provider_email,null);assert.equal(f.status,'retired');
  assert.equal((await db.query('SELECT status FROM sessions WHERE id=$1',[targetSession])).rows[0]!.status,'revoked');
  assert.ok((await db.query("SELECT 1 FROM platform_audit_events WHERE event_type='human.deletion.central_completed'")).rowCount);
  await assert.rejects(()=>service.execute(token(),{...c,scope:'eligible_personal_data'}),(e:any)=>e.code==='IDEMPOTENCY_CONFLICT');
  assert.equal((await service.available(token(),target)).deidentified,true);
 });
 it('rolls back every central change when the final audit fails',async()=>{
  const c=await command(),before=await snapshot(target);
  await db.query("CREATE FUNCTION synthetic_reject_delete_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='human.deletion.central_completed' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$");
  await db.query('CREATE TRIGGER synthetic_delete_audit_guard BEFORE INSERT ON platform_audit_events FOR EACH ROW EXECUTE FUNCTION synthetic_reject_delete_audit()');
  try{await assert.rejects(()=>service.execute(token(),c),/synthetic audit failure/);assert.deepEqual(await snapshot(target),before);assert.equal((await db.query('SELECT 1 FROM identity_management_operations WHERE id=$1',[c.requestId])).rowCount,0);}
  finally{await db.query('DROP TRIGGER synthetic_delete_audit_guard ON platform_audit_events');await db.query('DROP FUNCTION synthetic_reject_delete_audit()');}
 });
 it('rejects stale consequences and conflicting concurrent delete intents',async()=>{
  const c=await command();await db.query("UPDATE human_profiles SET revision=revision+1,preferred_display_name='Changed synthetic name' WHERE human_identity_id=$1",[target]);
  await assert.rejects(()=>service.execute(token(),c),(e:any)=>e.code==='REVIEW_CHANGED');
  const x=await command(),y=await command();const r=await Promise.allSettled([service.execute(token(),x),service.execute(token(),y)]);assert.equal(r.filter(a=>a.status==='fulfilled').length,1);
 });
 it('reports unknown external cleanup as pending and enforces product/workload/lease receipts',async()=>{
  const c=await command('delete',target,'eligible_personal_data');const r=await service.execute(token(),c)as any;assert.equal(r.operationState,'pending_external_cleanup');assert.ok(r.externalCleanup.some((t:any)=>t.productId===null&&t.state==='unsupported'));
  const secret=randomBytes(32).toString('base64url'),otherSecret=randomBytes(32).toString('base64url');
  await runtime.services.administration.workloads!.create(token(),{id:'synthetic-cleanup',productId:'synthetic-product',capabilities:['human.data.cleanup'],secret,requestId:randomUUID(),reason:'Local synthetic cleanup test'});
  await runtime.services.administration.workloads!.create(token(),{id:'unrelated-cleanup',productId:'unrelated-product',capabilities:['human.data.cleanup'],secret:otherSecret,requestId:randomUUID(),reason:'Local synthetic wrong product test'});
  await assert.rejects(()=>service.claimCleanup('synthetic-cleanup',otherSecret));
  const claims=await Promise.all([service.claimCleanup('synthetic-cleanup',secret),service.claimCleanup('synthetic-cleanup',secret)]);assert.equal(claims.flatMap(a=>a.tasks).length,1);
  const job=claims.flatMap(a=>a.tasks)[0]!;const completion={id:job.id,revision:job.revision,state:'completed' as const,deletedRecords:4,retainedRecords:1};
  await assert.rejects(()=>service.completeCleanup('unrelated-cleanup',otherSecret,completion));
  await assert.rejects(()=>service.completeCleanup('synthetic-cleanup',secret,{...completion,revision:job.revision+2}));
  assert.equal((await service.completeCleanup('synthetic-cleanup',secret,completion)).replayed,false);assert.equal((await service.completeCleanup('synthetic-cleanup',secret,completion)).replayed,true);
  await assert.rejects(()=>service.completeCleanup('synthetic-cleanup',secret,{...completion,deletedRecords:100}));
  assert.equal((await service.status(token(),c.requestId)).operationState,'pending_external_cleanup');
 });
 it('serializes different-session method removals so one usable method always remains',async()=>{
  const {PostgresSessionRepository}=await import('../../src/infrastructure/postgres/postgres-session-repository.js');
  const {PostgresHumanIdentityRepository}=await import('../../src/infrastructure/postgres/postgres-human-identity-repository.js');
  const {CreateSession}=await import('../../src/sessions/application/use-cases.js');const {UuidSessionIdGenerator}=await import('../../src/shared/identifiers.js');const {SystemClock}=await import('../../src/shared/clock.js');const {HumanIdentityId}=await import('../../src/identity/domain/human-identity-id.js');
  await db.query('UPDATE credentials SET email_verified_at=now() WHERE human_identity_id=$1',[target]);
  const google=await new CreateSession(new PostgresSessionRepository(db),new UuidSessionIdGenerator(),new SystemClock(),3600,undefined,2592000,new PostgresHumanIdentityRepository(db)).execute(HumanIdentityId.from(target),undefined,'google');
  const results=await Promise.allSettled([runtime.services.federatedAuthenticationMethods.unlink(SessionId.from(google.sessionId),'google'),runtime.services.accountManagement!.disconnectEmail(SessionId.from(targetSession))]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  assert.equal((await db.query("SELECT (SELECT count(*) FROM credentials WHERE human_identity_id=$1 AND status='active')+(SELECT count(*) FROM federated_identities WHERE human_identity_id=$1 AND status='active') n",[target])).rows[0]!.n,'1');
 });
 it('Email login cannot create a surviving session after that method is disconnected',async()=>{
  const results=await Promise.allSettled([runtime.services.login.execute({email:'customer@synthetic.example',password}),runtime.services.accountManagement!.disconnectEmail(SessionId.from(targetSession))]);
  assert.equal(results[1]!.status,'fulfilled');
  const login=results[0]!;if(login.status==='fulfilled')assert.equal((await db.query('SELECT status FROM sessions WHERE id=$1',[login.value.sessionId])).rows[0]!.status,'revoked');
  else assert.ok(login.reason);
 });
 it('failed password and reauthentication proofs retain durable rate-limit attempts',async()=>{
  for(let i=0;i<5;i++)assert.equal((await app.inject({method:'POST',url:'/account/password/change',headers:{authorization:`Bearer ${targetSession}`},payload:{currentPassword:'wrong',password}})).statusCode,403);
  assert.equal((await app.inject({method:'POST',url:'/account/password/change',headers:{authorization:`Bearer ${targetSession}`},payload:{currentPassword:password,password}})).statusCode,429);
  // Separate synthetic IP avoids sharing the existing aggregate IP ceiling.
  for(let i=0;i<5;i++)assert.equal((await app.inject({method:'POST',url:'/account/reauthenticate/email',remoteAddress:'127.0.0.3',headers:{authorization:`Bearer ${targetSession}`},payload:{email:'customer@synthetic.example',password:'wrong'}})).statusCode,401);
  assert.equal((await app.inject({method:'POST',url:'/account/reauthenticate/email',remoteAddress:'127.0.0.3',headers:{authorization:`Bearer ${targetSession}`},payload:{email:'customer@synthetic.example',password}})).statusCode,429);
  assert.ok((await db.query('SELECT count(*)::int n FROM identity_security_attempts')).rows[0]!.n>=10);
 });
 it('pending Apple revocation is a real deletion blocker; incomplete coverage still permits central-only deletion',async()=>{
  await db.query("INSERT INTO product_apple_revocations(operation_id,human_identity_id,client_id,encrypted_token) VALUES($1,$2,'synthetic-client','synthetic-encrypted-placeholder')",[randomUUID(),target]);
  assert.ok((await service.preview(token(),target,'delete')).blockers.includes('PROVIDER_REVOCATION_PENDING'));
  await db.query('UPDATE product_apple_revocations SET completed_at=now(),encrypted_token=NULL WHERE human_identity_id=$1',[target]);
  assert.equal((await service.preview(token(),target,'delete')).eligible,true);
 });
 it('bounded bulk returns individual outcomes and preserves protected accounts',async()=>{
  await db.query("INSERT INTO human_purposes(human_identity_id,purpose,reason,actor_human_identity_id,revision,updated_at) VALUES($1,'test','Synthetic bulk review',$2,1,now())",[target,admin]);
  const items=[await command('delete',admin),await command('delete',target)];const r=await service.bulk(token(),items,'review 2 identities');
  assert.deepEqual(r.results.map(x=>x.state),['blocked','completed']);assert.equal((await db.query('SELECT status FROM human_identities WHERE id=$1',[admin])).rows[0]!.status,'active');
 });
 it('revokes sessions separately and retirement retains credentials and associations',async()=>{
  await service.execute(token(),await command('revoke_sessions'));assert.equal((await db.query('SELECT status FROM sessions WHERE id=$1',[targetSession])).rows[0]!.status,'revoked');
  assert.equal((await db.query('SELECT count(*)::int n FROM credentials WHERE human_identity_id=$1',[target])).rows[0]!.n,1);
  await service.execute(token(),await command('retire'));assert.equal((await db.query('SELECT status FROM human_identities WHERE id=$1',[target])).rows[0]!.status,'retired');assert.equal((await db.query('SELECT count(*)::int n FROM product_entitlements WHERE human_identity_id=$1',[target])).rows[0]!.n,1);
 });
 it('independent classification gate restores Test to Unknown while every lifecycle and transfer gate stays off',async()=>{
  const partial=await buildRuntime(loadConfig({NODE_ENV:'production',REPOSITORY_MODE:'postgres',DATABASE_URL:url!,LOG_LEVEL:'silent',IDENTITY_HUMAN_CLASSIFICATION_ENABLED:'true'}));
  try {
   const m=partial.services.administration.identityManagement!,h=partial.services.administration.humans!;
   assert.equal(m.executionEnabled,false);assert.equal(m.recoveryEnabled,false);
   let a=await m.inspect(token(),target);
   await m.classify(token(),{humanIdentityId:target,purpose:'test',reason:'Synthetic explicit test designation',expectedRevision:a.classificationRevision,requestId:randomUUID()});
   a=await m.inspect(token(),target);assert.equal(a.purpose,'test');
   await m.classify(token(),{humanIdentityId:target,purpose:'unknown',reason:'Restore prior synthetic classification',expectedRevision:a.classificationRevision,requestId:randomUUID()});
   assert.equal((await m.inspect(token(),target)).purpose,'unknown');
   assert.ok((await h.available(token(),target)).actions.every(x=>x.executionEnabled===false));
   await assert.rejects(()=>h.execute(token(),awaitCommand),(e:any)=>e.code==='HUMAN_ADMINISTRATION_DISABLED');
   await assert.rejects(()=>m.prepareRecovery(token(),target,other),(e:any)=>e.code==='IDENTITY_MANAGEMENT_DISABLED');
   assert.equal((await db.query('SELECT status FROM sessions WHERE id=$1',[targetSession])).rows[0]!.status,'active');
   assert.equal((await db.query('SELECT count(*)::int n FROM product_entitlements WHERE human_identity_id=$1',[target])).rows[0]!.n,1);
  } finally {await partial.close();}
 });
 it('selected-session revocation binds to one Human, preserves its other session and replays safely',async()=>{
  const second=await runtime.services.login.execute({email:'customer@synthetic.example',password});
  const m=runtime.services.administration.identityManagement!;
  const {digest}=await import('../../src/control-plane/application/identity-management.js');
  const ref=digest(targetSession),a=await m.inspect(token(),target);
  assert.ok(a.sessions.some(x=>x.reference===ref));assert.ok(a.sessions.every(x=>x.reference.length===64 && !JSON.stringify(x).includes(targetSession)));
  const p=await service.preview(token(),target,'revoke_sessions','identity_only',ref);
  assert.equal(p.affectedSessions,1);
  const c={humanIdentityId:target,action:'revoke_sessions' as const,scope:'identity_only' as const,sessionReference:ref,requestId:randomUUID(),reviewDigest:p.reviewDigest,confirmation:p.confirmation};
  const result=await service.execute(token(),c);assert.deepEqual(await service.execute(token(),c),result);
  assert.equal((await db.query('SELECT status FROM sessions WHERE id=$1',[targetSession])).rows[0]!.status,'revoked');
  assert.equal((await db.query('SELECT status FROM sessions WHERE id=$1',[second.sessionId])).rows[0]!.status,'active');
  await assert.rejects(()=>runtime.services.renewSession.execute(targetRenewal));
  assert.equal((await db.query('SELECT status FROM sessions WHERE id=$1',[adminSession])).rows[0]!.status,'active');
  await assert.rejects(()=>service.preview(token(),other,'revoke_sessions','identity_only',ref),(e:any)=>e.code==='SESSION_REFERENCE_NOT_FOUND');
  await assert.rejects(()=>service.preview(token(),target,'delete','identity_only',ref),(e:any)=>e.code==='INVALID_SESSION_REFERENCE');
  assert.equal((await app.inject({method:'GET',url:'/account',headers:{authorization:'Bearer '+targetSession}})).statusCode,401);
  assert.equal((await app.inject({method:'GET',url:'/account',headers:{authorization:'Bearer '+second.sessionId}})).statusCode,200);
 });
 it('suspension denies fresh sign-in and existing access; reactivation requires fresh authentication',async()=>{
  await service.execute(token(),await command('suspend'));
  await assert.rejects(()=>runtime.services.renewSession.execute(targetRenewal));
  await assert.rejects(()=>runtime.services.login.execute({email:'customer@synthetic.example',password}));
  assert.equal((await app.inject({method:'GET',url:'/account',headers:{authorization:'Bearer '+targetSession}})).statusCode,401);
  await service.execute(token(),await command('reactivate'));
  await assert.rejects(()=>runtime.services.renewSession.execute(targetRenewal));
  const fresh=await runtime.services.login.execute({email:'customer@synthetic.example',password});assert.notEqual(fresh.sessionId,targetSession);
  assert.equal((await app.inject({method:'GET',url:'/account',headers:{authorization:'Bearer '+targetSession}})).statusCode,401);
  assert.equal((await app.inject({method:'GET',url:'/account',headers:{authorization:'Bearer '+fresh.sessionId}})).statusCode,200);
 });
 it('bulk eligibility rejects Unknown individually and replay remains valid after Test metadata is deleted',async()=>{
  const m=runtime.services.administration.identityManagement!,a=await m.inspect(token(),target);
  await m.classify(token(),{humanIdentityId:target,purpose:'test',reason:'Synthetic batch review',expectedRevision:a.classificationRevision,requestId:randomUUID()});
  const unknownPreview=await service.preview(token(),other,'revoke_sessions');assert.equal(unknownPreview.bulkEligible,false);
  const items=[await command('delete',target),await command('revoke_sessions',other)];
  const result=await service.bulk(token(),items,'review 2 identities');
  assert.deepEqual(result.results.map(x=>x.state),['completed','blocked']);assert.equal(result.results[1]!.code,'BULK_REQUIRES_CONFIRMED_TEST');
  const replay=await service.bulk(token(),items,'review 2 identities');assert.deepEqual(replay,result);
 });
 it('another business owner without a usable authentication method cannot bypass continuity',async()=>{
  await db.query("UPDATE tenant_memberships SET tenant_role='owner' WHERE tenant_id='shared-business' AND human_identity_id=$1",[target]);
  await db.query("UPDATE credentials SET status='retired' WHERE human_identity_id=$1",[target]);
  await db.query("UPDATE federated_identities SET status='retired' WHERE human_identity_id=$1",[target]);
  assert.ok((await service.preview(token(),other,'delete')).blockers.includes('SOLE_BUSINESS_OWNER'));
 });

 it('central deletion preserves a synthetic shared catalogue and 200 photographs owned by the surviving business',async()=>{
  await db.query("CREATE TABLE synthetic_shared_assets(id integer PRIMARY KEY,tenant_id text REFERENCES tenants(id),kind text NOT NULL)");
  try {
   await db.query("INSERT INTO synthetic_shared_assets SELECT n,'shared-business',CASE WHEN n=0 THEN 'catalogue' ELSE 'photograph' END FROM generate_series(0,200) n");
   const before=(await db.query('SELECT * FROM synthetic_shared_assets ORDER BY id')).rows;
   await service.execute(token(),await command());
   assert.deepEqual((await db.query('SELECT * FROM synthetic_shared_assets ORDER BY id')).rows,before);
   assert.equal((await db.query("SELECT count(*)::int n FROM synthetic_shared_assets WHERE kind='photograph'")).rows[0]!.n,200);
   assert.equal((await db.query("SELECT status FROM tenant_memberships WHERE tenant_id='shared-business' AND human_identity_id=$1",[other])).rows[0]!.status,'active');
  } finally {await db.query('DROP TABLE synthetic_shared_assets');}
 });

 it('an explicit individual false overrides the compatibility group and configuration transitions are audited without secrets',async()=>{
  const closedDelete=await buildRuntime(loadConfig({NODE_ENV:'production',REPOSITORY_MODE:'postgres',DATABASE_URL:url!,LOG_LEVEL:'silent',IDENTITY_HUMAN_ADMINISTRATION_ENABLED:'true',IDENTITY_HUMAN_DELETION_ENABLED:'false'}));
  try {
   const available=await closedDelete.services.administration.humans!.available(token(),target);
   assert.equal(available.capabilities.delete,false);assert.equal(available.capabilities.suspend,true);
   await assert.rejects(()=>closedDelete.services.administration.humans!.execute(token(),awaitCommand),(e:any)=>e.code==='HUMAN_ADMINISTRATION_DISABLED');
   const receipt=(await db.query("SELECT actor_reference,event_data FROM platform_audit_events WHERE event_type='administration.capabilities.configured' ORDER BY occurred_at DESC LIMIT 1")).rows[0]!;
   assert.equal(receipt.actor_reference,'system:runtime-configuration');
   assert.equal(JSON.parse(receipt.event_data.capabilities).human.delete,false);
   assert.doesNotMatch(JSON.stringify(receipt.event_data),/Synthetic-password|clientSecret|providerSubject|sessionId/);
  } finally {await closedDelete.close();}
 });

});
