// Local simulator fixture only; excluded from production builds.
import {buildRuntime} from '../../src/api/services.js';
import {buildApp} from '../../src/api/app.js';
import {loadConfig} from '../../src/config/env.js';
import {PostgresDatabase} from '../../src/infrastructure/postgres/database.js';
import {PostgresControlPlaneRepository} from '../../src/infrastructure/postgres/postgres-control-plane-repository.js';
import {consoleFixtureDatabaseAllowed} from './console-ui-fixture-safety.js';
const managementUI=process.env.GAMA_CONSOLE_MANAGEMENT_UI_TESTING==='1';
const url=process.env.POSTGRES_CONSOLE_UI_DATABASE_URL;
if(!consoleFixtureDatabaseAllowed(url,managementUI)||!url)throw new Error('Local fixture database required');
const runtime=await buildRuntime(loadConfig({...(managementUI?{NODE_ENV:'test'}:{}),REPOSITORY_MODE:'postgres',DATABASE_URL:url,LOG_LEVEL:'silent'}));
const db=new PostgresDatabase(url,false,()=>{},managementUI),control=new PostgresControlPlaneRepository(db);
await db.query('TRUNCATE human_identities,registered_products,tenants,platform_audit_events,federated_authentication_nonces CASCADE');
const admin=await runtime.services.register.execute({email:'console-admin@fixture.example',password:'Fixture-console-password-123!'});
await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin.humanIdentityId,'ui-fixture');
const customer=await runtime.services.register.execute({email:'customer@fixture.example',password:'Fixture-customer-password-123!'});
await db.query('UPDATE credentials SET email_verified_at=now()');
for(const [id,name] of [[admin.humanIdentityId,'Fixture Administrator'],[customer.humanIdentityId,'Fixture Customer']])await db.query('INSERT INTO human_profiles VALUES($1,$2,1,now())',[id,name]);
const source='33333333-3333-4333-8333-333333333333';
await db.query("INSERT INTO human_identities(id,status,created_at,updated_at) VALUES($1,'active',now(),now())",[source]);
await db.query("INSERT INTO federated_identities(id,human_identity_id,provider,provider_subject,provider_email,provider_email_verified,status,created_at,updated_at) VALUES('ui-fixture-google',$1,'google','ui-fixture-secret-subject','customer@fixture.example',true,'active',now(),now())",[source]);
await control.saveProduct({id:'fixture-product',displayName:'Fixture Product',status:'active'});
await control.saveWorkload({id:'fixture-workload',productId:'fixture-product',secretHash:'unused-ui-fixture-hash',status:'active'});
await db.query("INSERT INTO human_product_participations(human_identity_id,product_id,workload_id,status,created_at,updated_at) VALUES($1,'fixture-product','fixture-workload','active',now(),now())",[customer.humanIdentityId]);
await control.saveTenant({id:'fixture-business',displayName:'Fixture Business',status:'active'});
await control.saveParticipation({tenantId:'fixture-business',productId:'fixture-product',status:'active'});
await control.saveMembership({tenantId:'fixture-business',humanIdentityId:admin.humanIdentityId,tenantRole:'owner',status:'active',createdAt:new Date(),updatedAt:new Date()});
await control.saveEntitlement({tenantId:'fixture-business',productId:'fixture-product',humanIdentityId:admin.humanIdentityId,status:'active'});
await db.query("INSERT INTO human_purposes(human_identity_id,purpose,reason,actor_human_identity_id,revision,updated_at) VALUES($1,'test','Trusted isolated UI fixture',$2,1,now())",[source,admin.humanIdentityId]);
const app=buildApp(runtime.services,runtime.databaseHealth);
if(managementUI){
 const {Argon2PasswordOperations}=await import('../../src/authentication/adapters/argon2-password-operations.js');
 const hash=await new Argon2PasswordOperations({memoryCost:1024,timeCost:1,parallelism:1}).hash('Synthetic-ui-workload-secret!');
 await control.saveWorkload({id:'fixture-workload',productId:'fixture-product',status:'active',secretHash:hash.value});
 const test=await runtime.services.register.execute({email:'test-owner@fixture.example',password:'Fixture-test-password-123!'});
 await db.query('INSERT INTO human_profiles VALUES($1,$2,1,now())',[test.humanIdentityId,'Fixture Test Human']);
 await runtime.services.administration.identityManagement!.registerInspector((await import('../../src/sessions/domain/session-id.js')).SessionId.from(admin.session.sessionId),'fixture-product','fixture-workload');
 const refresh=async()=>{ for(const id of [test.humanIdentityId,source,customer.humanIdentityId])await runtime.services.administration.identityManagement!.reportDependencies('fixture-workload','Synthetic-ui-workload-secret!',{humanIdentityId:id,counts:{localAccounts:0,subscriptions:0,permissions:0,ownership:0,backgroundJobs:0,pendingOperations:0,externalReferences:0,retention:0},evidenceReference:'synthetic-ui-clear',observedAt:new Date().toISOString()});};
 await refresh();
 // Known synthetic dependencies refresh only when the user requests an assessment
 // or lifecycle Preview. Keep evidence stable through explicit confirmation;
 // production freshness limits and review-digest checks remain unchanged.
 const assessmentRoutes=new Set(['/administration/platform/identity-management/inspect','/administration/platform/identity-management/lifecycle/preview']);
 app.addHook('preHandler',async request=>{if(request.method==='POST'&&assessmentRoutes.has(request.routeOptions.url??''))await refresh();});
}
const port=managementUI?3120:3119;
await app.listen({host:'127.0.0.1',port});
console.log(`Console UI fixture ready on loopback port${port} (${managementUI?'synthetic-management':'read-only'})`);
for(const signal of ['SIGINT','SIGTERM'] as const)process.on(signal,()=>{void app.close().then(()=>runtime.close()).then(()=>db.close()).then(()=>process.exit(0));});
