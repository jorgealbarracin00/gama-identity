// Development-only actual product-caller demonstration. Never connects to production.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {buildRuntime} from '../src/api/services.js';
import {buildApp} from '../src/api/app.js';
import {loadConfig} from '../src/config/env.js';
import {syntheticManagementEnabled} from '../src/control-plane/application/identity-management.js';
import {PostgresDatabase} from '../src/infrastructure/postgres/database.js';
import {PostgresControlPlaneRepository} from '../src/infrastructure/postgres/postgres-control-plane-repository.js';
import {Argon2PasswordOperations} from '../src/authentication/adapters/argon2-password-operations.js';

const databaseURL=process.env.POSTGRES_CROSS_PRODUCT_DEMO_DATABASE_URL;
assert.ok(databaseURL && syntheticManagementEnabled({NODE_ENV:'test',REPOSITORY_MODE:'postgres',DATABASE_URL:databaseURL}), 'Only a disposable explicit localhost *_management_test database is allowed');
assert.equal(process.env.NODE_ENV,'test');
const roots={grocery:process.env.GROCERY_CANDIDATE_ROOT,coco:process.env.COCO_CANDIDATE_ROOT,cashcast:process.env.CASHCAST_CANDIDATE_ROOT};
for(const root of Object.values(roots))assert.ok(root?.startsWith('/tmp/gama-post-v22-'),'Use the reviewed isolated product candidates');
const output=process.argv[2];assert.ok(output);
const identityBaseURL='http://127.0.0.1:3131';
const runtime=await buildRuntime(loadConfig({NODE_ENV:'test',REPOSITORY_MODE:'postgres',DATABASE_URL:databaseURL,LOG_LEVEL:'silent',PASSWORD_HASH_MEMORY_KIB:'8192',PASSWORD_HASH_ITERATIONS:'2',IDENTITY_PRODUCT_INTEGRATIONS:JSON.stringify([
 {productId:'grocery-master',integrationStatus:'gama_identity',participationRecording:'verified',evidenceReference:'synthetic-actual-product-caller',verifiedAt:new Date().toISOString()},
 {productId:'coco-the-llama',integrationStatus:'gama_identity',participationRecording:'verified',evidenceReference:'synthetic-actual-product-caller',verifiedAt:new Date().toISOString()},
 {productId:'cashcast',integrationStatus:'gama_identity',participationRecording:'verified',evidenceReference:'synthetic-actual-product-caller',verifiedAt:new Date().toISOString()},
 {productId:'synthetic-cloudkit',integrationStatus:'cloudkit_only',participationRecording:'not_applicable',evidenceReference:'synthetic-cloudkit-fixture',verifiedAt:new Date().toISOString()}
])}));
const db=new PostgresDatabase(databaseURL!),plane=new PostgresControlPlaneRepository(db),app=buildApp(runtime.services,runtime.databaseHealth);
let grocery:any,coco:any;
try {
 assert.equal((await db.query('SELECT count(*)::int AS count FROM human_identities')).rows[0]!.count,0,'Needs a fresh empty synthetic database');
 const password=`Synthetic-${randomUUID()}-123!`,secret=`Synthetic-workload-${randomUUID()}`;
 const admin=await runtime.services.register.execute({email:'admin@cross-product.invalid',password});
 await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin.humanIdentityId,'synthetic-cross-product');
 const human=await runtime.services.register.execute({email:'human-a@cross-product.invalid',password});
 const entitlementOnly=await runtime.services.register.execute({email:'entitlement-only@cross-product.invalid',password});
 await db.query('UPDATE credentials SET email_verified_at=now()');
 const hash=await new Argon2PasswordOperations({memoryCost:8192,timeCost:2,parallelism:1}).hash(secret);
 const productWorkloads={'grocery-master':'grocery-master-backend','coco-the-llama':'coco-backend',cashcast:'cashcast-preview-backend'};
 for(const [product,id] of Object.entries(productWorkloads)){
  await plane.saveProduct({id:product,displayName:`Synthetic ${product}`,status:'active'});
  await plane.saveWorkload({id,productId:product,secretHash:hash.value,status:'active'});
 }
 await plane.saveProduct({id:'synthetic-cloudkit',displayName:'Synthetic local-only product',status:'active'});
 await app.listen({host:'127.0.0.1',port:3131});
 const second=await runtime.services.login.execute({email:'human-a@cross-product.invalid',password});
 const sessions=[human.session.sessionId,second.sessionId];
 const imported=async(root:string,file:string)=>import(pathToFileURL(`${root}/${file}`).href);
 const g=await imported(roots.grocery!,'test/operational/grocery-participation-fixture.ts');
 grocery=g.createGroceryParticipationFixture({identityBaseURL,workloadID:productWorkloads['grocery-master'],workloadSecret:secret});
 const groceryResults=await g.exerciseGroceryParticipationFixture(grocery,sessions);
 assert.ok(groceryResults.every((result:{statusCode:number;reportingStatus?:string})=>result.statusCode===200 && result.reportingStatus!=='pending'));
 const {createApp}=await imported(roots.coco!,'backend/src/app.ts');
 const {CocoService}=await imported(roots.coco!,'backend/src/service.ts');
 const {InMemoryCocoRepository}=await imported(roots.coco!,'backend/src/in-memory-repository.ts');
 coco=createApp({PORT:3001,COCO_TENANT_ID:'synthetic-coco-tenant',COCO_OWNER_HUMAN_IDENTITY_ID:admin.humanIdentityId,GAMA_BASE_URL:identityBaseURL,COCO_WORKLOAD_ID:'coco-backend',COCO_WORKLOAD_SECRET:secret,FIREBASE_PROJECT_ID:'synthetic-local',FIREBASE_SERVICE_ACCOUNT_JSON:'{}',OPENAI_API_KEY:'unused-synthetic',OPENAI_TEXT_MODEL:'unused',OPENAI_IMAGE_MODEL:'unused',GENERATION_RECOVERY_ENABLED:false,COCO_IDENTITY_PARTICIPATION_ENABLED:true},new CocoService(new InMemoryCocoRepository()));
 const cocoResults=[];
 for(const bearer of [...sessions,...sessions]){
  const response=await coco.inject({method:'GET',url:'/v1/shop/cart',headers:{authorization:`Bearer ${bearer}`}});
  assert.equal(response.statusCode,200);assert.notEqual(response.headers['x-gama-participation-status'],'pending');
  cocoResults.push({status:response.statusCode,reportingStatus:response.headers['x-gama-participation-status']??'recorded_or_cached'});
 }
 const {recordCashCastWorkspaceAccess}=await imported(roots.cashcast!,'src/lib/auth/participation.ts');
 const cashcastResults=[];
 for(const bearer of [...sessions,...sessions]){
  // Use the actual central session/method/credential validation projection, not email matching.
  const response=await fetch(`${identityBaseURL}/session`,{headers:{authorization:`Bearer ${bearer}`}});assert.equal(response.status,200);
  const validated=await response.json() as {outcome:string;humanIdentityId:string;expiresAt:string};assert.equal(validated.outcome,'authenticated');assert.equal(validated.humanIdentityId,human.humanIdentityId);
  const status=await recordCashCastWorkspaceAccess({identityUrl:identityBaseURL,sessionKey:'unused-synthetic-cookie-key',providers:{},secureCookies:false},{bearer,expiresAt:validated.expiresAt},{principalId:validated.humanIdentityId,expiresAt:validated.expiresAt,emailVerified:true},{CASHCAST_IDENTITY_PARTICIPATION_ENABLED:'true',CASHCAST_PARTICIPATION_WORKLOAD_ID:productWorkloads.cashcast,CASHCAST_PARTICIPATION_WORKLOAD_SECRET:secret});
  assert.equal(status,'registered');cashcastResults.push(status);
 }
 const before=(await db.query('SELECT count(*)::int AS count FROM human_product_participations')).rows[0]!.count;
 assert.equal((await coco.inject({method:'GET',url:'/v1/shop/home'})).statusCode,200);
 assert.equal((await grocery.inject({method:'GET',url:'/v1/me/grocery-group'})).statusCode,401);
 assert.equal((await coco.inject({method:'GET',url:'/v1/shop/cart',headers:{authorization:'Bearer expired-synthetic'}})).statusCode,401);
 assert.equal((await db.query('SELECT count(*)::int AS count FROM human_product_participations')).rows[0]!.count,before);
 const security=(await db.query('SELECT (SELECT count(*)::int FROM tenant_memberships WHERE human_identity_id=$1) AS memberships,(SELECT count(*)::int FROM product_entitlements WHERE human_identity_id=$1) AS entitlements',[human.humanIdentityId])).rows[0]!;
 assert.deepEqual(security,{memberships:0,entitlements:0});
 const inspect=(path:string,payload:object)=>app.inject({method:'POST',url:path,payload,headers:{authorization:`Bearer ${admin.session.sessionId}`}});
 const associations=(await inspect('/administration/platform/humans/products/query',{humanIdentityId:human.humanIdentityId})).json();
 assert.equal(associations.products.length,3);assert.equal(associations.nextCursor,null);
 const reverse=[];
 for(const productId of Object.keys(productWorkloads)){
  const response=await inspect('/administration/platform/products/humans/query',{productId});assert.equal(response.statusCode,200);assert.deepEqual(response.json().humans.map((h:{humanIdentityId:string})=>h.humanIdentityId),[human.humanIdentityId]);reverse.push({productId,count:response.json().humans.length});
 }
 await plane.saveTenant({id:'synthetic-independent-business',displayName:'Independent synthetic business',status:'active'});
 await plane.saveMembership({tenantId:'synthetic-independent-business',humanIdentityId:entitlementOnly.humanIdentityId,tenantRole:'staff',status:'active',createdAt:new Date(),updatedAt:new Date()});
 await plane.saveParticipation({tenantId:'synthetic-independent-business',productId:'cashcast',status:'active'});
 await plane.saveEntitlement({tenantId:'synthetic-independent-business',productId:'cashcast',humanIdentityId:entitlementOnly.humanIdentityId,status:'active'});
 assert.equal((await inspect('/administration/platform/humans/products/query',{humanIdentityId:entitlementOnly.humanIdentityId})).json().products.length,0);
 // Removing an independent entitlement cannot erase another participation/history.
 await plane.saveMembership({tenantId:'synthetic-independent-business',humanIdentityId:human.humanIdentityId,tenantRole:'staff',status:'active',createdAt:new Date(),updatedAt:new Date()});
 await plane.saveEntitlement({tenantId:'synthetic-independent-business',productId:'cashcast',humanIdentityId:human.humanIdentityId,status:'active'});
 await db.query('DELETE FROM product_entitlements WHERE human_identity_id=$1',[human.humanIdentityId]);
 assert.equal((await db.query('SELECT count(*)::int AS count FROM human_product_participations WHERE human_identity_id=$1',[human.humanIdentityId])).rows[0]!.count,3);
 const products=(await inspect('/administration/platform/products/inspect',{})).json().products;
 assert.equal(products.find((p:{id:string})=>p.id==='synthetic-cloudkit').participants,0);
 const evidence={demonstration:'A',result:'passed',timestamp:new Date().toISOString(),productionActions:false,environment:'isolated synthetic PostgreSQL18 + real HTTPIdentity + actual product callers',providerCoverage:'Actual Email/Password login against synthetic Humans; no live Apple/Google',productStoreCoverage:'Grocery and Coco use explicitly in-memory product stores for hook demonstration; separately populated PG/Firestore inspection evidence exists. CashCast inspected implementation has fictional in-memory financial presentation.',canonicalHuman:human.humanIdentityId,canonicalHumanCount:1,authenticationCreatedExtraHuman:false,participationRows:3,grocery:groceryResults,coco:cocoResults,cashcast:cashcastResults,noAnonymousOrExpiredAssociation:true,securityBeforeIndependentFixture:security,pagination:{threeAssociationsInOnePage:true,boundedCursorCoverage:'complete PostgreSQL regression suite separately tests page boundaries, scope binding and invalid cursors'},productToHumans:reverse,entitlementRemovalPreservedParticipation:true,entitlementAndMembershipOnlyHumanHasNoParticipation:true,unintegratedProductNoArtificialHumans:true,productCounts:products.map((p:{id:string;participants:number;entitledHumans:number;integrationStatus:string})=>({productId:p.id,participants:p.participants,entitledHumans:p.entitledHumans,integrationStatus:p.integrationStatus})),audits:(await db.query("SELECT event_type,count(*)::int AS count FROM platform_audit_events WHERE event_type='human.product.participation.registered' GROUP BY event_type")).rows};
 await writeFile(output,JSON.stringify(evidence,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({result:evidence.result,participationRows:3,actualProductCallers:['Grocery protected route','Coco protected customer route','CashCast trusted workspace hook'],output}));
} finally {await grocery?.close();await coco?.close();await app.close();await runtime.close();await db.close();}
