import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { buildRuntime } from "../src/api/services.js";
import { buildApp } from "../src/api/app.js";
import { loadConfig } from "../src/config/env.js";
import { PostgresDatabase } from "../src/infrastructure/postgres/database.js";
import { PostgresControlPlaneRepository } from "../src/infrastructure/postgres/postgres-control-plane-repository.js";
import { Argon2PasswordOperations } from "../src/authentication/adapters/argon2-password-operations.js";
import { syntheticManagementEnabled } from "../src/control-plane/application/identity-management.js";

const url=process.env.POSTGRES_PARTICIPATION_DEMO_DATABASE_URL;
assert.ok(url&&syntheticManagementEnabled({NODE_ENV:"test",REPOSITORY_MODE:"postgres",DATABASE_URL:url}),"Use a separate localhost *_management_test database containing only synthetic fixtures");
const output=process.argv[2];
assert.ok(output,"Pass a JSON evidence output filename");
const config=loadConfig({NODE_ENV:"test",REPOSITORY_MODE:"postgres",DATABASE_URL:url,LOG_LEVEL:"silent",PASSWORD_HASH_MEMORY_KIB:"8192",PASSWORD_HASH_ITERATIONS:"2",IDENTITY_PRODUCT_INTEGRATIONS:JSON.stringify([{productId:"synthetic-cloudkit-product",integrationStatus:"cloudkit_only",participationRecording:"not_applicable",evidenceReference:"synthetic-only-source-fixture",verifiedAt:new Date().toISOString()}])});
const runtime=await buildRuntime(config),db=new PostgresDatabase(url!),plane=new PostgresControlPlaneRepository(db),app=buildApp(runtime.services,runtime.databaseHealth);
try {
  assert.equal((await db.query("SELECT count(*)::int AS count FROM human_identities")).rows[0]!.count,0,"Demo refuses a database containing existing Humans");
  const password=`Synthetic-${randomUUID()}-123!`,secret=`Synthetic-product-reporter-${randomUUID()}`;
  const admin=await runtime.services.register.execute({email:"administrator@synthetic-participation.example",password});
  await runtime.platformAdministrationProvisioning.bootstrapAdministrator(admin.humanIdentityId,"synthetic-demo-A");
  const human=await runtime.services.register.execute({email:"human-a@synthetic-participation.example",password});
  const entitlementOnly=await runtime.services.register.execute({email:"entitlement-only@synthetic-participation.example",password});
  const hash=(await new Argon2PasswordOperations({memoryCost:8192,timeCost:2,parallelism:1}).hash(secret)).value;
  const products=["grocery-master","coco-the-llama","cashcast"],stages=[];
  for(const product of [...products,"synthetic-cloudkit-product"])await plane.saveProduct({id:product,displayName:`Synthetic ${product}`,status:"active"});
  for(const product of products) {
    await plane.saveWorkload({id:`synthetic-${product}-reporter`,productId:product,secretHash:hash,status:"active"});
    const login=await runtime.services.login.execute({email:"human-a@synthetic-participation.example",password});
    const request=()=>app.inject({method:"POST",url:"/control/human-participation",payload:{},headers:{authorization:`Bearer ${login.sessionId}`,"x-gama-workload-id":`synthetic-${product}-reporter`,"x-gama-workload-secret":secret}});
    const first=await request(),repeat=await request();assert.equal(first.statusCode,200);assert.equal(repeat.statusCode,200);assert.equal(first.json().created,true);assert.equal(repeat.json().created,false);assert.equal(first.json().humanIdentityId,human.humanIdentityId);
    stages.push({productId:product,canonicalHumanPreserved:true,firstCreated:first.json().created,repeatedCreated:repeat.json().created});
  }
  await plane.saveTenant({id:"synthetic-business",displayName:"Synthetic business",status:"active"});
  await plane.saveParticipation({tenantId:"synthetic-business",productId:"cashcast",status:"active"});
  await plane.saveMembership({tenantId:"synthetic-business",humanIdentityId:entitlementOnly.humanIdentityId,tenantRole:"staff",status:"active",createdAt:new Date(),updatedAt:new Date()});
  await plane.saveEntitlement({tenantId:"synthetic-business",productId:"cashcast",humanIdentityId:entitlementOnly.humanIdentityId,status:"active"});
  const inspect=(path:string,payload:Record<string,unknown>)=>app.inject({method:"POST",url:path,payload,headers:{authorization:`Bearer ${admin.session.sessionId}`}});
  const h=await inspect("/administration/platform/humans/products/query",{humanIdentityId:human.humanIdentityId});assert.equal(h.statusCode,200);assert.equal(h.json().products.length,3);
  const entitlementRelationships=await inspect("/administration/platform/humans/products/query",{humanIdentityId:entitlementOnly.humanIdentityId});assert.equal(entitlementRelationships.json().products.length,0);
  const counts=(await inspect("/administration/platform/products/inspect",{})).json().products;
  const productHumans=[];
  for(const product of products){const p=await inspect("/administration/platform/products/humans/query",{productId:product});assert.deepEqual(p.json().humans.map((x:{humanIdentityId:string})=>x.humanIdentityId),[human.humanIdentityId]);productHumans.push({productId:product,humanIds:p.json().humans.map((x:{humanIdentityId:string})=>x.humanIdentityId)});}
  const rowCount=(await db.query("SELECT count(*)::int AS count FROM human_product_participations WHERE human_identity_id=$1",[human.humanIdentityId])).rows[0]!.count;
  const securityCounts=(await db.query("SELECT (SELECT count(*)::int FROM tenant_memberships WHERE human_identity_id=$1) AS memberships,(SELECT count(*)::int FROM product_entitlements WHERE human_identity_id=$1) AS entitlements",[human.humanIdentityId])).rows[0]!;
  assert.equal(rowCount,3);assert.equal(securityCounts.memberships,0);assert.equal(securityCounts.entitlements,0);
  const audit=(await db.query("SELECT event_type AS event,count(*)::int AS count FROM platform_audit_events WHERE event_type IN ('human.product.participation.registered','platform.product.humans.inspected','platform.human.products.inspected') GROUP BY event_type ORDER BY event_type")).rows;
  const result={demonstration:"A",timestamp:new Date().toISOString(),environment:"isolated_synthetic_localhost",productionActions:false,providerCoverage:"Real GAMA Email/Password login against synthetic identities; no live federated provider used",humanA:human.humanIdentityId,stages,canonicalHumanCount:1,participationRows:rowCount,securityCounts,consoleHumanProducts:h.json(),consoleProductHumans:productHumans,productCounts:counts.map((p:{id:string;participants:number;entitledHumans:number;integrationStatus:string})=>({id:p.id,participants:p.participants,entitledHumans:p.entitledHumans,integrationStatus:p.integrationStatus})),entitlementAndMembershipWithoutParticipationConfirmed:true,unintegratedProductHasNoArtificialHuman:true,audit,result:"passed"};
  await writeFile(output,JSON.stringify(result,null,2)+"\n",{mode:0o600});
  process.stdout.write(JSON.stringify({result:"passed",humanA:human.humanIdentityId,participationRows:rowCount,securityCounts,output})+"\n");
}finally{await app.close();await runtime.close();await db.close();}
