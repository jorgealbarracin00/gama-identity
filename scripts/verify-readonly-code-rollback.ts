// Code compatibility only: a synthetic database; never a production restore.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {PostgresDatabase} from '../src/infrastructure/postgres/database.js';
import {syntheticManagementEnabled} from '../src/control-plane/application/identity-management.js';
import {buildRuntime,type ApplicationRuntime} from '../src/api/services.js';
import {buildApp} from '../src/api/app.js';
import {loadConfig} from '../src/config/env.js';
const url=process.env.POSTGRES_CODE_ROLLBACK_DATABASE_URL;
assert.ok(url && syntheticManagementEnabled({NODE_ENV:'test',REPOSITORY_MODE:'postgres',DATABASE_URL:url}));
assert.equal(new URL(url!).pathname,'/gama_post_v22_recoverydemo_management_test');
const baseline=process.env.IDENTITY_ROLLBACK_BASELINE_ROOT;
assert.equal(baseline,'/tmp/gama-v22-backend');
const db=new PostgresDatabase(url!);
const tables=['human_identities','credentials','federated_identities','sessions','tenant_memberships','platform_administration_memberships','product_entitlements','human_profiles','human_product_participations','human_purposes','identity_management_cases','identity_management_control_proofs','identity_management_operations','identity_recovery_compensations','identity_management_google_handoffs','platform_audit_events'];
const snapshot=async()=>{
 const values=[];
 for(const table of tables){const data=(await db.query(`SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text AS data FROM ${table} t`)).rows[0]!.data;values.push({table,sha256:createHash('sha256').update(data).digest('hex')});}
 return values;
};
try {
 const before=await snapshot();
 const previous=await import(pathToFileURL(`${baseline}/src/api/services.ts`).href);
 const oldConfig=await import(pathToFileURL(`${baseline}/src/config/env.ts`).href);
 const previousApp=await import(pathToFileURL(`${baseline}/src/api/app.ts`).href);
 const results=[];
 for(const [revision,makeRuntime,configLoader,makeApp] of [['1c8655dc24bce684bddd1b1dbd5e22a6788fc863',previous.buildRuntime,oldConfig.loadConfig,previousApp.buildApp],['reviewed-candidate',buildRuntime,loadConfig,buildApp]] as const){
  const runtime:ApplicationRuntime=await makeRuntime(configLoader({NODE_ENV:'production',REPOSITORY_MODE:'postgres',DATABASE_URL:url,LOG_LEVEL:'silent',DATABASE_SSL_REQUIRED:'false'}));
  const app=makeApp(runtime.services,runtime.databaseHealth);
  try {
   assert.ok(runtime.services.administration.identityManagement);
   assert.ok(runtime.services.administration.googleRecoveryHandoff);
   assert.equal(runtime.services.administration.identityManagement.executionEnabled,false);
   if(revision==='reviewed-candidate')assert.deepEqual(await runtime.services.administration.googleRecoveryHandoff.expireAbandoned(),{enabled:false,expired:0});
   const health=await app.inject({method:'GET',url:'/health'});assert.equal(health.statusCode,200);assert.equal(health.json().database.status,'connected');
   const denied=await app.inject({method:'POST',url:'/administration/platform/identity-management/recovery/google/start',payload:{}});assert.equal(denied.statusCode,401);
   assert.deepEqual(await snapshot(),before);
   results.push({revision,health:200,missingAdministrator:401,executionEnabled:false,all16ProtectedProjectionsUnchanged:true});
  } finally {await app.close();await runtime.close();}
 }
 const migrations=(await db.query('SELECT version,checksum FROM schema_migrations ORDER BY version')).rows;assert.equal(migrations.length,16);
 for(const migration of migrations){
  const {readdir}=await import('node:fs/promises');const file=(await readdir('migrations')).find(file=>file.startsWith(migration.version+'_'))!;
  const current:Buffer=await readFile(`migrations/${file}`),old:Buffer=await readFile(`${baseline}/migrations/${file}`);assert.deepEqual(current,old);assert.equal(createHash('sha256').update(current).digest('hex'),migration.checksum);
 }
 await writeFile(process.argv[2]!,JSON.stringify({timestamp:new Date().toISOString(),environment:'isolated synthetic PostgreSQL18',productionActions:false,mode:'production-config logic against guarded synthetic local database',results,migrations,protectedTableFingerprints:before,newMigrations:0,destructiveMigrations:false,codeRollbackCompatible:true,ownershipRollbackGuaranteed:false},null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({codeRollbackCompatible:true,newMigrations:0,protectedProjections:16}));
}finally{await db.close();}
