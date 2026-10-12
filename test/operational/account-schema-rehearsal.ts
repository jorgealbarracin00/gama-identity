// Local synthetic-only migration/revert rehearsal. Never a production runner.
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {buildRuntime} from '../../src/api/services.js';
import {loadConfig} from '../../src/config/env.js';
import {PostgresDatabase} from '../../src/infrastructure/postgres/database.js';
import {runMigrations} from '../../src/infrastructure/postgres/migrations.js';
import {buildApp} from '../../src/api/app.js';
const url='postgresql://account_test@127.0.0.1:55471/gama_account_schema_management_test';
const baselinePath='/private/tmp/gama-post-v22-workload/src/api/services.ts';
const baseline=await import(baselinePath);
const currentDirectory=process.cwd();process.chdir('/private/tmp/gama-post-v22-workload');
const original=await baseline.buildRuntime(loadConfig({NODE_ENV:'development',REPOSITORY_MODE:'postgres',DATABASE_URL:url,LOG_LEVEL:'silent'}));
const a=await original.services.register.execute({email:'rehearsal@synthetic.example',password:'Synthetic-rehearsal-password-123!'});
const b=await original.services.register.execute({email:'rehearsal-source@synthetic.example',password:'Synthetic-rehearsal-password-123!'});
await original.close();process.chdir(currentDirectory);
const db=new PostgresDatabase(url);
// Populate the CHECK/default boundaries before migration018, rather than only
// testing empty metadata tables. This is synthetic fixture data, never a backfill.
const legacyCase=randomUUID();
await db.query("INSERT INTO identity_management_cases(id,actor_human_identity_id,source_human_identity_id,target_human_identity_id,provider,nonce,state,created_at,expires_at) VALUES($1,$2,$3,$2,'google','synthetic-historical-nonce','awaiting_proof',now(),now()+interval '15 minutes')",[legacyCase,a.humanIdentityId,b.humanIdentityId]);
await db.query("INSERT INTO email_action_challenges(id,credential_id,app_id,purpose,token_hash,created_at,expires_at) SELECT 'synthetic-historical-email',id,'gama','reset_password',$2,now(),now()+interval '15 minutes' FROM credentials WHERE human_identity_id=$1",[a.humanIdentityId,'s'.repeat(43)]);
await db.query("INSERT INTO registered_products(id,display_name,status) VALUES('synthetic-historical-product','Synthetic historical product','active')");
await db.query("INSERT INTO managed_product_workloads(id,product_id,secret_hash,status,revision,capabilities,created_at,updated_at) VALUES('synthetic-historical-workload','synthetic-historical-product','synthetic-nonauthenticating-placeholder','active',1,ARRAY['workload.context.read','human.participation.register'],now(),now())");
await db.query("INSERT INTO human_product_participations(human_identity_id,product_id,managed_workload_id,status,created_at,updated_at) VALUES($1,'synthetic-historical-product','synthetic-historical-workload','active',now(),now())",[a.humanIdentityId]);
const quote=(s:string)=>'"'+s.replaceAll('"','""')+'"';
const columns=(await db.query<{table_name:string,column_name:string}>('SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=\'public\' AND table_name<>\'schema_migrations\' ORDER BY table_name,ordinal_position')).rows;
const tables=new Map<string,string[]>();for(const c of columns)tables.set(c.table_name,[...(tables.get(c.table_name)??[]),c.column_name]);
const fingerprint=async()=>{
 const hashes:Record<string,string>={};
 for(const [table,cols]of tables){const rows=(await db.query(`SELECT ${cols.map(quote).join(',')} FROM ${quote(table)}`)).rows;const values=rows.map(r=>JSON.stringify(cols.map(c=>r[c]))).sort();hashes[table]=createHash('sha256').update(JSON.stringify(values)).digest('hex');}return hashes;
};
const schema=async()=>({constraints:(await db.query<{table_name:string,name:string,type:string,definition:string}>("SELECT c.conrelid::regclass::text table_name,c.conname name,c.contype type,pg_get_constraintdef(c.oid) definition FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public' ORDER BY table_name,name")).rows,indexes:(await db.query("SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY tablename,indexname")).rows});
const before=await fingerprint(),old=await schema();
const allowed=new Set(['email_action_challenges.email_action_challenges_purpose_check','managed_product_workloads.managed_product_workloads_capabilities_check']);
for(const key of allowed){const c=old.constraints.find(c=>`${c.table_name}.${c.name}`===key);assert.ok(c);assert.equal(c.type,'c');assert.ok(c.definition.startsWith('CHECK ('));assert.ok(!c.definition.includes('link_email')&&!c.definition.includes('human.data.cleanup'));}
await runMigrations(db);assert.deepEqual(await fingerprint(),before);assert.equal((await db.query('SELECT transfer_policy FROM identity_management_cases WHERE id=$1',[legacyCase])).rows[0]!.transfer_policy,'verified_empty_source');const next=await schema();
for(const c of old.constraints){const key=`${c.table_name}.${c.name}`,n=next.constraints.find(n=>n.table_name===c.table_name&&n.name===c.name);assert.ok(n,`Removed constraint ${key}`);if(allowed.has(key)){assert.equal(n.type,c.type);assert.ok(n.definition.includes(key.startsWith('email_')?'link_email':'human.data.cleanup'));}else assert.deepEqual(n,c,`Changed constraint ${key}`);}
for(const index of old.indexes)assert.deepEqual(next.indexes.find(n=>n.tablename===index.tablename&&n.indexname===index.indexname),index);
assert.ok(next.constraints.some(c=>c.table_name==='identity_management_cases'&&c.type==='c'&&c.definition.includes('transfer_policy')&&c.definition.includes('retain_records')));
const sql=await readFile('migrations/018_account_management.sql','utf8');await db.withTransaction(()=>db.query(sql));await runMigrations(db);assert.deepEqual(await fingerprint(),before);assert.deepEqual(await schema(),next);
const current=await buildRuntime(loadConfig({NODE_ENV:'development',REPOSITORY_MODE:'postgres',DATABASE_URL:url,LOG_LEVEL:'silent'}));const app=buildApp(current.services,current.databaseHealth);
assert.equal((await app.inject({method:'GET',url:'/health'})).statusCode,200);await app.close();await current.close();assert.deepEqual(await fingerprint(),before);
for(const path of ['/private/tmp/gama-post-v22-workload/src/api/services.ts','/private/tmp/gama-account-safety-rollback/src/api/services.ts']){
 const candidate=await import(path);process.chdir(path.slice(0,-"/src/api/services.ts".length));const runtime=await candidate.buildRuntime(loadConfig({NODE_ENV:'development',REPOSITORY_MODE:'postgres',DATABASE_URL:url,LOG_LEVEL:'silent'}));
 assert.equal((await runtime.services.login.execute({email:'rehearsal@synthetic.example',password:'Synthetic-rehearsal-password-123!'})).humanIdentityId,a.humanIdentityId);await runtime.close();process.chdir(currentDirectory);
}
console.log(JSON.stringify({status:'PASS',priorColumns:columns.length,priorTables:tables.size,priorConstraints:old.constraints.length,priorIndexes:old.indexes.length,allPriorColumnsPreserved:true,allPriorIndexesPreserved:true,intentionalCheckExpansions:[...allowed],idempotence:true,currentRuntime:true,predecessor44Compatibility:true,safetyRollbackCompatibility:true,noProductionAccess:true}));
await db.close();
