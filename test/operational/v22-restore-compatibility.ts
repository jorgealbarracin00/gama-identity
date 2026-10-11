// Stream-restored encrypted historical snapshot; no production connection or owner credentials.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {PostgresDatabase} from '../../src/infrastructure/postgres/database.js';
import {runMigrations} from '../../src/infrastructure/postgres/migrations.js';
import {loadConfig} from '../../src/config/env.js';
const url='postgresql:///gama_v22_restore_readonly?host=/tmp/gama-v22-backup-restore/socket&port=55443';
const db=new PostgresDatabase(url);
const tables=['human_identities','credentials','federated_identities','sessions','tenant_memberships','platform_administration_memberships','product_entitlements','human_product_participations','platform_audit_events','human_profiles','identity_recovery_requests','google_identity_verification_cases'];
async function projections(){const values:Record<string,string>={};for(const table of tables){const r=await db.query(`SELECT coalesce(jsonb_agg(value ORDER BY value::text),'[]'::jsonb) AS value FROM (SELECT to_jsonb(t)-'write_revision'-'authentication_method' AS value FROM ${table} t) x`);values[table]=createHash('sha256').update(JSON.stringify(r.rows[0]!.value)).digest('hex');}return values;}
try{
 const before=await projections();await runMigrations(db);const after=await projections();assert.deepEqual(after,before);await runMigrations(db);
 const versions=(await db.query('SELECT version FROM schema_migrations ORDER BY version')).rows.map(r=>r.version);assert.equal(versions.length,16);
 assert.equal((await db.query('SELECT 1 FROM sessions WHERE authentication_method IS NOT NULL')).rowCount,0);
 const config=loadConfig({NODE_ENV:'production',REPOSITORY_MODE:'postgres',DATABASE_URL:url,LOG_LEVEL:'silent'});
 const baselineRoot=new URL('file:///tmp/gama-console-v21-backend/');
 const {buildRuntime:baselineRuntime}=await import(new URL('src/api/services.ts',baselineRoot).href);
 const {buildApp:baselineApp}=await import(new URL('src/api/app.ts',baselineRoot).href);
 const baseline=await baselineRuntime(config),app=baselineApp(baseline.services,baseline.databaseHealth);
 try{assert.equal((await app.inject({method:'GET',url:'/health'})).statusCode,200);assert.equal(baseline.services.administration.identityManagement?.executionEnabled,false);
 assert.equal((await app.inject({method:'POST',url:'/administration/platform/identity-management/recovery/native-prove',payload:{}})).statusCode,404);
 assert.equal((await app.inject({method:'POST',url:'/administration/platform/overview',payload:{}})).statusCode,401);
 }finally{await app.close();await baseline.close();}
 assert.deepEqual(await projections(),before);
 const report={verifiedAt:new Date().toISOString(),environment:'private isolated PostgreSQL18 encrypted-snapshot restore; not production',snapshotTimestamp:'2026-10-11T11:31:50.365Z',versions,additiveMigrations:['014','015','016'],migrationIdempotence:'passed',existingCriticalProjections:'unchanged',existingSessionsNotAttributedOrRevoked:true,baselineRevision:'e6fe97ea9a31d5e4aff5738cd731e0bf99498b96',baselineHealth:true,baselinePermissionDenial:true,newRoutesAbsentOnRollback:true,productionMutationGatesDisabled:true,destructiveRollback:false,currentCheckpointBeforeDeploymentRequired:true};
 writeFileSync(process.argv[2]!,JSON.stringify(report,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(report));
}finally{await db.close();}
