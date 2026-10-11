// Isolated synthetic compatibility check; never accepts a production URL or real credentials.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {Pool} from 'pg';
import {buildRuntime as candidateRuntime} from '../../src/api/services.js';
import {loadConfig} from '../../src/config/env.js';
import {SessionId} from '../../src/sessions/domain/session-id.js';
const baselineRoot = new URL('file:///tmp/gama-console-v21-rollback-baseline/');
const {buildRuntime: baselineRuntime} = await import(new URL('src/api/services.ts', baselineRoot).href);
const {buildApp} = await import(new URL('src/api/app.ts', baselineRoot).href);
const url='postgresql://127.0.0.1:55439/gama_v21_rollback_check_test';
const pool=new Pool({connectionString:'postgresql://127.0.0.1:55439/postgres'});
try {await pool.query('CREATE DATABASE gama_v21_rollback_check_test');} catch(e) {if((e as {code?:string}).code!=='42P04')throw e;} finally {await pool.end();}
const config=loadConfig({NODE_ENV:'test',REPOSITORY_MODE:'postgres',DATABASE_URL:url,LOG_LEVEL:'silent'});
const candidate=await candidateRuntime(config);
let initial,customer;
try {
 initial=await candidate.services.register.execute({email:'rollback-admin@fixture.example',password:'Synthetic-rollback-password-123!'});
 customer=await candidate.services.register.execute({email:'rollback-customer@fixture.example',password:'Synthetic-rollback-password-123!'});
 await candidate.platformAdministrationProvisioning.bootstrapAdministrator(initial.humanIdentityId,'synthetic-rollback-check');
} finally {await candidate.close();}
const baseline=await baselineRuntime(config);
const app=buildApp(baseline.services,baseline.databaseHealth);
let baselineClosed=false;
try {
 const checked=await baseline.services.validateSession.execute(SessionId.from(initial.session.sessionId));
 assert.equal(checked.outcome,'authenticated');
 const response=await app.inject({method:'POST',url:'/administration/platform/overview',headers:{authorization:`Bearer ${initial.session.sessionId}`},payload:{}});
 assert.equal(response.statusCode,200);
 const denied=await app.inject({method:'POST',url:'/administration/platform/overview',headers:{authorization:`Bearer ${customer.session.sessionId}`},payload:{}});
 assert.equal(denied.statusCode,403);
 const absent=await app.inject({method:'POST',url:'/administration/platform/identity-management/inspect',headers:{authorization:`Bearer ${initial.session.sessionId}`},payload:{humanIdentityId:customer.humanIdentityId}});
 assert.equal(absent.statusCode,404);
 const renewed=await baseline.services.renewSession.execute(initial.session.renewalToken);
 assert.equal(renewed.authenticatedAt,initial.session.authenticatedAt);
 const login=await baseline.services.login.execute({email:'rollback-admin@fixture.example',password:'Synthetic-rollback-password-123!'});
 assert.equal(login.humanIdentityId,initial.humanIdentityId);
 await app.close();await baseline.close();baselineClosed=true;
 const again=await candidateRuntime(config);
 try {assert.equal((await again.services.validateSession.execute(SessionId.from(renewed.sessionId))).outcome,'authenticated');}finally{await again.close();}
 const report={checkedAt:new Date().toISOString(),environment:'isolated synthetic PostgreSQL',baselineRevision:'b6609bd7bcbdd40c4f7557cd5c2c4ea5e04a0c33',retainedSchema:'001-014',candidateSessionAcceptedByBaseline:true,baselineSessionAcceptedByCandidate:true,emailLoginAndRenewal:true,renewalDoesNotResetStepUp:true,administratorOverview:true,ordinaryHumanDenied:true,newRoutesAbsentOnRollback:true,destructiveRollback:false};
 writeFileSync(process.argv[2]!,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{if(!baselineClosed){await app.close();await baseline.close();}}
