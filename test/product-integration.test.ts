import assert from 'node:assert/strict';
import {describe,it} from 'node:test';
import {randomUUID,randomBytes} from 'node:crypto';
import {ProductPersonalCleanupWorker,type PersonalCleanupTask} from '../src/product-integration/account-cleanup.js';
import {PromotionalEligibilityBoundary,type PromotionalEligibilityRecord} from '../src/product-integration/promotional-eligibility.js';
import {SerialExecutor} from '../src/shared/serial-executor.js';
describe('Optional product integration and transaction serialisation',()=>{
 it('Demo E: deletes only selected personal data, preserving unrelated customers and shared assets',async()=>{
  const task:PersonalCleanupTask={id:randomUUID(),humanIdentityId:'synthetic-departing',productId:'synthetic-product',revision:1,scope:'eligible_personal_data',preserveSharedAssets:true,preservePromotionalEligibility:true};
  const personal=new Map([['synthetic-departing',['one','two']],['synthetic-unrelated',['private-other']]]),shared=['catalogue','200-synthetic-photo-references'];const before=[...shared];const receipts:unknown[]=[];
  const worker=new ProductPersonalCleanupWorker('synthetic-product',{claim:async()=>({tasks:[task]}),complete:async receipt=>{receipts.push(receipt);}},{cleanup:async t=>{const n=personal.get(t.humanIdentityId)?.length??0;personal.delete(t.humanIdentityId);return {state:'completed',deletedRecords:n,retainedRecords:0};}});
  assert.equal((await worker.runOnce()).processed,1);assert.equal(personal.has(task.humanIdentityId),false);assert.deepEqual(personal.get('synthetic-unrelated'),['private-other']);assert.deepEqual(shared,before);assert.equal((receipts[0]as any).deletedRecords,2);
 });
 it('validates every task before cleanup, rejects cross-product and unsafe batch scopes',async()=>{
  let mutated=0;const task={id:randomUUID(),humanIdentityId:'synthetic',productId:'other-product',revision:1,scope:'eligible_personal_data',preserveSharedAssets:true,preservePromotionalEligibility:true}as const;
  const worker=new ProductPersonalCleanupWorker('synthetic-product',{claim:async()=>({tasks:[task]}),complete:async()=>{}},{cleanup:async()=>{mutated++;return {state:'completed',deletedRecords:1,retainedRecords:0};}});
  await assert.rejects(()=>worker.runOnce(),/scope/);assert.equal(mutated,0);
 });
 it('adapter failure is acknowledged as failed; unacknowledged receipts are not reported as completed',async()=>{
  const task={id:randomUUID(),humanIdentityId:'synthetic',productId:'synthetic-product',revision:1,scope:'eligible_personal_data',preserveSharedAssets:true,preservePromotionalEligibility:true}as const;let state='';
  const worker=new ProductPersonalCleanupWorker('synthetic-product',{claim:async()=>({tasks:[task]}),complete:async r=>{state=r.state;throw new Error('synthetic acknowledgement failed');}},{cleanup:async()=>{throw new Error('private-data-must-not-escape');}});
  await assert.rejects(()=>worker.runOnce(),/acknowledgement/);assert.equal(state,'failed');
 });
 it('Demo F: returning account cannot reset product-specific redeemed eligibility; expiry allows policy choice',async()=>{
  const rows=new Map<string,PromotionalEligibilityRecord>();const opaque:string[]=[];
  const store={find:async(p:string,b:string,k:string)=>rows.get(`${p}:${b}:${k}`)??null,redeem:async(p:string,b:string,k:string,r:PromotionalEligibilityRecord,now:Date)=>{opaque.push(k);const key=`${p}:${b}:${k}`,old=rows.get(key);if(old&&old.expiresAt>now)return false;rows.set(key,r);return true;}};
  const key=randomBytes(32),policy={reference:'synthetic-lawful-policy-30-days',retentionDays:30};const product=new PromotionalEligibilityBoundary('synthetic-product',key,store,policy),now=new Date();
  assert.equal(await product.redeem('ten-day-trial','google','synthetic-verified-subject',now),true);
  // Account deletion is intentionally absent from this independent policy store.
  assert.equal(await product.eligible('ten-day-trial','google','synthetic-verified-subject',now),false);assert.equal(await product.redeem('ten-day-trial','google','synthetic-verified-subject',now),false);
  assert.equal(await new PromotionalEligibilityBoundary('different-product',key,store,policy).eligible('ten-day-trial','google','synthetic-verified-subject',now),true);
  assert.equal(await product.eligible('ten-day-trial','google','synthetic-verified-subject',new Date(now.getTime()+31*86400000)),true);assert.ok(opaque.every(k=>/^[a-f0-9]{64}$/.test(k)));assert.ok(!JSON.stringify([...rows]).includes('synthetic-verified-subject'));
 });
 it('nested transaction work is reentrant while unrelated callers remain serial',async()=>{
  const serial=new SerialExecutor(),order:string[]=[];let release!:()=>void;
  const first=serial.execute(async()=>{order.push('outer');await serial.execute(async()=>{order.push('inner');});await new Promise<void>(resolve=>release=resolve);order.push('finished');});
  while(!release)await new Promise(r=>setImmediate(r));const second=serial.execute(async()=>{order.push('second');});assert.deepEqual(order,['outer','inner']);release();await Promise.all([first,second]);assert.deepEqual(order,['outer','inner','finished','second']);
 });
 it('escaped async transaction context cannot bypass a later transaction',async()=>{
  const serial=new SerialExecutor(),order:string[]=[];let delayed!:()=>Promise<void>,release!:()=>void;
  await serial.execute(async()=>{delayed=()=>serial.execute(async()=>{order.push('delayed');});});
  const first=serial.execute(async()=>{order.push('new');await new Promise<void>(resolve=>release=resolve);});while(!release)await new Promise(r=>setImmediate(r));const next=delayed();await new Promise(r=>setImmediate(r));assert.deepEqual(order,['new']);release();await Promise.all([first,next]);assert.deepEqual(order,['new','delayed']);
 });
});
