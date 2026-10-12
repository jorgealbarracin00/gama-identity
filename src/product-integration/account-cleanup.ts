/** Optional server-side integration. No native workload credentials or product adoption. */
export interface PersonalCleanupTask {
 readonly id:string; readonly humanIdentityId:string; readonly productId:string; readonly revision:number;
 readonly scope:'eligible_personal_data'; readonly preserveSharedAssets:true; readonly preservePromotionalEligibility:true;
}
export interface CleanupOutcome {readonly state:'completed'|'unsupported'|'failed'; readonly deletedRecords:number; readonly retainedRecords:number}
export interface ProductPersonalDataAdapter {
 /** Must be idempotent by task ID across crashes/reclaims. Scope by canonical Human,
  * preserve shared resources and lawfully retained policy records. Unsupported
  * dependencies must return unsupported, never a falsely completed response. */
 cleanup(task:PersonalCleanupTask):Promise<CleanupOutcome>;
}
export interface CleanupTransport {
 claim():Promise<{tasks:PersonalCleanupTask[]}>;
 complete(receipt:{id:string;revision:number}&CleanupOutcome):Promise<unknown>;
}
export class ProductPersonalCleanupWorker {
 constructor(private readonly productId:string,private readonly transport:CleanupTransport,private readonly adapter:ProductPersonalDataAdapter){}
 async runOnce():Promise<{processed:number}> {
  const response=await this.transport.claim();
  if(!Array.isArray(response.tasks)||response.tasks.length>10)throw new Error('Invalid cleanup batch');
  const seen=new Set<string>();
  // Validate the whole batch before any product-side mutation.
  for(const t of response.tasks){
   if(!t||t.productId!==this.productId||!t.humanIdentityId||t.humanIdentityId.length>200||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(t.id)||!Number.isSafeInteger(t.revision)||t.revision<1||t.scope!=='eligible_personal_data'||t.preserveSharedAssets!==true||t.preservePromotionalEligibility!==true||seen.has(t.id))throw new Error('Invalid product cleanup scope');
   seen.add(t.id);
  }
  let processed=0;
  for(const t of response.tasks){
   let outcome:CleanupOutcome;
   try{outcome=await this.adapter.cleanup(t);}catch{outcome={state:'failed',deletedRecords:0,retainedRecords:0};}
   if(!['completed','unsupported','failed'].includes(outcome.state)||![outcome.deletedRecords,outcome.retainedRecords].every(n=>Number.isSafeInteger(n)&&n>=0&&n<=2147483647))throw new Error('Invalid cleanup outcome');
   await this.transport.complete({id:t.id,revision:t.revision,...outcome});processed++;
  }return {processed};
 }
}
