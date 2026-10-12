import {createHmac} from 'node:crypto';
/** Optional product-policy boundary, independent of Human/account deletion. */
export interface PromotionalEligibilityRecord {readonly redeemedAt:Date;readonly expiresAt:Date;readonly retentionPolicyReference:string}
export interface PromotionalEligibilityStore {
 find(product:string,benefit:string,opaqueKey:string):Promise<PromotionalEligibilityRecord|null>;
 /** Atomic put-if-absent; a valid unexpired redemption must win concurrent attempts. */
 redeem(product:string,benefit:string,opaqueKey:string,record:PromotionalEligibilityRecord,now:Date):Promise<boolean>;
}
export class PromotionalEligibilityBoundary {
 constructor(private readonly product:string,private readonly secret:Uint8Array,private readonly store:PromotionalEligibilityStore,private readonly policy:{reference:string;retentionDays:number}) {
  if(secret.length<32||!product||!policy.reference||!Number.isInteger(policy.retentionDays)||policy.retentionDays<1||policy.retentionDays>3650)throw new Error('Defined product eligibility retention policy required');
 }
 /** Only use a provider subject verified by the product's approved server auth
  * integration. Never a user-entered email, client assertion or raw subject log.
  * Product-specific HMAC prevents cross-product correlation. Key rotation and
  * lawful basis/expiry enforcement belong to the hosting product. */
 private key(provider:'apple'|'google',verifiedSubject:string){
  if(!['apple','google'].includes(provider)||!verifiedSubject||verifiedSubject.length>500)throw new Error('Verified eligibility evidence required');
  return createHmac('sha256',this.secret).update(JSON.stringify([this.product,provider,verifiedSubject])).digest('hex');
 }
 async eligible(benefit:string,provider:'apple'|'google',verifiedSubject:string,now:Date){
  if(!benefit||benefit.length>80||!Number.isFinite(now.getTime()))throw new Error('Invalid eligibility policy input');
  const record=await this.store.find(this.product,benefit,this.key(provider,verifiedSubject));
  return !record||record.expiresAt<=now;
 }
 async redeem(benefit:string,provider:'apple'|'google',verifiedSubject:string,now:Date){
  if(!benefit||benefit.length>80||!Number.isFinite(now.getTime()))throw new Error('Invalid eligibility policy input');
  return this.store.redeem(this.product,benefit,this.key(provider,verifiedSubject),{redeemedAt:now,expiresAt:new Date(now.getTime()+this.policy.retentionDays*86400000),retentionPolicyReference:this.policy.reference},now);
 }
}
