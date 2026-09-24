import { randomBytes } from 'node:crypto';
import { id, integer, mac, secret, frozen, object, oneOf, deny } from './util.js';
export interface Principal {readonly tenantId:string;readonly subjectId:string;readonly roles:readonly string[];}
export interface ApprovalBinding {readonly tenantId:string;readonly subjectId:string;readonly sessionId:string;readonly policyRevision:number;readonly actionDigest:string;}
interface Grant {binding:ApprovalBinding;expiresAt:number;approverRef:string;}
function binding(x:ApprovalBinding):ApprovalBinding {object(frozen(x),['tenantId','subjectId','sessionId','policyRevision','actionDigest']);id(x.tenantId);id(x.subjectId);id(x.sessionId);integer(x.policyRevision,1);if(!/^[0-9a-f]{64}$/.test(x.actionDigest))deny('APPROVAL_INVALID');return frozen(x);}
/** Four-eyes, exact-action and session-bound, single-use approvals. Trusted principals only.
 * Single-process adapter: use an atomic durable shared store for clustered AIDR deployments. */
export class ApprovalLedger {
  #key:Buffer;#grants=new Map<string,Grant>();#lastNow=0;#disposed=false;
  constructor(key:Uint8Array,readonly capacity=10000){this.#key=secret(key);integer(capacity,1,100000);}
  #time(now:number):void{integer(now);if(this.#disposed)deny('APPROVAL_DISPOSED');if(now<this.#lastNow)deny('CLOCK_ROLLBACK');this.#lastNow=now;for(const [k,g]of this.#grants)if(now>=g.expiresAt)this.#grants.delete(k);}
  approve(request:ApprovalBinding,approver:Principal,now=Date.now(),ttlMs=60000):string {
    this.#time(now);integer(ttlMs,1000,300000);const b=binding(request);id(approver.tenantId);id(approver.subjectId);
    if(!Array.isArray(approver.roles)||!approver.roles.includes('security-approver')||approver.tenantId!==b.tenantId||approver.subjectId===b.subjectId)deny('APPROVAL_FORBIDDEN');
    if(this.#grants.size>=this.capacity)deny('APPROVAL_CAPACITY');const token=randomBytes(32).toString('base64url');
    this.#grants.set(mac(this.#key,'aidr-approval-token-v1',token),{binding:b,expiresAt:now+ttlMs,approverRef:mac(this.#key,'aidr-approver-v1',b.tenantId,approver.subjectId)});return token;
  }
  consume(token:string,request:ApprovalBinding,now=Date.now()):boolean {
    this.#time(now);if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token))return false;
    const tag=mac(this.#key,'aidr-approval-token-v1',token),grant=this.#grants.get(tag);this.#grants.delete(tag);if(!grant)return false;
    try{return now<grant.expiresAt&&mac(this.#key,'aidr-approval-binding-v1',grant.binding)===mac(this.#key,'aidr-approval-binding-v1',binding(request));}catch{return false;}
  }
  revokeAll():void{this.#grants.clear();}
  dispose():void{this.#key.fill(0);this.#grants.clear();this.#disposed=true;}
}
