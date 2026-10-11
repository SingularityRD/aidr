import { randomBytes } from 'node:crypto';
import { canonical, hash, id, integer, frozen, deny } from '../enterprise/util.js';
import type { ApprovalBinding, Principal } from '../enterprise/approvals.js';
import type { PolicyCheckpoint } from '../enterprise/policy.js';
import type { TenantState, StateTransaction } from './state.js';
/** Apply a persisted high-water clock inside the SAME transaction as the protected mutation. */
export function monotonic(tx:StateTransaction,now:number):void {integer(now);const c=tx.get<number>('internal','clock');if(c&&now<c.value)deny('CLOCK_ROLLBACK');if(!c||now>c.value)tx.put('internal','clock',now,c?.version??null);}
export class DurablePolicyCheckpoint {
  constructor(readonly state:TenantState){}
  read():PolicyCheckpoint|undefined{return this.state.get<PolicyCheckpoint>('internal','policy')?.value;}
  async write(c:PolicyCheckpoint):Promise<void>{if(c.tenantId!==this.state.tenantId)deny('TENANT_MISMATCH');integer(c.revision,1);if(!/^[0-9a-f]{64}$/.test(c.digest))deny('POLICY_CHECKPOINT_INVALID');this.state.transaction(tx=>{const old=tx.get<PolicyCheckpoint>('internal','policy');if(old&&(c.revision<old.value.revision||c.revision===old.value.revision&&c.digest!==old.value.digest))deny('POLICY_ROLLBACK');tx.put('internal','policy',c,old?.version??null);});}
}
function validateBinding(b:ApprovalBinding,tenant:string):ApprovalBinding {if(b.tenantId!==tenant)deny('TENANT_MISMATCH');id(b.subjectId);id(b.sessionId);integer(b.policyRevision,1);if(!/^[a-f0-9]{64}$/.test(b.actionDigest))deny('APPROVAL_INVALID');return frozen(b);}
export class DurableApprovalLedger {
  constructor(readonly state:TenantState){}
  approve(binding:ApprovalBinding,approver:Principal,now=Date.now(),ttlMs=60000):string{
    const b=validateBinding(binding,this.state.tenantId);id(approver.subjectId);integer(ttlMs,1000,300000);
    if(approver.tenantId!==b.tenantId||approver.subjectId===b.subjectId||!approver.roles.includes('security-approver'))deny('APPROVAL_FORBIDDEN');
    const token=randomBytes(32).toString('base64url'),tag=hash(['approval-token-v1',token]);
    this.state.transaction(tx=>{monotonic(tx,now);const epoch=tx.get<number>('internal','approval-epoch')?.value??0;tx.put('approvals',tag,{binding:b,epoch,used:false},null,now+ttlMs);tx.event('APPROVAL_GRANTED',approver.subjectId,b.subjectId,now);});return token;
  }
  consume(token:string,binding:ApprovalBinding,now=Date.now()):boolean {
    if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(token))return false;
    let b:ApprovalBinding;try{b=validateBinding(binding,this.state.tenantId);}catch{return false;}
    return this.state.transaction(tx=>{monotonic(tx,now);const tag=hash(['approval-token-v1',token]),r=tx.get<{binding:ApprovalBinding;epoch:number;used:boolean}>('approvals',tag);
      if(!r||r.value.used)return false;
      // Consume even a mismatched/expired attempt; never make a token reusable after uncertainty.
      tx.put('approvals',tag,{...r.value,used:true},r.version,r.expiresAt);
      const allowed=now<(r.expiresAt??0)&&r.value.epoch===(tx.get<number>('internal','approval-epoch')?.value??0)&&canonical(r.value.binding)===canonical(b);
      tx.event(allowed?'APPROVAL_CONSUMED':'APPROVAL_REJECTED',b.subjectId,b.sessionId,now);return allowed;
    });
  }
  revokeAll():void{this.state.transaction(tx=>{const c=tx.get<number>('internal','approval-epoch');tx.put('internal','approval-epoch',(c?.value??0)+1,c?.version??null);});}
}
const QUOTA_PURGE_BATCH=64;
export class DurableBudget {
  constructor(readonly state:TenantState,readonly windowMs=60000,readonly maxCalls=60,readonly maxBytes=1048576){integer(windowMs,1000,86400000);integer(maxCalls,1);integer(maxBytes,1);}
  consume(tenant:string,subject:string,bytes:number,now=Date.now()):boolean{
    if(tenant!==this.state.tenantId)deny('TENANT_MISMATCH');id(subject);integer(bytes,0,104857600);
    // Bounded physical purge of expired windows (expires<=now never includes the current window) keeps rows bounded.
    return this.state.transaction(tx=>{monotonic(tx,now);tx.purgeExpiredTransient('quotas',now,QUOTA_PURGE_BATCH);const key=hash(['quota',subject,Math.floor(now/this.windowMs)]),r=tx.get<{calls:number;bytes:number}>('quotas',key),calls=(r?.value.calls??0)+1,total=(r?.value.bytes??0)+bytes;
      if(calls>this.maxCalls||total>this.maxBytes)return false;tx.put('quotas',key,{calls,bytes:total},r?.version??null,(Math.floor(now/this.windowMs)+1)*this.windowMs);return true;
    });
  }
}
export interface ActionRecord {readonly digest:string;readonly subjectId:string;readonly sessionId:string;readonly status:'reserved'|'dispatched'|'completed'|'failed'|'unknown';readonly at:number;}
/** At-most-one local dispatch attempt, NOT exactly-once remote effects. A timeout after dispatch
 * is UNKNOWN, never an invitation to retry using the same authorization. */
export class DurableDispatchLedger {
  constructor(readonly state:TenantState){}
  reserve(requestId:string,digest:string,subjectId:string,sessionId:string,now=Date.now()):void{
    id(requestId);id(subjectId);id(sessionId);if(!/^[a-f0-9]{64}$/.test(digest))deny('ACTION_DIGEST');
    this.state.transaction(tx=>{monotonic(tx,now);if(tx.get('dispatch',requestId))deny('ACTION_REPLAY');tx.put('dispatch',requestId,{digest,subjectId,sessionId,status:'reserved',at:now},null);tx.event('ACTION_RESERVED',subjectId,requestId,now);});
  }
  transition(requestId:string,expected:ActionRecord['status'],next:ActionRecord['status'],now=Date.now()):void{
    const allowed:Record<string,string[]>={reserved:['dispatched','failed'],dispatched:['completed','unknown']};if(!allowed[expected]?.includes(next))deny('ACTION_TRANSITION');
    this.state.transaction(tx=>{monotonic(tx,now);const r=tx.get<ActionRecord>('dispatch',id(requestId));if(!r||r.value.status!==expected)deny('ACTION_STATE');tx.put('dispatch',requestId,{...r.value,status:next,at:now},r.version);tx.event('ACTION_'+next.toUpperCase(),r.value.subjectId,requestId,now);});
  }
  get(requestId:string):ActionRecord|null{return this.state.get<ActionRecord>('dispatch',id(requestId))?.value??null;}
}
