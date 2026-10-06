import { randomUUID } from 'node:crypto';
import { id, integer, frozen, deny, textBound } from '../enterprise/util.js';
import { monotonic } from './durable.js';
import type { TenantState, StateTransaction } from './state.js';
import type { AuthenticatedPrincipal, ContextResolver } from './identity.js';
export const REVIEWABLE_REASONS=['SEMANTIC_REVIEW','PII_REVIEW','DOCUMENT_REVIEW','MANUAL_REVIEW'] as const;
export interface ReviewCase {
  readonly id:string;readonly tenantId:string;readonly owner:string;readonly ownerSession:string;
  readonly actionDigest:string;readonly policyRevision:number;readonly reason:typeof REVIEWABLE_REASONS[number];
  readonly destination:string;readonly status:'open'|'approved'|'denied'|'appealed'|'expired'|'consumed';
  readonly sequence:number;readonly createdAt:number;readonly updatedAt:number;readonly expiresAt:number;
  readonly approvalExpiresAt:number|null;readonly remainingUses:number;readonly approver:string|null;
}
export interface ReviewHistory {readonly caseId:string;readonly sequence:number;readonly at:number;readonly actor:string;readonly transition:string;readonly reason:string;}
/** Stateful, encrypted review workflow. Exceptions cannot override block decisions, identity,
 * device, classifier or secret policies. Only an exact already-reviewed action may be consumed. */
export class ReviewWorkflow {
  constructor(readonly state:TenantState,readonly identity:ContextResolver,readonly clock:()=>number=Date.now){}
  #auth(p:AuthenticatedPrincipal,role?:string):void{this.identity.assertPrincipal(p,role);if(p.tenantId!==this.state.tenantId)deny('TENANT_MISMATCH');}
  #history(tx:StateTransaction,c:ReviewCase,p:AuthenticatedPrincipal,transition:string,reason:string,now:number):void {
    textBound(reason,2000);if(reason.trim().length<8)deny('REVIEW_REASON_REQUIRED');const h:ReviewHistory={caseId:c.id,sequence:c.sequence,at:now,actor:p.subjectId,transition,reason};
    tx.put('review-history',c.id+'.'+String(c.sequence).padStart(6,'0'),h,null,c.expiresAt+30*86400000);tx.event('REVIEW_'+transition,p.subjectId,c.id,now);
  }
  open(p:AuthenticatedPrincipal,input:{actionDigest:string;policyRevision:number;reason:ReviewCase['reason'];destination:string;explanation:string},ttlMs=86400000):ReviewCase{
    this.#auth(p);if(!/^[0-9a-f]{64}$/.test(input.actionDigest)||!REVIEWABLE_REASONS.includes(input.reason))deny('REVIEW_NOT_OVERRIDABLE');integer(input.policyRevision,1);id(input.destination);integer(ttlMs,60000,7*86400000);textBound(input.explanation,2000);
    const now=this.clock(),c:ReviewCase=frozen({id:randomUUID(),tenantId:p.tenantId,owner:p.subjectId,ownerSession:p.sessionId,actionDigest:input.actionDigest,policyRevision:input.policyRevision,reason:input.reason,destination:input.destination,status:'open',sequence:1,createdAt:now,updatedAt:now,expiresAt:now+ttlMs,approvalExpiresAt:null,remainingUses:0,approver:null});
    this.state.transaction(tx=>{monotonic(tx,now);tx.put('reviews',c.id,c,null,c.expiresAt);this.#history(tx,c,p,'OPENED',input.explanation,now);});return c;
  }
  get(p:AuthenticatedPrincipal,caseId:string):ReviewCase{
    this.#auth(p);const c=this.state.get<ReviewCase>('reviews',id(caseId))?.value;if(!c)deny('REVIEW_NOT_FOUND');if(c.owner!==p.subjectId&&!p.roles.includes('security-reviewer')&&!p.roles.includes('security-admin'))deny('REVIEW_FORBIDDEN');return c;
  }
  list(p:AuthenticatedPrincipal,limit=50,after=''):readonly ReviewCase[]{
    this.#auth(p);integer(limit,1,200);const out:ReviewCase[]=[],canReview=p.roles.includes('security-reviewer')||p.roles.includes('security-admin');let cursor=after;
    // ponytail: scan tenant pages; add an owner index if tenant queue throughput requires it.
    while(out.length<limit){const page=this.state.list('reviews',200,cursor);for(const r of page){const c=r.cell.value as ReviewCase;if(canReview||c.owner===p.subjectId)out.push(c);if(out.length===limit)break;}if(page.length<200)break;cursor=page[page.length-1]!.key;}
    return frozen(out);
  }
  history(p:AuthenticatedPrincipal,caseId:string):readonly ReviewHistory[]{const c=this.get(p,caseId),out:ReviewHistory[]=[];for(let n=1;n<=c.sequence;n++){const r=this.state.get<ReviewHistory>('review-history',c.id+'.'+String(n).padStart(6,'0'));if(!r)deny('REVIEW_HISTORY_INTEGRITY');out.push(r.value);}return frozen(out);}
  decide(p:AuthenticatedPrincipal,caseId:string,decision:'approved'|'denied',reason:string,expectedSequence:number,ttlMs=300000,uses=1):ReviewCase {
    this.#auth(p,'security-reviewer');if(!['approved','denied'].includes(decision))deny('REVIEW_DECISION');integer(expectedSequence,1);integer(ttlMs,1000,3600000);integer(uses,1,20);const now=this.clock();
    return this.state.transaction(tx=>{monotonic(tx,now);const r=tx.get<ReviewCase>('reviews',id(caseId));if(!r)deny('REVIEW_NOT_FOUND');const c=r.value;
      if(c.owner===p.subjectId)deny('REVIEW_FOUR_EYES');if(c.sequence!==expectedSequence)deny('REVIEW_CONFLICT');if(!['open','appealed'].includes(c.status)||now>=c.expiresAt)deny('REVIEW_STATE');
      // On appeal the previous reviewer cannot rubber-stamp their own old decision.
      if(c.status==='appealed'&&c.approver===p.subjectId)deny('REVIEW_INDEPENDENT_APPEAL');
      const next:ReviewCase=frozen({...c,status:decision,sequence:c.sequence+1,updatedAt:now,approvalExpiresAt:decision==='approved'?Math.min(now+ttlMs,c.expiresAt):null,remainingUses:decision==='approved'?uses:0,approver:p.subjectId});
      tx.put('reviews',c.id,next,r.version,c.expiresAt);this.#history(tx,next,p,decision.toUpperCase(),reason,now);return next;
    });
  }
  appeal(p:AuthenticatedPrincipal,caseId:string,reason:string):ReviewCase{
    this.#auth(p);const now=this.clock();return this.state.transaction(tx=>{monotonic(tx,now);const r=tx.get<ReviewCase>('reviews',id(caseId));if(!r||r.value.owner!==p.subjectId)deny('REVIEW_FORBIDDEN');const c=r.value;if(c.status!=='denied'||now>=c.expiresAt||c.sequence>20)deny('REVIEW_STATE');const next:ReviewCase=frozen({...c,status:'appealed',sequence:c.sequence+1,updatedAt:now});tx.put('reviews',c.id,next,r.version,c.expiresAt);this.#history(tx,next,p,'APPEALED',reason,now);return next;});
  }
  consumeApproved(p:AuthenticatedPrincipal,caseId:string,actionDigest:string,policyRevision:number):boolean{
    this.#auth(p);const now=this.clock();return this.state.transaction(tx=>{monotonic(tx,now);const r=tx.get<ReviewCase>('reviews',id(caseId));if(!r)return false;const c=r.value;
      if(c.owner!==p.subjectId||c.ownerSession!==p.sessionId||c.status!=='approved'||!c.approver||c.approver===p.subjectId||now>=(c.approvalExpiresAt??0)||now>=c.expiresAt||c.actionDigest!==actionDigest||c.policyRevision!==policyRevision||c.remainingUses<1)return false;
      const remainingUses=c.remainingUses-1,next:ReviewCase=frozen({...c,remainingUses,status:remainingUses===0?'consumed':'approved',sequence:c.sequence+1,updatedAt:now});tx.put('reviews',c.id,next,r.version,c.expiresAt);this.#history(tx,next,p,'CONSUMED','Exact authorized action consumed.',now);return true;
    });
  }
}
