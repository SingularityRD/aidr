import { id, integer, mac, secret, deny } from './util.js';
export interface BudgetOptions {readonly windowMs:number;readonly maxCalls:number;readonly maxBytes:number;readonly maxSubjects:number;}
/** Synchronous reservation: atomic within one process only. Use a transactional shared adapter
 * for horizontally scaled gateways. Never LRU-evicts live entries, which would reset protection. */
export class ActivityBudget {
  #key:Buffer;#rows=new Map<string,{at:number;bytes:number}[]>();#lastNow=0;#disposed=false;#options:BudgetOptions;
  constructor(key:Uint8Array,options:BudgetOptions){this.#key=secret(key);this.#options=Object.freeze({...options});
    integer(options.windowMs,1000,86400000);integer(options.maxCalls,1,10000);integer(options.maxBytes,1,1e12);integer(options.maxSubjects,1,100000);}
  consume(tenantId:string,subjectId:string,bytes:number,now=Date.now()):boolean {
    id(tenantId);id(subjectId);integer(bytes,0,1e9);integer(now);if(this.#disposed)deny('BUDGET_DISPOSED');if(now<this.#lastNow)deny('CLOCK_ROLLBACK');this.#lastNow=now;
    const cutoff=now-this.#options.windowMs;
    for(const [k,row]of this.#rows){while(row[0]&&row[0].at<=cutoff)row.shift();if(!row.length)this.#rows.delete(k);}
    const key=mac(this.#key,'aidr-budget-v1',tenantId,subjectId),row=this.#rows.get(key)??[];
    if(row.length>=this.#options.maxCalls||row.reduce((s,x)=>s+x.bytes,0)+bytes>this.#options.maxBytes)return false;
    if(!this.#rows.has(key)&&this.#rows.size>=this.#options.maxSubjects)deny('BUDGET_CAPACITY');row.push({at:now,bytes});this.#rows.set(key,row);return true;
  }
  dispose():void{this.#key.fill(0);this.#rows.clear();this.#disposed=true;}
}
