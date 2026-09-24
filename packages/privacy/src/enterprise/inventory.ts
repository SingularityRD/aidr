import { frozen, id, integer, httpsOrigin, object, deny } from './util.js';
/** Inventory from explicitly submitted trusted observations, not autonomous endpoint discovery.
 * URL paths, query strings, prompt text and employee identities are never retained. */
export class ApplicationInventory {
  #apps=new Map<string,{origin:string;firstSeen:number;lastSeen:number;observations:number;sanctioned:boolean}>();#sanctioned:Set<string>;#lastNow=0;
  constructor(readonly tenantId:string,sanctionedOrigins:readonly string[],readonly capacity=1000){id(tenantId);integer(capacity,1,10000);this.#sanctioned=new Set(sanctionedOrigins.map(httpsOrigin));}
  observe(origin:string,now=Date.now()):void{integer(now);if(now<this.#lastNow)deny('CLOCK_ROLLBACK');this.#lastNow=now;origin=httpsOrigin(origin);
    const old=this.#apps.get(origin);if(!old&&this.#apps.size>=this.capacity)deny('INVENTORY_CAPACITY');
    this.#apps.set(origin,{origin,firstSeen:old?.firstSeen??now,lastSeen:now,observations:integer((old?.observations??0)+1,1),sanctioned:this.#sanctioned.has(origin)});
  }
  snapshot():unknown{return frozen({tenantId:this.tenantId,coverage:'submitted-observations-only',applications:[...this.#apps.values()].sort((a,b)=>a.origin.localeCompare(b.origin))});}
}
