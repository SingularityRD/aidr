import { randomUUID } from 'node:crypto';
import { secret, mac, textBound, id, integer, oneOf, deny, frozen } from './util.js';
import { CLASSIFICATIONS, maximumClassification, type Classification } from './types.js';
interface Asset {id:string;classification:Classification;tainted:boolean;parents:readonly string[];contentTag:string;expiresAt:number;}
/** Trusted in-process provenance receipts. Integrators must propagate handles at every copy/derive
 * boundary. This is not endpoint clipboard surveillance or complete enterprise-wide lineage. */
export class ProvenanceLedger {
  readonly tenantId:string;#key:Buffer;#assets=new Map<string,Asset>();#disposed=false;#lastNow=0;
  constructor(tenantId:string,key:Uint8Array,readonly maxAssets=10000){this.tenantId=id(tenantId);this.#key=secret(key);integer(maxAssets,1,100000);}
  #time(now:number):void{integer(now);if(this.#disposed)deny('PROVENANCE_DISPOSED');if(now<this.#lastNow)deny('CLOCK_ROLLBACK');this.#lastNow=now;}
  #get(assetId:string,now:number):Asset {const a=this.#assets.get(id(assetId));if(!a||now>=a.expiresAt)deny('PROVENANCE_MISSING');return a;}
  #tag(text:string):string{return mac(this.#key,'aidr-content-v1',this.tenantId,textBound(text));}
  registerRoot(text:string,classification:Classification,tainted:boolean,now=Date.now(),ttlMs=3600000):string {
    this.#time(now);oneOf(classification,CLASSIFICATIONS);if(typeof tainted!=='boolean')deny();integer(ttlMs,1000,86400000);this.#room(now);
    const a:Asset={id:randomUUID(),classification,tainted,parents:[],contentTag:this.#tag(text),expiresAt:now+ttlMs};this.#assets.set(a.id,frozen(a));return a.id;
  }
  derive(text:string,parentIds:readonly string[],now=Date.now()):string {
    this.#time(now);if(!Array.isArray(parentIds)||!parentIds.length||parentIds.length>128||new Set(parentIds).size!==parentIds.length)deny('PROVENANCE_INVALID');
    const parents=parentIds.map(x=>this.#get(x,now));this.#room(now);
    const a:Asset={id:randomUUID(),classification:maximumClassification(...parents.map(p=>p.classification)),tainted:parents.some(p=>p.tainted),parents:[...parentIds],contentTag:this.#tag(text),expiresAt:Math.min(...parents.map(p=>p.expiresAt))};
    this.#assets.set(a.id,frozen(a));return a.id;
  }
  resolve(text:string,assetIds:readonly string[],now=Date.now()):{classification:Classification;tainted:boolean} {
    this.#time(now);if(!Array.isArray(assetIds)||assetIds.length>128||new Set(assetIds).size!==assetIds.length)deny('PROVENANCE_INVALID');
    const tag=this.#tag(text),assets=assetIds.map(x=>this.#get(x,now));if(assets.some(a=>a.contentTag!==tag))deny('PROVENANCE_CONTENT_MISMATCH');
    return frozen({classification:maximumClassification(...assets.map(a=>a.classification)),tainted:assets.some(a=>a.tainted)});
  }
  #room(now:number):void{for(const [key,a]of this.#assets)if(now>=a.expiresAt)this.#assets.delete(key);if(this.#assets.size>=this.maxAssets)deny('PROVENANCE_CAPACITY');}
  dispose():void{this.#assets.clear();this.#key.fill(0);this.#disposed=true;}
}
