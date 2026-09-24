import { setTimeout as delay } from 'node:timers/promises';
import { hash, id, integer, frozen, deny } from '../enterprise/util.js';
import { discoverMcpConfig, type McpObservation } from './discovery.js';
export interface ApprovedMcpSource {readonly id:string;readonly path:string;readonly expectedRealPath:string;}
export type McpCollection =
 | {readonly sourceId:string;readonly status:'snapshot';readonly idempotencyKey:string;readonly observedAt:number;readonly servers:readonly McpObservation[]}
 | {readonly sourceId:string;readonly status:'unavailable';readonly observedAt:number;readonly reason:'SOURCE_UNAVAILABLE'};
/** Explicitly configured local collector. Never discovers arbitrary home folders, runs commands,
 * accesses env/argument values in telemetry, or contacts a remote server. No collector starts on import.
 * Persist delivery idempotency keys in the receiving inventory; restarts intentionally resnapshot. */
export class AuthorizedMcpCollector {
 readonly #sources:readonly ApprovedMcpSource[];readonly #seen=new Map<string,string>();
 constructor(sources:readonly ApprovedMcpSource[],readonly clock:()=>number=Date.now){
  if(!sources.length||sources.length>32)deny('COLLECTOR_CONFIG');const ids=new Set<string>();
  for(const s of sources){id(s.id);if(ids.has(s.id))deny('COLLECTOR_CONFIG');ids.add(s.id);}
  this.#sources=frozen(sources);
 }
 poll():readonly McpCollection[]{
  const out:McpCollection[]=[];const now=this.clock();integer(now);
  for(const source of this.#sources){try{
   const servers=discoverMcpConfig(source.path,source.expectedRealPath),digest=hash({sourceId:source.id,servers});
   // Returning the full snapshot allows removal detection without inventing a network event.
   out.push({sourceId:source.id,status:'snapshot',idempotencyKey:digest,observedAt:now,servers});
  }catch{out.push({sourceId:source.id,status:'unavailable',observedAt:now,reason:'SOURCE_UNAVAILABLE'});}}
  return frozen(out);
 }
 async *watch(signal:AbortSignal,intervalMs=60000):AsyncGenerator<McpCollection>{
  integer(intervalMs,1000,86400000);
  while(!signal.aborted){for(const item of this.poll()){
   if(signal.aborted)return;
   if(item.status==='unavailable'){this.#seen.delete(item.sourceId);yield item;}
   else if(this.#seen.get(item.sourceId)!==item.idempotencyKey){yield item;this.#seen.set(item.sourceId,item.idempotencyKey);}
  }
  try{await delay(intervalMs,undefined,{signal});}catch(e){if(signal.aborted)return;throw e;}
  }
 }
}
