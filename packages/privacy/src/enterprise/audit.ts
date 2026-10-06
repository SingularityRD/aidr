import { randomUUID } from 'node:crypto';
import { ENTITY_TYPES } from '../types.js';
import { canonical, frozen, object, id, integer, oneOf, mac, hash, secret, equalHex, deny } from './util.js';
import { CLASSIFICATIONS, type Classification, type ControlDecision } from './types.js';
export interface DecisionEvent {
  readonly eventId:string;readonly at:number;readonly actorRef:string;readonly destinationId:string;
  readonly policyRevision:number;readonly decision:ControlDecision;readonly classification:Classification;
  readonly reasons:readonly string[];readonly counts:Readonly<Record<string,number>>;readonly inputBytes:number;
}
export interface AuditRecord {readonly format:'aidr-audit-v1';readonly tenantId:string;readonly logId:string;readonly keyId:string;readonly sequence:number;readonly previousHash:string;readonly event:DecisionEvent;readonly entryHash:string;readonly auth:string;}
export interface AuditCheckpoint {readonly tenantId:string;readonly logId:string;readonly sequence:number;readonly head:string;readonly auth:string;}
export function validateAuditEvent(input:DecisionEvent):DecisionEvent {
  const e=object(frozen(input),['eventId','at','actorRef','destinationId','policyRevision','decision','classification','reasons','counts','inputBytes']);
  id(e.eventId);id(e.destinationId);integer(e.at);integer(e.policyRevision,1);integer(e.inputBytes,0,1048576);
  if(typeof e.actorRef!=='string'||!/^[0-9a-f]{64}$/.test(e.actorRef))deny('AUDIT_INVALID');oneOf(e.decision,['allow','redact','review','block']);oneOf(e.classification,CLASSIFICATIONS);
  if(!Array.isArray(e.reasons)||e.reasons.length>64||e.reasons.some(x=>typeof x!=='string'||!/^[A-Z][A-Z0-9_]{0,63}$/.test(x)))deny('AUDIT_INVALID');
  const counts=object(e.counts,ENTITY_TYPES);for(const count of Object.values(counts))integer(count,0,100000);
  return e as unknown as DecisionEvent;
}
export type AuditWriter=(record:AuditRecord)=>Promise<void>;
/** Serialized, fail-closed journal. The supplied writer must durably append before resolving.
 * An array writer is useful for tests but is not durable. Hash/HMAC chaining is tamper-evident,
 * NOT immutable storage. Anchor checkpoints off-host to detect suffix truncation/rollback. */
export class AuditJournal {
  readonly tenantId:string;readonly logId:string;readonly keyId:string;
  #key:Buffer;#sequence=0;#head='0'.repeat(64);#lastAt=0;#write:AuditWriter;#queue:Promise<void>=Promise.resolve();#halted=false;#closing=false;#pending=0;#timeoutMs:number;
  constructor(tenantId:string,logId:string,keyId:string,key:Uint8Array,write:AuditWriter,timeoutMs=10000){this.#timeoutMs=integer(timeoutMs,1,120000);this.tenantId=id(tenantId);this.logId=id(logId);this.keyId=id(keyId);this.#key=secret(key);if(typeof write!=='function')deny();this.#write=write;}
  actor(subjectId:string):string {return mac(this.#key,'aidr-actor-v1',this.tenantId,id(subjectId));}
  append(input:DecisionEvent):Promise<AuditRecord> {
    if(this.#halted||this.#closing||this.#pending>=64)return Promise.reject(new Error('AUDIT_UNAVAILABLE'));
    let event:DecisionEvent;try{event=validateAuditEvent(input);}catch(e){return Promise.reject(e);}
    this.#pending++;const task=this.#queue.then(async()=>{
      if(this.#halted)deny('AUDIT_HALTED');if(event.at<this.#lastAt)deny('CLOCK_ROLLBACK');
      const body={format:'aidr-audit-v1' as const,tenantId:this.tenantId,logId:this.logId,keyId:this.keyId,sequence:this.#sequence+1,previousHash:this.#head,event};
      const entryHash=hash(body),record=frozen({...body,entryHash,auth:mac(this.#key,'aidr-audit-auth-v1',entryHash)});
      let timer:ReturnType<typeof setTimeout>|undefined;
      try{await Promise.race([Promise.resolve().then(()=>this.#write(record)),new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(new Error('AUDIT_TIMEOUT')),this.#timeoutMs);})]);}
      catch{this.#halted=true;deny('AUDIT_WRITE_FAILURE');}finally{if(timer)clearTimeout(timer);}
      this.#sequence++;this.#head=entryHash;this.#lastAt=event.at;return record;
    });this.#queue=task.then(()=>{this.#pending--;},()=>{this.#pending--;this.#halted=true;});return task;
  }
  checkpoint():AuditCheckpoint {const body={tenantId:this.tenantId,logId:this.logId,sequence:this.#sequence,head:this.#head};return frozen({...body,auth:mac(this.#key,'aidr-audit-checkpoint-v1',body)});}
  async dispose():Promise<void>{this.#closing=true;await this.#queue;this.#halted=true;this.#key.fill(0);}
}
export function verifyAudit(records:readonly AuditRecord[],checkpoint:AuditCheckpoint,key:Uint8Array):boolean {
  try{
    const k=secret(key);try{
      const c=object(frozen(checkpoint),['tenantId','logId','sequence','head','auth']);id(c.tenantId);id(c.logId);integer(c.sequence);
      const cp={tenantId:c.tenantId,logId:c.logId,sequence:c.sequence,head:c.head};if(!equalHex(c.auth,mac(k,'aidr-audit-checkpoint-v1',cp)))return false;
      if(!Array.isArray(records)||records.length>100000||records.length!==c.sequence)return false;
      let previous='0'.repeat(64),at=0,keyId:string|undefined;
      for(let i=0;i<records.length;i++){
        const r=object(frozen(records[i]),['format','tenantId','logId','keyId','sequence','previousHash','event','entryHash','auth']);
        if(r.format!=='aidr-audit-v1'||r.tenantId!==c.tenantId||r.logId!==c.logId||r.sequence!==i+1||r.previousHash!==previous)return false;
        id(r.keyId);keyId??=r.keyId as string;if(r.keyId!==keyId)return false;
        const event=validateAuditEvent(r.event as DecisionEvent);if(event.at<at)return false;at=event.at;
        const body={format:r.format,tenantId:r.tenantId,logId:r.logId,keyId:r.keyId,sequence:r.sequence,previousHash:r.previousHash,event};
        if(!equalHex(r.entryHash,hash(body))||!equalHex(r.auth,mac(k,'aidr-audit-auth-v1',r.entryHash)))return false;previous=r.entryHash as string;
      }
      return c.head===previous;
    }finally{k.fill(0);}
  }catch{return false;}
}
export interface WebhookEnvelope {readonly format:'aidr-webhook-v1';readonly deliveryId:string;readonly at:number;readonly body:string;readonly signature:string;}
export function signWebhook(records:readonly AuditRecord[],key:Uint8Array,now=Date.now()):WebhookEnvelope {
  integer(now);if(records.length>100)deny('WEBHOOK_LIMIT');for(const r of records){object(frozen(r),['format','tenantId','logId','keyId','sequence','previousHash','event','entryHash','auth']);if(r.format!=='aidr-audit-v1')deny('AUDIT_INVALID');id(r.tenantId);id(r.logId);id(r.keyId);integer(r.sequence,1);for(const x of [r.previousHash,r.entryHash,r.auth])if(!/^[0-9a-f]{64}$/.test(x))deny('AUDIT_INVALID');validateAuditEvent(r.event);}
  const body=canonical(records,1048576),deliveryId=randomUUID(),k=secret(key);
  try{return frozen({format:'aidr-webhook-v1',deliveryId,at:now,body,signature:mac(k,'aidr-webhook-v1',deliveryId,now,body)});}finally{k.fill(0);}
}
/** Caller's replay store must atomically reject duplicate deliveryId across all receivers. */
export function verifyWebhook(e:WebhookEnvelope,key:Uint8Array,now=Date.now(),toleranceMs=300000):boolean {
  try{integer(now);integer(toleranceMs,1,300000);object(frozen(e),['format','deliveryId','at','body','signature']);id(e.deliveryId);integer(e.at);
    if(e.format!=='aidr-webhook-v1'||typeof e.body!=='string'||Buffer.byteLength(e.body)>1048576||Math.abs(now-e.at)>toleranceMs)return false;
    const k=secret(key);try{return equalHex(e.signature,mac(k,'aidr-webhook-v1',e.deliveryId,e.at,e.body));}finally{k.fill(0);}
  }catch{return false;}
}
