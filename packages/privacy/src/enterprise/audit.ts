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
const ZERO='0'.repeat(64);
/** Incremental verifier for a paged export of ONE chain segment. Pages must be supplied in sequence
 * order: a gap, duplicate, reorder, foreign segment, mixed keyId, clock rollback or bad MAC fails the
 * whole verification permanently. finish() checks the final trusted checkpoint and wipes the key. */
export class AuditChainVerifier {
  readonly tenantId:string;readonly logId:string;
  #key:Buffer;#sequence=0;#previous=ZERO;#at=0;#keyId:string|undefined;#failed=false;#done=false;
  constructor(key:Uint8Array,tenantId:string,logId:string){this.tenantId=id(tenantId);this.logId=id(logId);this.#key=secret(key);}
  /** Number of records verified so far and the hash the next page must continue from. */
  get sequence():number{return this.#sequence;}
  get head():string{return this.#previous;}
  accept(records:readonly AuditRecord[]):boolean {
    if(this.#failed||this.#done)return false;
    try{
      if(!Array.isArray(records))deny('AUDIT_INVALID');
      for(const record of records){
        const r=object(frozen(record),['format','tenantId','logId','keyId','sequence','previousHash','event','entryHash','auth']);
        if(r.format!=='aidr-audit-v1'||r.tenantId!==this.tenantId||r.logId!==this.logId||r.sequence!==this.#sequence+1||r.previousHash!==this.#previous)deny('AUDIT_INVALID');
        id(r.keyId);this.#keyId??=r.keyId as string;if(r.keyId!==this.#keyId)deny('AUDIT_INVALID');
        const event=validateAuditEvent(r.event as DecisionEvent);if(event.at<this.#at)deny('AUDIT_INVALID');
        const body={format:r.format,tenantId:r.tenantId,logId:r.logId,keyId:r.keyId,sequence:r.sequence,previousHash:r.previousHash,event};
        if(!equalHex(r.entryHash,hash(body))||!equalHex(r.auth,mac(this.#key,'aidr-audit-auth-v1',r.entryHash)))deny('AUDIT_INVALID');
        this.#sequence++;this.#previous=r.entryHash as string;this.#at=event.at;
      }
      return true;
    }catch{this.#failed=true;return false;}
  }
  finish(checkpoint:AuditCheckpoint):boolean {
    if(this.#done)return false;this.#done=true;
    try{
      const c=object(frozen(checkpoint),['tenantId','logId','sequence','head','auth']);id(c.tenantId);id(c.logId);integer(c.sequence);
      const cp={tenantId:c.tenantId,logId:c.logId,sequence:c.sequence,head:c.head};
      return !this.#failed&&equalHex(c.auth,mac(this.#key,'aidr-audit-checkpoint-v1',cp))&&c.tenantId===this.tenantId&&c.logId===this.logId&&c.sequence===this.#sequence&&c.head===this.#previous;
    }catch{return false;}finally{this.#key.fill(0);}
  }
}
export function verifyAudit(records:readonly AuditRecord[],checkpoint:AuditCheckpoint,key:Uint8Array):boolean {
  try{
    const c=object(frozen(checkpoint),['tenantId','logId','sequence','head','auth']);
    if(!Array.isArray(records)||records.length>100000)return false;
    const v=new AuditChainVerifier(key,c.tenantId as string,c.logId as string),ok=v.accept(records);return v.finish(checkpoint)&&ok;
  }catch{return false;}
}
/** Explicit audit key rotation: the old segment is closed by a checkpoint signed with the OLD key and
 * a new segment (new logId) is opened for the NEW key. The record is endorsed by both keys and chains
 * to the previous rotation, so each segment verifies independently with verifyAudit() and its own key. */
export interface AuditRotation {
  readonly format:'aidr-audit-rotation-v1';readonly tenantId:string;readonly logId:string;readonly segment:number;
  readonly previous:string;readonly closing:AuditCheckpoint;readonly fromKeyId:string;readonly toLogId:string;readonly toKeyId:string;readonly at:number;
  readonly oldAuth:string;readonly newAuth:string;
}
export type AuditRotationBody=Omit<AuditRotation,'oldAuth'|'newAuth'>;
export function auditRotationBody(r:AuditRotation|AuditRotationBody):AuditRotationBody {
  return {format:r.format,tenantId:r.tenantId,logId:r.logId,segment:r.segment,previous:r.previous,closing:r.closing,fromKeyId:r.fromKeyId,toLogId:r.toLogId,toKeyId:r.toKeyId,at:r.at};
}
export function signAuditRotation(body:AuditRotationBody,oldKey:Uint8Array,newKey:Uint8Array):AuditRotation {
  const o=secret(oldKey),n=secret(newKey);try{const b=auditRotationBody(body);return frozen({...b,oldAuth:mac(o,'aidr-audit-rotation-v1',b),newAuth:mac(n,'aidr-audit-rotation-v1',b)});}finally{o.fill(0);n.fill(0);}
}
/** Verifies both endorsements, the old segment's closing checkpoint, and (optionally) the link to the
 * previous rotation record. The old segment's records verify separately: verifyAudit(old, r.closing, oldKey). */
export function verifyAuditRotation(rotation:AuditRotation,oldKey:Uint8Array,newKey:Uint8Array,previous?:AuditRotation):boolean {
  try{
    const r=object(frozen(rotation),['format','tenantId','logId','segment','previous','closing','fromKeyId','toLogId','toKeyId','at','oldAuth','newAuth']) as unknown as AuditRotation;
    if(r.format!=='aidr-audit-rotation-v1')return false;id(r.tenantId);id(r.logId);integer(r.segment,1);integer(r.at);id(r.fromKeyId);id(r.toKeyId);id(r.toLogId);
    if(r.fromKeyId===r.toKeyId||r.toLogId===r.closing.logId||r.closing.tenantId!==r.tenantId)return false;
    const expected=previous?hash(auditRotationBody(previous)):ZERO;if(r.previous!==expected)return false;
    if(previous&&(previous.segment!==r.segment-1||previous.toLogId!==r.closing.logId||previous.toKeyId!==r.fromKeyId||previous.tenantId!==r.tenantId||previous.logId!==r.logId))return false;
    const o=secret(oldKey),n=secret(newKey);
    try{
      const b=auditRotationBody(r),c=object(r.closing,['tenantId','logId','sequence','head','auth']);integer(c.sequence);
      const cp={tenantId:c.tenantId,logId:c.logId,sequence:c.sequence,head:c.head};
      return equalHex(c.auth,mac(o,'aidr-audit-checkpoint-v1',cp))&&equalHex(r.oldAuth,mac(o,'aidr-audit-rotation-v1',b))&&equalHex(r.newAuth,mac(n,'aidr-audit-rotation-v1',b));
    }finally{o.fill(0);n.fill(0);}
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
