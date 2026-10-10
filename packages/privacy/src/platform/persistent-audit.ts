import { validateAuditEvent, signAuditRotation, auditRotationBody, type AuditRecord, type DecisionEvent, type AuditCheckpoint, type AuditRotation } from '../enterprise/audit.js';
import { id, integer, secret, mac, hash, frozen, deny, equalHex } from '../enterprise/util.js';
import type { TenantState, Cell } from './state.js';
/** keyId/segment/link are absent only in heads written before key binding; such heads are verified via their last record. */
interface Head {sequence:number;head:string;lastAt:number;keyId?:string;segment?:number;link?:string;}
interface Reader {get<T=unknown>(namespace:string,key:string):Cell<T>|null;}
export interface AuditKey {readonly keyId:string;readonly key:Uint8Array;}
export interface AuditPage {readonly tenantId:string;readonly logId:string;readonly fromSequence:number;readonly upTo:number;readonly records:readonly AuditRecord[];readonly next:number|null;}
const ZERO='0'.repeat(64),MAX_PAGE=1000,EXPORT_LIMIT=100000;
const pad=(n:number,w=12)=>String(n).padStart(w,'0');
/** Segment 0 keeps the configured logId (pre-rotation chains stay valid); later segments get their own logId. */
const segmentLog=(base:string,segment:number)=>segment?id(base+':s'+segment):base;
const rotationKey=(base:string,segment:number)=>base+'.'+pad(segment,6);
/** Bind the stored head to the configured key: the last record (or the rotation that opened an empty
 * segment) must carry this keyId and verify under this key. Anything else fails closed. */
function verifyLastRecord(r:Reader,tenantId:string,log:string,h:Head,keyId:string,key:Buffer):void{
  const last=r.get<AuditRecord>('audit-records',log+'.'+pad(h.sequence))?.value;if(!last)deny('AUDIT_INTEGRITY');
  const {entryHash,auth,...body}=last;
  if(last.tenantId!==tenantId||last.logId!==log||last.sequence!==h.sequence||entryHash!==h.head||hash(body)!==entryHash)deny('AUDIT_INTEGRITY');
  if(last.keyId!==keyId||!equalHex(auth,mac(key,'aidr-audit-auth-v1',entryHash)))deny('AUDIT_KEY_MISMATCH');
}
function verifyOpeningRotation(r:Reader,base:string,segment:number,log:string,h:Head,keyId:string,key:Buffer):void{
  const rot=r.get<AuditRotation>('audit-rotations',rotationKey(base,segment))?.value;
  if(!rot||rot.toLogId!==log||rot.segment!==segment||hash(auditRotationBody(rot))!==h.link)deny('AUDIT_INTEGRITY');
  if(rot.toKeyId!==keyId||!equalHex(rot.newAuth,mac(key,'aidr-audit-rotation-v1',auditRotationBody(rot))))deny('AUDIT_KEY_MISMATCH');
}
/** Bind the stored head to the configured key: the last record (or the rotation that opened an empty
 * segment) must carry this keyId and verify under this key. Anything else fails closed. */
function verifiedHead(r:Reader,tenantId:string,base:string,keyId:string,key:Buffer):{head:Head;version:number|null}{
  const c=r.get<Head>('audit-head',base),h=c?.value??{sequence:0,head:ZERO,lastAt:0},segment=h.segment??0,log=segmentLog(base,segment);
  if(h.keyId!==undefined&&h.keyId!==keyId)deny('AUDIT_KEY_MISMATCH');
  if(h.sequence>0)verifyLastRecord(r,tenantId,log,h,keyId,key);
  if(segment>0)verifyOpeningRotation(r,base,segment,log,h,keyId,key);
  return {head:h,version:c?.version??null};
}
/** Compatible with verifyAudit(), but serialized across processes by the database transaction.
 * Opening with a key that does not match the stored chain throws AUDIT_KEY_MISMATCH; change keys only
 * through rotate()/open({rotateFrom}), which closes the old segment and starts a new one. */
export class PersistentAuditJournal {
  readonly tenantId:string;#key:Buffer;#disposed=false;
  #ready():void{if(this.#disposed)deny('AUDIT_DISPOSED');}
  constructor(readonly state:TenantState,readonly logId:string,readonly keyId:string,key:Uint8Array){
    this.tenantId=state.tenantId;id(logId);id(keyId);this.#key=secret(key);
    try{verifiedHead(state,this.tenantId,logId,keyId,this.#key);}catch(e){this.#key.fill(0);throw e;}
  }
  /** Opens the journal; with rotateFrom, a chain still bound to that previous key is rotated first. */
  static open(state:TenantState,logId:string,keyId:string,key:Uint8Array,options:{rotateFrom?:AuditKey;at?:number}={}):PersistentAuditJournal{
    try{return new PersistentAuditJournal(state,logId,keyId,key);}catch(e){
      if(!options.rotateFrom||(e as {code?:string}).code!=='AUDIT_KEY_MISMATCH')throw e;
      PersistentAuditJournal.rotate(state,logId,options.rotateFrom,{keyId,key},options.at??Date.now());return new PersistentAuditJournal(state,logId,keyId,key);
    }
  }
  /** Close the current segment with a checkpoint signed by the OLD key and open a new segment for the NEW key.
   * Requires both keys; refuses unless the current chain verifies under `from`. */
  static rotate(state:TenantState,logId:string,from:AuditKey,to:AuditKey,at:number):AuditRotation{
    id(logId);id(from.keyId);id(to.keyId);integer(at);if(from.keyId===to.keyId)deny('AUDIT_ROTATION_INVALID');
    const o=secret(from.key),n=secret(to.key);
    try{return state.transaction(tx=>{
      const {head:h,version}=verifiedHead(tx,state.tenantId,logId,from.keyId,o),segment=(h.segment??0)+1,toLogId=segmentLog(logId,segment);if(at<h.lastAt)deny('CLOCK_ROLLBACK');
      const cp={tenantId:state.tenantId,logId:segmentLog(logId,h.segment??0),sequence:h.sequence,head:h.head},closing={...cp,auth:mac(o,'aidr-audit-checkpoint-v1',cp)};
      const rotation=signAuditRotation({format:'aidr-audit-rotation-v1',tenantId:state.tenantId,logId,segment,previous:h.link??ZERO,closing,fromKeyId:from.keyId,toLogId,toKeyId:to.keyId,at},o,n);
      tx.put('audit-rotations',rotationKey(logId,segment),rotation,null);
      tx.put('audit-head',logId,{sequence:0,head:ZERO,lastAt:at,keyId:to.keyId,segment,link:hash(auditRotationBody(rotation))},version);
      tx.event('AUDIT_KEY_ROTATED','system',toLogId,at);return rotation;
    });}finally{o.fill(0);n.fill(0);}
  }
  actor(subjectId:string):string{this.#ready();return mac(this.#key,'aidr-actor-v1',this.tenantId,id(subjectId));}
  async append(input:DecisionEvent):Promise<AuditRecord>{this.#ready();const event=validateAuditEvent(input);return this.state.transaction(tx=>{const {head:old,version}=verifiedHead(tx,this.tenantId,this.logId,this.keyId,this.#key),segment=old.segment??0,log=segmentLog(this.logId,segment);if(event.at<old.lastAt)deny('CLOCK_ROLLBACK');
    const body={format:'aidr-audit-v1' as const,tenantId:this.tenantId,logId:log,keyId:this.keyId,sequence:old.sequence+1,previousHash:old.head,event},entryHash=hash(body),record=frozen({...body,entryHash,auth:mac(this.#key,'aidr-audit-auth-v1',entryHash)});
    tx.put('audit-records',log+'.'+pad(body.sequence),record,null);tx.put('audit-head',this.logId,{...old,sequence:body.sequence,head:entryHash,lastAt:event.at,keyId:this.keyId},version);tx.event('DECISION_RECORDED','system',entryHash,event.at);return record;
  });}
  /** Checkpoint of the CURRENT segment, signed with this journal's key. */
  checkpoint():AuditCheckpoint {this.#ready();const c:Head=this.state.get<Head>('audit-head',this.logId)?.value??{sequence:0,head:ZERO,lastAt:0},body={tenantId:this.tenantId,logId:segmentLog(this.logId,c.segment??0),sequence:c.sequence,head:c.head};return frozen({...body,auth:mac(this.#key,'aidr-audit-checkpoint-v1',body)});}
  /** Rotation records in segment order; rotations()[i] closes segment i and opens segment i+1. */
  rotations():readonly AuditRotation[]{const n=this.state.get<Head>('audit-head',this.logId)?.value.segment??0,out:AuditRotation[]=[];for(let s=1;s<=n;s++){const r=this.state.get<AuditRotation>('audit-rotations',rotationKey(this.logId,s));if(!r)deny('AUDIT_INTEGRITY');out.push(r.value);}return Object.freeze(out);}
  /** Whole current segment in memory; bounded. Use page() for incident export of long-running logs. */
  records():readonly AuditRecord[]{const cp=this.checkpoint();if(cp.sequence>EXPORT_LIMIT)deny('AUDIT_EXPORT_LIMIT');return this.#page(1,EXPORT_LIMIT,{upTo:cp.sequence}).records;}
  /** Bounded page by sequence of one segment (default: current). Pass the first page's `upTo` to later pages
   * so concurrent appends do not move the export target; verify with AuditChainVerifier and the matching
   * checkpoint (checkpoint() for the current segment, rotations()[n].closing for a closed one). */
  page(fromSequence:number,limit=MAX_PAGE,options:{logId?:string;upTo?:number}={}):AuditPage{integer(limit,1,MAX_PAGE);return this.#page(fromSequence,limit,options);}
  #page(fromSequence:number,limit:number,options:{logId?:string;upTo?:number}):AuditPage{
    this.#ready();integer(fromSequence,1);
    const h=this.state.get<Head>('audit-head',this.logId)?.value,log=options.logId===undefined?segmentLog(this.logId,h?.segment??0):id(options.logId);
    let end=this.#segmentEnd(h,log);
    if(options.upTo!==undefined){integer(options.upTo);if(options.upTo>end)deny('AUDIT_EXPORT_RANGE');end=options.upTo;}
    const last=Math.min(end,fromSequence+limit-1),out:AuditRecord[]=[];
    for(let i=fromSequence;i<=last;i++){const r=this.state.get<AuditRecord>('audit-records',log+'.'+pad(i))?.value;if(!r||r.sequence!==i||r.logId!==log||r.tenantId!==this.tenantId)deny('AUDIT_INTEGRITY');out.push(r);}
    // Cells are already deep-frozen on read; re-canonicalising a whole page would hit the per-value size cap.
    return Object.freeze({tenantId:this.tenantId,logId:log,fromSequence,upTo:end,records:Object.freeze(out),next:last<end?last+1:null});
  }
  /** Last sequence of a segment: the live head for the current one, the signed closing checkpoint for a closed one. */
  #segmentEnd(h:Head|undefined,log:string):number{
    const current=h?.segment??0;if(log===segmentLog(this.logId,current))return h?.sequence??0;
    for(let s=1;s<=current;s++){const r=this.state.get<AuditRotation>('audit-rotations',rotationKey(this.logId,s))?.value;if(!r)deny('AUDIT_INTEGRITY');if(r.closing.logId===log)return r.closing.sequence;}
    deny('AUDIT_SEGMENT_UNKNOWN');
  }
  dispose():void{this.#disposed=true;this.#key.fill(0);}
}
