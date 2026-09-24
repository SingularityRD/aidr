import { validateAuditEvent, type AuditRecord, type DecisionEvent, type AuditCheckpoint } from '../enterprise/audit.js';
import { id, secret, mac, hash, frozen, deny } from '../enterprise/util.js';
import type { TenantState } from './state.js';
interface Head {sequence:number;head:string;lastAt:number;}
/** Compatible with verifyAudit(), but serialized across processes by the database transaction. */
export class PersistentAuditJournal {
  readonly tenantId:string;#key:Buffer;#disposed=false;
  #ready():void{if(this.#disposed)deny('AUDIT_DISPOSED');}
  constructor(readonly state:TenantState,readonly logId:string,readonly keyId:string,key:Uint8Array){this.tenantId=state.tenantId;id(logId);id(keyId);this.#key=secret(key);}
  actor(subjectId:string):string{this.#ready();return mac(this.#key,'aidr-actor-v1',this.tenantId,id(subjectId));}
  async append(input:DecisionEvent):Promise<AuditRecord>{this.#ready();const event=validateAuditEvent(input);return this.state.transaction(tx=>{const c=tx.get<Head>('audit-head',this.logId),old=c?.value??{sequence:0,head:'0'.repeat(64),lastAt:0};if(event.at<old.lastAt)deny('CLOCK_ROLLBACK');
    const body={format:'aidr-audit-v1' as const,tenantId:this.tenantId,logId:this.logId,keyId:this.keyId,sequence:old.sequence+1,previousHash:old.head,event},entryHash=hash(body),record=frozen({...body,entryHash,auth:mac(this.#key,'aidr-audit-auth-v1',entryHash)});
    tx.put('audit-records',this.logId+'.'+String(body.sequence).padStart(12,'0'),record,null);tx.put('audit-head',this.logId,{sequence:body.sequence,head:entryHash,lastAt:event.at},c?.version??null);tx.event('DECISION_RECORDED','system',entryHash,event.at);return record;
  });}
  checkpoint():AuditCheckpoint {this.#ready();const c=this.state.get<Head>('audit-head',this.logId)?.value??{sequence:0,head:'0'.repeat(64)},body={tenantId:this.tenantId,logId:this.logId,sequence:c.sequence,head:c.head};return frozen({...body,auth:mac(this.#key,'aidr-audit-checkpoint-v1',body)});}
  records():readonly AuditRecord[]{const cp=this.checkpoint();if(cp.sequence>100000)deny('AUDIT_EXPORT_LIMIT');const out:AuditRecord[]=[];for(let i=1;i<=cp.sequence;i++){const r=this.state.get<AuditRecord>('audit-records',this.logId+'.'+String(i).padStart(12,'0'));if(!r)deny('AUDIT_INTEGRITY');out.push(r.value);}return frozen(out);}
  dispose():void{this.#disposed=true;this.#key.fill(0);}
}
