import {SensitiveDataIndex} from '../enterprise/data-index.js';
import {deny,hash} from '../enterprise/util.js';
import type {TenantState} from './state.js';
import type {SourceRecord} from './dspm.js';
/** Durable administrator labels feed the same final text gate. No request-supplied classification. */
export class DurableDataPolicy {
 readonly tenantId:string;#index:SensitiveDataIndex|undefined;#revision='';#disposed=false;
 constructor(private state:TenantState,private keyId:string,private key:Uint8Array){this.tenantId=state.tenantId;}
 scan(text:string){
  if(this.#disposed)deny('INDEX_DISPOSED');
  const revision=String(this.state.get<number>('dspm-policy','revision')?.value??0);
  if(!this.#index||revision!==this.#revision){
   const rows=this.state.list('dspm-documents',1001);if(rows.length>1000)deny('DSPM_POLICY_CAPACITY');
   const next=new SensitiveDataIndex(this.tenantId,'institution-data',this.keyId,this.key);
   try{for(const row of rows){const d=row.cell.value as SourceRecord,ref=hash([d.sourceId,d.id]),words=d.text.match(/[\p{L}\p{N}]+/gu)??[];
    if(!words.length)continue;if(words.length<=16)next.enrollRecord(ref,{content:d.text},d.classification,1);else next.enrollDocument(ref,d.text,d.classification);
   }}catch(e){next.dispose();throw e;}
   this.#index?.dispose();this.#index=next;this.#revision=revision;
  }
  return this.#index.scan(text);
 }
 dispose(){this.#disposed=true;this.#index?.dispose();this.key.fill(0);}
}
