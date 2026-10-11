import {SensitiveDataIndex} from '../enterprise/data-index.js';
import {deny,hash} from '../enterprise/util.js';
import type {TenantState} from './state.js';
import type {SourceRecord} from './dspm.js';
/** Total indexed source documents across every source; beyond it the snapshot is out of the supported scope. */
export const MAX_INDEXED_SOURCE_DOCUMENTS=1000;
function buildIndex(tenantId:string,keyId:string,key:Uint8Array,records:readonly SourceRecord[]):SensitiveDataIndex{
 if(records.length>MAX_INDEXED_SOURCE_DOCUMENTS)deny('DSPM_POLICY_CAPACITY');
 const next=new SensitiveDataIndex(tenantId,'institution-data',keyId,key);
 try{for(const d of records){const ref=hash([d.sourceId,d.id]),words=d.text.match(/[\p{L}\p{N}]+/gu)??[];
  if(!words.length)continue;if(words.length<=16)next.enrollRecord(ref,{content:d.text},d.classification,1);else next.enrollDocument(ref,d.text,d.classification);
 }}catch(e){next.dispose();throw e;}
 return next;
}
/** Durable administrator labels feed the same final text gate. No request-supplied classification. */
export class DurableDataPolicy {
 readonly tenantId:string;#index:SensitiveDataIndex|undefined;#revision='';#disposed=false;
 constructor(private state:TenantState,private keyId:string,private key:Uint8Array){this.tenantId=state.tenantId;}
 scan(text:string){
  if(this.#disposed)deny('INDEX_DISPOSED');
  const revision=String(this.state.get<number>('dspm-policy','revision')?.value??0);
  if(!this.#index||revision!==this.#revision){
   const rows=this.state.list('dspm-documents',MAX_INDEXED_SOURCE_DOCUMENTS+1);
   const next=buildIndex(this.tenantId,this.keyId,this.key,rows.map(row=>row.cell.value as SourceRecord));
   this.#index?.dispose();this.#index=next;this.#revision=revision;
  }
  return this.#index.scan(text);
 }
 /** Admission check for a snapshot before it commits: the complete resulting record set must build a
  * supported index, otherwise it throws the same stable code (DSPM_POLICY_CAPACITY, INDEX_CAPACITY,
  * INDEX_CONTENT_LIMIT, CONTENT_LIMIT, ...) and the stored, usable policy is left unchanged. */
 admit(records:readonly SourceRecord[]):void{
  if(this.#disposed)deny('INDEX_DISPOSED');
  buildIndex(this.tenantId,this.keyId,this.key,records).dispose();
 }
 dispose(){this.#disposed=true;this.#index?.dispose();this.key.fill(0);}
}
