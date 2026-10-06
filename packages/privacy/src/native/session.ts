import { createHash } from 'node:crypto';
import { CHUNK_BYTES, fromBase64 } from '../browser/transport.js';
import { protectDocument, type DocumentKind, type DocumentScanner } from '../browser/documents.js';
import type { VisualResult } from '../visual/types.js';
import type { EntityType } from '../types.js';
export interface NativeServices {
  text:DocumentScanner;
  visual?:{protect(bytes:Uint8Array,signal?:AbortSignal):Promise<VisualResult>};
  policyId:string;policyDigest:string;
}
function reject():never{throw new Error('NATIVE_PROTOCOL_INVALID');}
function keys(v:Record<string,unknown>,allowed:string[]):void{if(Object.keys(v).some(k=>!['v','id','op',...allowed].includes(k)))reject();}
function digest(b:Uint8Array):string{return createHash('sha256').update(b).digest('hex');}
export class NativeSession {
  #services:NativeServices;#input:Buffer|undefined;#received=0;#expectedHash='';#kind:'image'|DocumentKind='text';
  #state:'new'|'input'|'processing'|'output'|'done'='new';#output:Buffer|undefined;#readOffset=0;#abort=new AbortController();
  #ids=new Set<string>();
  constructor(services:NativeServices){this.#services=services;}
  close():void{this.#abort.abort();this.#input?.fill(0);this.#input=undefined;this.#output?.fill(0);this.#output=undefined;this.#state='done';}
  async handle(q:Record<string,unknown>):Promise<Record<string,unknown>> {
    if(q.v!==1||typeof q.id!=='string'||!/^[a-zA-Z0-9_-]{1,64}$/.test(q.id)||this.#ids.has(q.id)||this.#ids.size>256)reject();
    this.#ids.add(q.id);const base={v:1,id:q.id};
    if(q.op==='hello'){keys(q,[]);if(this.#state!=='new')reject();return {...base,ok:true,protocol:1,local:true,ocr:!!this.#services.visual,policyId:this.#services.policyId,policyDigest:this.#services.policyDigest};}
    if(q.op==='begin'){
      keys(q,['kind','size','sha256','policyDigest']);if(q.policyDigest!==this.#services.policyDigest||this.#state!=='new'||!['image','text','json','csv','tsv'].includes(q.kind as string)
        ||!Number.isSafeInteger(q.size)||(q.size as number)<1||(q.size as number)>(q.kind==='image'?8388608:1048576)||typeof q.sha256!=='string'||!/^[a-f0-9]{64}$/.test(q.sha256))reject();
      this.#input=Buffer.alloc(q.size as number);this.#kind=q.kind as 'image'|DocumentKind;this.#expectedHash=q.sha256;this.#state='input';return {...base,ok:true};
    }
    if(q.op==='write'){
      keys(q,['offset','data']);if(this.#state!=='input'||!this.#input||q.offset!==this.#received)reject();
      const chunk=fromBase64(q.data,CHUNK_BYTES);if(!chunk.length||this.#received+chunk.length>this.#input.length)reject();
      this.#input.set(chunk,this.#received);this.#received+=chunk.length;chunk.fill(0);return {...base,ok:true,received:this.#received};
    }
    if(q.op==='commit'){
      keys(q,[]);if(this.#state!=='input'||!this.#input||this.#received!==this.#input.length||digest(this.#input)!==this.#expectedHash)reject();
      this.#state='processing';let metadata:Record<string,unknown>;
      try{
        if(this.#kind==='image'){
          if(!this.#services.visual){this.#state='done';return {...base,ok:true,decision:'block',reasons:['NATIVE_OCR_UNAVAILABLE'],outputBytes:0};}
          const r=await this.#services.visual.protect(this.#input,this.#abort.signal);
          metadata={decision:r.decision,reasons:r.reasons,filename:r.filename,contentType:r.contentType,coverage:r.audit.textCoverage,verification:r.audit.verification,counts:{}};
          if(r.output&&r.output.length<=16777216)this.#output=r.output;
          else if(r.output){r.output.fill(0);return {...base,ok:true,decision:'block',reasons:['NATIVE_OUTPUT_LIMIT'],outputBytes:0};}
        }else{
          const text=new TextDecoder('utf-8',{fatal:true}).decode(this.#input);
          const r=await protectDocument(text,this.#kind,this.#services.text);
          // Native full coverage is queried from the actual engine, not from a client declaration.
          const probe=await this.#services.text.protect('');
          metadata={decision:r.decision,reasons:r.reasons,filename:r.filename,contentType:r.contentType,coverage:probe.audit.coverage,counts:r.counts as Partial<Record<EntityType,number>>};
          if(r.output!==null)this.#output=Buffer.from(r.output,'utf8');
        }
        if(this.#abort.signal.aborted){this.close();reject();}
        if(!this.#output){this.#state='done';return {...base,ok:true,...metadata,policyId:this.#services.policyId,policyDigest:this.#services.policyDigest,outputBytes:0};}
        const sha256=digest(this.#output);this.#state='output';
        return {...base,ok:true,...metadata,policyId:this.#services.policyId,policyDigest:this.#services.policyDigest,outputBytes:this.#output.length,sha256};
      }finally{this.#input?.fill(0);this.#input=undefined;}
    }
    if(q.op==='read'){
      keys(q,['offset']);if(this.#state!=='output'||!this.#output||q.offset!==this.#readOffset)reject();
      const end=Math.min(this.#readOffset+CHUNK_BYTES,this.#output.length),data=this.#output.subarray(this.#readOffset,end).toString('base64'),offset=this.#readOffset;
      this.#readOffset=end;const done=end===this.#output.length;if(done){this.#output.fill(0);this.#output=undefined;this.#state='done';}
      return {...base,ok:true,offset,data,done};
    }
    if(q.op==='cancel'){keys(q,[]);this.close();return {...base,ok:true};}
    reject();
  }
}
