import { createHash } from 'node:crypto';
import { CHUNK_BYTES, fromBase64 } from '../browser/transport.js';
import { protectDocument, type DocumentKind, type DocumentScanner } from '../browser/documents.js';
import type { VisualInspection, VisualResult } from '../visual/types.js';
import type { EntityType } from '../types.js';
export interface NativeServices {
  text:DocumentScanner;
  visual?:{protect(bytes:Uint8Array,signal?:AbortSignal):Promise<VisualResult>;inspect(bytes:Uint8Array,signal?:AbortSignal):Promise<VisualInspection>};
  policyId:string;policyDigest:string;
  /** Per-dataset exact-data key (base64) derived from the host's EDM secret (./edm.ts); absent: no secret configured. */
  exactDataKey?:(datasetId:string)=>string;
}
/** `image`: OCR + pixel redaction (a sanitised PNG may be read back). `image-scan`: OCR inspection only;
 * the reply carries a decision and per-type counts, never bytes (see VisualPrivacyEngine.inspect). */
type ImageKind='image'|'image-scan';
const IMAGE_KINDS:readonly string[]=['image','image-scan'];
/** Correlation ids remembered for duplicate detection (a rolling window, so a persistent session never runs out). */
const ID_WINDOW=256;
const DATASET_ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const MAX_KEY_REQUEST=16;
function reject():never{throw new Error('NATIVE_PROTOCOL_INVALID');}
function keys(v:Record<string,unknown>,allowed:string[]):void{if(Object.keys(v).some(k=>!['v','id','op',...allowed].includes(k)))reject();}
function digest(b:Uint8Array):string{return createHash('sha256').update(b).digest('hex');}
/**
 * One native-messaging connection. A client that sends `hello {persistent:true}` (Browser Guard) keeps the
 * connection, and so the host process and its warm NER worker, for many documents: once a document is
 * finished (`done`, or `output` the client chose not to read back) the next `begin` starts a new one, and
 * `cancel` abandons the current document without ending the session. A plain `hello` gets the original
 * reply, so older clients see no change. `edm-keys` (idle only) returns per-dataset exact-data keys.
 */
export class NativeSession {
  #services:NativeServices;#input:Buffer|undefined;#received=0;#expectedHash='';#kind:ImageKind|DocumentKind='text';
  #state:'new'|'input'|'processing'|'output'|'done'='new';#output:Buffer|undefined;#readOffset=0;#abort=new AbortController();
  #ids=new Set<string>();#closed=false;#documents=0;#persistent=false;
  constructor(services:NativeServices){this.#services=services;}
  /** Documents begun on this session (tests and diagnostics; never their content). */
  get documents():number{return this.#documents;}
  /** The client asked to keep this connection for many documents (`hello {persistent:true}`). */
  get persistent():boolean{return this.#persistent;}
  /** Ends the session for good (disconnect/shutdown); a later request is refused. */
  close():void{this.#closed=true;this.#reset();this.#state='done';}
  #reset():void{this.#abort.abort();this.#input?.fill(0);this.#input=undefined;this.#output?.fill(0);this.#output=undefined;this.#received=0;this.#readOffset=0;this.#expectedHash='';}
  #idle():boolean{return this.#state==='new'||this.#state==='done'||this.#state==='output';}
  #remember(id:string):void{this.#ids.add(id);if(this.#ids.size>ID_WINDOW)this.#ids.delete(this.#ids.values().next().value as string);}
  async handle(q:Record<string,unknown>):Promise<Record<string,unknown>> {
    if(this.#closed||q.v!==1||typeof q.id!=='string'||!/^[a-zA-Z0-9_-]{1,64}$/.test(q.id)||this.#ids.has(q.id))reject();
    this.#remember(q.id);const base={v:1,id:q.id};
    if(q.op==='hello'){
      keys(q,['persistent']);if(q.persistent!==undefined&&q.persistent!==true)reject();
      if(!(this.#state==='new'||(q.persistent===true&&this.#persistent&&this.#idle())))reject();
      if(q.persistent===true)this.#persistent=true;
      return {...base,ok:true,protocol:1,local:true,ocr:!!this.#services.visual,policyId:this.#services.policyId,policyDigest:this.#services.policyDigest,...(q.persistent===true?{persistent:true}:{})};
    }
    if(q.op==='edm-keys'){
      keys(q,['datasetIds']);const ids=q.datasetIds;
      if(!this.#idle()||!Array.isArray(ids)||!ids.length||ids.length>MAX_KEY_REQUEST||ids.some(id=>typeof id!=='string'||!DATASET_ID.test(id))||new Set(ids).size!==ids.length)reject();
      const derive=this.#services.exactDataKey,out:Record<string,string>={};
      if(derive)for(const id of ids as string[])out[id]=derive(id);
      return {...base,ok:true,keys:out};
    }
    if(q.op==='begin'){
      keys(q,['kind','size','sha256','policyDigest']);if(q.policyDigest!==this.#services.policyDigest||!(this.#state==='new'||(this.#persistent&&this.#idle()))||![...IMAGE_KINDS,'text','json','csv','tsv'].includes(q.kind as string)
        ||!Number.isSafeInteger(q.size)||(q.size as number)<1||(q.size as number)>(IMAGE_KINDS.includes(q.kind as string)?8388608:1048576)||typeof q.sha256!=='string'||!/^[a-f0-9]{64}$/.test(q.sha256))reject();
      // A finished (or unread) previous document is discarded before the next one starts.
      this.#reset();this.#abort=new AbortController();this.#documents++;
      this.#input=Buffer.alloc(q.size as number);this.#kind=q.kind as ImageKind|DocumentKind;this.#expectedHash=q.sha256;this.#state='input';return {...base,ok:true};
    }
    if(q.op==='write'){
      keys(q,['offset','data']);if(this.#state!=='input'||!this.#input||q.offset!==this.#received)reject();
      const chunk=fromBase64(q.data,CHUNK_BYTES);if(!chunk.length||this.#received+chunk.length>this.#input.length)reject();
      this.#input.set(chunk,this.#received);this.#received+=chunk.length;chunk.fill(0);return {...base,ok:true,received:this.#received};
    }
    if(q.op==='commit'){
      keys(q,[]);if(this.#state!=='input'||!this.#input||this.#received!==this.#input.length||digest(this.#input)!==this.#expectedHash)reject();
      this.#state='processing';const signal=this.#abort.signal;let metadata:Record<string,unknown>;
      try{
        if(this.#kind==='image-scan'){
          // Decision only: nothing is released, so the document ends here (no `read`).
          this.#state='done';
          if(!this.#services.visual)return {...base,ok:true,decision:'review',reasons:['NATIVE_OCR_UNAVAILABLE'],counts:{},outputBytes:0};
          const r=await this.#services.visual.inspect(this.#input,signal);
          if(signal.aborted)reject();
          return {...base,ok:true,decision:r.decision,reasons:r.reasons,coverage:r.audit.textCoverage,counts:r.counts,policyId:this.#services.policyId,policyDigest:this.#services.policyDigest,outputBytes:0};
        }
        if(this.#kind==='image'){
          if(!this.#services.visual){this.#state='done';return {...base,ok:true,decision:'block',reasons:['NATIVE_OCR_UNAVAILABLE'],outputBytes:0};}
          const r=await this.#services.visual.protect(this.#input,signal);
          metadata={decision:r.decision,reasons:r.reasons,filename:r.filename,contentType:r.contentType,coverage:r.audit.textCoverage,verification:r.audit.verification,counts:{}};
          if(signal.aborted){r.output?.fill(0);reject();}
          if(r.output&&r.output.length<=16777216)this.#output=r.output;
          else if(r.output){r.output.fill(0);this.#state='done';return {...base,ok:true,decision:'block',reasons:['NATIVE_OUTPUT_LIMIT'],outputBytes:0};}
        }else{
          const text=new TextDecoder('utf-8',{fatal:true}).decode(this.#input);
          const r=await protectDocument(text,this.#kind,this.#services.text);
          // Native full coverage is queried from the actual engine, not from a client declaration.
          const probe=await this.#services.text.protect('');
          metadata={decision:r.decision,reasons:r.reasons,filename:r.filename,contentType:r.contentType,coverage:probe.audit.coverage,counts:r.counts as Partial<Record<EntityType,number>>};
          if(r.output!==null)this.#output=Buffer.from(r.output,'utf8');
        }
        if(signal.aborted){this.#output?.fill(0);this.#output=undefined;reject();}
        if(!this.#output){this.#state='done';return {...base,ok:true,...metadata,policyId:this.#services.policyId,policyDigest:this.#services.policyDigest,outputBytes:0};}
        const sha256=digest(this.#output);this.#state='output';this.#readOffset=0;
        return {...base,ok:true,...metadata,policyId:this.#services.policyId,policyDigest:this.#services.policyDigest,outputBytes:this.#output.length,sha256};
      }catch(e){if(this.#state==='processing')this.#state='done';throw e;}
      finally{this.#input?.fill(0);this.#input=undefined;}
    }
    if(q.op==='read'){
      keys(q,['offset']);if(this.#state!=='output'||!this.#output||q.offset!==this.#readOffset)reject();
      const end=Math.min(this.#readOffset+CHUNK_BYTES,this.#output.length),data=this.#output.subarray(this.#readOffset,end).toString('base64'),offset=this.#readOffset;
      this.#readOffset=end;const done=end===this.#output.length;if(done){this.#output.fill(0);this.#output=undefined;this.#state='done';}
      return {...base,ok:true,offset,data,done};
    }
    if(q.op==='cancel'){keys(q,[]);this.#reset();this.#state='done';return {...base,ok:true};}
    reject();
  }
}
