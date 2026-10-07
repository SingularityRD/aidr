import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { lstatSync, readFileSync } from 'node:fs';
import { bytesDigest } from './state.js';
import { ControlError, deny } from '../enterprise/util.js';
import { parseJsonStrict } from '../json.js';
/** `findings` (half-open UTF-16 spans of the input, as PrivacyEngine returns them) is required only for format-preserving output. */
export interface TextProtector {protect(text:string):Promise<{output:string|null;decision:string;findings?:readonly {readonly start:number;readonly end:number}[]}>;}
export const OFFICE_MIME={
 docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
 xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
 pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',
} as const;
export type OfficeKind=keyof typeof OFFICE_MIME;
export type DocumentMime='text/plain'|typeof OFFICE_MIME[OfficeKind];
export type DocumentFilename='aidr-sanitized.txt'|`aidr-redacted.${OfficeKind}`;
export interface DocumentResult {decision:'redact'|'block'|'review';output:Buffer|null;mime:DocumentMime;filename:DocumentFilename;reason:string;}
/**
 * `text` (default): text-only reconstruction, the original container never passes through.
 * `office`: explicit opt-in, DOCX/XLSX/PPTX only. The original package is re-serialized with
 * detected spans redacted in place, metadata/thumbnails dropped and cached formula values removed,
 * then re-parsed and re-scanned; any remaining finding or validation failure yields no output.
 */
export type DocumentOutput='text'|'office';
export interface DocumentProtectOptions {readonly output?:DocumentOutput;}
const isOffice=(kind:string):kind is OfficeKind=>Object.hasOwn(OFFICE_MIME,kind);
const SANDBOX='linux-seccomp-no-network-filesystem-open-exec';
const MAX_TEXT=524288;
/** Units/views are joined like the TXT path joins segments, so detection context matches. */
const JOIN='\n\n';
type WorkerReply={ok:boolean;reason?:string;sandbox?:string;format?:string;[k:string]:unknown};
function strings(x:unknown,max:number):x is string[] {return Array.isArray(x)&&x.length<=max&&x.every(s=>typeof s==='string');}
/**
 * Recovers each finding's replacement from the protector output. PrivacyEngine replaces every merged
 * span with a single bracketed marker (`[EMAIL]`, `[REDACTED]`, `[EMAIL~kid~token]`); anything that
 * does not reconstruct the output exactly is treated as a failure, never guessed.
 */
export function alignReplacements(text:string,output:string,findings:readonly {start:number;end:number}[]):string[]|null {
 const sorted=[...findings].sort((a,b)=>a.start-b.start);const reps:string[]=[];let pin=0,pout=0;
 for(const f of sorted){
  if(!Number.isSafeInteger(f.start)||!Number.isSafeInteger(f.end)||f.start<pin||f.end<=f.start||f.end>text.length)return null;
  const keep=text.slice(pin,f.start);if(output.slice(pout,pout+keep.length)!==keep)return null;pout+=keep.length;
  if(output[pout]!=='[')return null;const close=output.indexOf(']',pout);if(close<0)return null;
  const rep=output.slice(pout,close+1);if(!/^\[[\x20-\x5c\x5e-\x7e]{1,198}\]$/.test(rep))return null;
  reps.push(rep);pout=close+1;pin=f.end;
 }
 if(output.slice(pout)!==text.slice(pin))return null;
 return reps;
}
/** Code-point offset of a UTF-16 offset (the worker indexes Python str by code point). */
function codePoints(s:string,utf16:number):number {let n=0;for(let i=0;i<utf16;i++,n++){const c=s.charCodeAt(i);if(c>=0xd800&&c<=0xdbff&&i+1<utf16)i++;}return n;}
/**
 * Maps findings over `units.join(JOIN)` onto [unit, start, end, replacement] edits in code points.
 * A finding that crosses a unit boundary is redacted in every unit it touches (marker in the first).
 */
export function unitEdits(units:readonly string[],findings:readonly {start:number;end:number}[],reps:readonly string[]):[number,number,number,string][] {
 const starts:number[]=[];let o=0;for(const u of units){starts.push(o);o+=u.length+JOIN.length;}
 const edits:[number,number,number,string][]=[];
 [...findings].map((f,i)=>({f,rep:reps[i]!})).sort((a,b)=>a.f.start-b.f.start).forEach(({f,rep})=>{
  let placed=false;
  units.forEach((u,i)=>{
   const a=Math.max(f.start,starts[i]!)-starts[i]!,b=Math.min(f.end,starts[i]!+u.length)-starts[i]!;
   if(a>=b)return;edits.push([i,codePoints(u,a),codePoints(u,b),placed?'':rep]);placed=true;
  });
  if(!placed)deny('REDACTION_ALIGNMENT'); // a span made only of separators: never silently dropped
 });
 return edits;
}
export class DocumentCdr {
 #active=0;
 constructor(private options:{python:string;worker:string;workerSha256:string;protector:TextProtector;timeoutMs?:number}){
  for(const p of [options.python,options.worker])if(!isAbsolute(p)||!lstatSync(p).isFile()||lstatSync(p).isSymbolicLink())deny('PARSER_CONFIG');
  if(bytesDigest(readFileSync(options.worker))!==options.workerSha256)deny('PARSER_PIN');
 }
 async #run(request:Record<string,unknown>,maxStdout:number,maxNodes:number):Promise<WorkerReply> {
  // The pin is re-checked before EVERY spawn, including each step of the office pipeline.
  if(bytesDigest(readFileSync(this.options.worker))!==this.options.workerSha256)deny('PARSER_PIN');
  const body=Buffer.from(JSON.stringify(request));
  const output=await new Promise<string>((resolve,reject)=>{
   const child=spawn(this.options.python,['-I',this.options.worker],{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',PYTHONHASHSEED:'0'},cwd:'/'});let n=0;const chunks:Buffer[]=[];let done=false;
   const fail=()=>{if(done)return;done=true;child.kill('SIGKILL');reject(new Error('PARSER_FAILURE'));};
   const timer=setTimeout(fail,this.options.timeoutMs??12000);
   child.stdout.on('data',(b:Buffer)=>{n+=b.length;if(n>maxStdout)fail();else chunks.push(b);});child.stderr.on('data',()=>{});child.on('error',fail);child.stdin.on('error',fail);
   child.on('close',code=>{clearTimeout(timer);if(done)return;done=true;if(code!==0)reject(new Error('PARSER_FAILURE'));else resolve(Buffer.concat(chunks).toString('utf8'));});child.stdin.end(body);
  });
  const r=parseJsonStrict(output,8,maxNodes) as WorkerReply;
  if(r.ok!==true||r.sandbox!==SANDBOX)deny(r.reason&&/^[A-Z_]{1,64}$/.test(r.reason)?r.reason:'PARSER_FAILURE');
  return r;
 }
 async protect(input:Uint8Array,kind:string,options:DocumentProtectOptions={}):Promise<DocumentResult> {
  const office=options.output==='office';
  const mime:DocumentMime=office&&isOffice(kind)?OFFICE_MIME[kind]:'text/plain';
  const filename:DocumentFilename=office&&isOffice(kind)?`aidr-redacted.${kind}`:'aidr-sanitized.txt';
  const rejected=(reason:string,review=false):DocumentResult=>({decision:review?'review':'block',output:null,mime,filename,reason});
  if(this.#active>=2)return rejected('PARSER_BUSY');this.#active++;
  try{
   if(!(input instanceof Uint8Array)||input.length>8388608||!/^[a-z]{1,8}$/.test(kind))return rejected('PARSER_INPUT');
   if(options.output!==undefined&&options.output!=='text'&&options.output!=='office')return rejected('PARSER_INPUT');
   if(office)return isOffice(kind)?await this.#office(input,kind,rejected):rejected('FORMAT_PRESERVING_UNSUPPORTED');
   const r=await this.#run({kind,data:Buffer.from(input).toString('base64')},2097152,10000) as WorkerReply&{segments:unknown};
   if(!strings(r.segments,1000))return rejected('PARSER_RESPONSE');
   const text=r.segments.join(JOIN);if(Buffer.byteLength(text)>MAX_TEXT)return rejected('PARSER_TEXT_LIMIT');
   const result=await this.options.protector.protect(text);
   if(result.output===null||!['allow','redact'].includes(result.decision))return rejected('DOCUMENT_POLICY',result.decision==='review');
   return {decision:'redact',output:Buffer.from(result.output,'utf8'),mime:'text/plain',filename:'aidr-sanitized.txt',reason:'TEXT_ONLY_RECONSTRUCTION'};
  }catch(error){
   return rejected(error instanceof ControlError&&/^[A-Z_]{1,64}$/.test(error.code)?error.code:'PARSER_FAILURE');
  }finally{this.#active--;}
 }
 async #office(input:Uint8Array,kind:OfficeKind,rejected:(reason:string,review?:boolean)=>DocumentResult):Promise<DocumentResult> {
  const data=Buffer.from(input).toString('base64');
  // 1. Units: every text node grouped by paragraph/string/cell, scanned by the SAME protector as TXT.
  const u=await this.#run({kind,data,mode:'units'},4194304,60000) as WorkerReply&{units:unknown;unitsDigest:unknown};
  if(u.format!=='aidr-office-units-v1'||!strings(u.units,20000)||typeof u.unitsDigest!=='string'||!/^[0-9a-f]{64}$/.test(u.unitsDigest))return rejected('PARSER_RESPONSE');
  const text=u.units.join(JOIN);if(Buffer.byteLength(text)>MAX_TEXT)return rejected('PARSER_TEXT_LIMIT');
  const result=await this.options.protector.protect(text);
  if(result.output===null||!['allow','redact'].includes(result.decision))return rejected('DOCUMENT_POLICY',result.decision==='review');
  let edits:[number,number,number,string][]=[];
  if(result.output!==text){
   if(!Array.isArray(result.findings)||!result.findings.length)return rejected('REDACTION_SPANS_REQUIRED');
   const reps=alignReplacements(text,result.output,result.findings);if(!reps)return rejected('REDACTION_ALIGNMENT');
   edits=unitEdits(u.units,result.findings,reps);if(edits.length>20000)return rejected('REDACTION_LIMIT');
  }
  // 2. Apply in place (worker re-derives units from the same bytes and checks the digest).
  const a=await this.#run({kind,data,mode:'apply',edits,unitsDigest:u.unitsDigest},12582912,64) as WorkerReply&{data:unknown};
  if(a.format!=='aidr-office-redacted-v1'||typeof a.data!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(a.data))return rejected('PARSER_RESPONSE');
  const out=Buffer.from(a.data,'base64');if(!out.length||out.length>8388608)return rejected('PARSER_RESPONSE');
  // 3. Verify in a fresh worker: the unchanged TXT extractor and the unit extractor must both re-scan clean.
  const v=await this.#run({kind,data:out.toString('base64'),mode:'verify'},4194304,60000) as WorkerReply&{segments:unknown;units:unknown};
  if(v.format!=='aidr-office-verify-v1'||!strings(v.segments,1000)||!strings(v.units,20000))return rejected('PARSER_RESPONSE');
  for(const view of [v.segments.join(JOIN),v.units.join(JOIN)]){
   if(Buffer.byteLength(view)>MAX_TEXT)return rejected('PARSER_TEXT_LIMIT');
   const rescan=await this.options.protector.protect(view);
   if(rescan.decision!=='allow'||rescan.output!==view||(rescan.findings?.length??0)>0)return rejected('REDACTION_RESIDUAL');
  }
  return {decision:'redact',output:out,mime:OFFICE_MIME[kind],filename:`aidr-redacted.${kind}`,reason:'FORMAT_PRESERVING_REDACTION'};
 }
}
