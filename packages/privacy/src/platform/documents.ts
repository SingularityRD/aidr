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
export const PDF_MIME='application/pdf';
export type DocumentMime='text/plain'|typeof OFFICE_MIME[OfficeKind]|typeof PDF_MIME;
export type DocumentFilename='aidr-sanitized.txt'|`aidr-redacted.${OfficeKind|'pdf'}`;
export interface DocumentResult {decision:'redact'|'block'|'review';output:Buffer|null;mime:DocumentMime;filename:DocumentFilename;reason:string;}
/**
 * `text` (default): text-only reconstruction, the original container never passes through.
 * `office`: explicit opt-in, DOCX/XLSX/PPTX only. The original package is re-serialized with
 * detected spans redacted in place, metadata/thumbnails dropped and cached formula values removed,
 * then re-parsed and re-scanned; any remaining finding or validation failure yields no output.
 * `pdf`: explicit opt-in, PDF only. Spans are detected on PDFium's per-page text (which must agree
 * with the TXT-path pypdf text), each page is rasterized with opaque boxes over the span characters
 * and re-assembled as an IMAGE-ONLY PDF (no text layer, no metadata). The output is re-opened in a
 * fresh worker and must contain the same number of pages and no extractable text, else no output.
 * Unlike `office`, the redacted raster cannot be re-scanned (that would need OCR): a span the
 * detector misses stays visible in the image, and glyphs PDFium cannot extract as text (outlined
 * text, Type3 glyph art) are reproduced unscanned. Inline/XObject images are rejected.
 */
export type DocumentOutput='text'|'office'|'pdf';
export interface DocumentProtectOptions {readonly output?:DocumentOutput;}
const isOffice=(kind:string):kind is OfficeKind=>Object.hasOwn(OFFICE_MIME,kind);
type PreservedKind=OfficeKind|'pdf';
/** Worker reply formats per format-preserving pipeline (units / apply / verify). */
const PRESERVE={
 office:{units:'aidr-office-units-v1',apply:'aidr-office-redacted-v1',verify:'aidr-office-verify-v1'},
 pdf:{units:'aidr-pdf-units-v1',apply:'aidr-pdf-redacted-v1',verify:'aidr-pdf-verify-v1'},
} as const;
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
  const office=options.output==='office',pdf=options.output==='pdf';
  const preserved:PreservedKind|null=office&&isOffice(kind)?kind:pdf&&kind==='pdf'?'pdf':null;
  const mime:DocumentMime=preserved===null?'text/plain':preserved==='pdf'?PDF_MIME:OFFICE_MIME[preserved];
  const filename:DocumentFilename=preserved===null?'aidr-sanitized.txt':`aidr-redacted.${preserved}`;
  const rejected=(reason:string,review=false):DocumentResult=>({decision:review?'review':'block',output:null,mime,filename,reason});
  if(this.#active>=2)return rejected('PARSER_BUSY');this.#active++;
  try{
   if(!(input instanceof Uint8Array)||input.length>8388608||!/^[a-z]{1,8}$/.test(kind))return rejected('PARSER_INPUT');
   if(options.output!==undefined&&options.output!=='text'&&options.output!=='office'&&options.output!=='pdf')return rejected('PARSER_INPUT');
   if(office||pdf)return preserved!==null?await this.#preserve(input,preserved,rejected):rejected('FORMAT_PRESERVING_UNSUPPORTED');
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
 async #preserve(input:Uint8Array,kind:PreservedKind,rejected:(reason:string,review?:boolean)=>DocumentResult):Promise<DocumentResult> {
  const data=Buffer.from(input).toString('base64'),isPdf=kind==='pdf',formats=PRESERVE[isPdf?'pdf':'office'];
  // 1. Units, scanned by the SAME protector as TXT. Office: every text node grouped by
  //    paragraph/string/cell. PDF: one unit per page, PDFium's text (the characters whose boxes get painted).
  const u=await this.#run({kind,data,mode:'units'},4194304,60000) as WorkerReply&{units:unknown;unitsDigest:unknown;pages?:unknown};
  if(u.format!==formats.units||!strings(u.units,20000)||typeof u.unitsDigest!=='string'||!/^[0-9a-f]{64}$/.test(u.unitsDigest))return rejected('PARSER_RESPONSE');
  if(isPdf&&(u.pages!==u.units.length||u.units.length<1||u.units.length>50))return rejected('PARSER_RESPONSE');
  const text=u.units.join(JOIN);if(Buffer.byteLength(text)>MAX_TEXT)return rejected('PARSER_TEXT_LIMIT');
  const result=await this.options.protector.protect(text);
  if(result.output===null||!['allow','redact'].includes(result.decision))return rejected('DOCUMENT_POLICY',result.decision==='review');
  let edits:[number,number,number,string][]=[];
  if(result.output!==text){
   if(!Array.isArray(result.findings)||!result.findings.length)return rejected('REDACTION_SPANS_REQUIRED');
   const reps=alignReplacements(text,result.output,result.findings);if(!reps)return rejected('REDACTION_ALIGNMENT');
   edits=unitEdits(u.units,result.findings,reps);if(edits.length>20000)return rejected('REDACTION_LIMIT');
  }
  // 2. Apply (worker re-derives units from the same bytes and checks the digest). Office edits in place;
  //    PDF paints the spans' character boxes on a raster and writes an image-only PDF.
  const a=await this.#run({kind,data,mode:'apply',edits,unitsDigest:u.unitsDigest},12582912,64) as WorkerReply&{data:unknown};
  if(a.format!==formats.apply||typeof a.data!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(a.data))return rejected('PARSER_RESPONSE');
  const out=Buffer.from(a.data,'base64');if(!out.length||out.length>8388608)return rejected('PARSER_RESPONSE');
  if(isPdf&&out.subarray(0,9).toString('latin1')!=='%PDF-1.4\n')return rejected('PARSER_RESPONSE');
  // 3. Verify in a fresh worker. Office: the unchanged TXT extractor and the unit extractor must both
  //    re-scan clean. PDF: pypdf and PDFium must both extract NO text and the page count must be kept.
  const v=await this.#run({kind,data:out.toString('base64'),mode:'verify'},4194304,60000) as WorkerReply&{segments:unknown;units:unknown;pages?:unknown};
  if(v.format!==formats.verify||!strings(v.segments,1000)||!strings(v.units,20000))return rejected('PARSER_RESPONSE');
  if(isPdf){
   if(v.pages!==u.units.length||v.units.length!==u.units.length)return rejected('REDACTION_VALIDATION');
   if([...v.segments,...v.units].some(t=>t.trim()!==''))return rejected('REDACTION_RESIDUAL');
   return {decision:'redact',output:out,mime:PDF_MIME,filename:'aidr-redacted.pdf',reason:'FORMAT_PRESERVING_REDACTION'};
  }
  for(const view of [v.segments.join(JOIN),v.units.join(JOIN)]){
   if(Buffer.byteLength(view)>MAX_TEXT)return rejected('PARSER_TEXT_LIMIT');
   const rescan=await this.options.protector.protect(view);
   if(rescan.decision!=='allow'||rescan.output!==view||(rescan.findings?.length??0)>0)return rejected('REDACTION_RESIDUAL');
  }
  return {decision:'redact',output:out,mime:OFFICE_MIME[kind as OfficeKind],filename:`aidr-redacted.${kind}`,reason:'FORMAT_PRESERVING_REDACTION'};
 }
}
