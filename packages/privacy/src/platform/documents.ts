import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { lstatSync, readFileSync } from 'node:fs';
import { bytesDigest } from './state.js';
import { deny } from '../enterprise/util.js';
import { parseJsonStrict } from '../json.js';
export interface TextProtector {protect(text:string):Promise<{output:string|null;decision:string}>;}
export interface DocumentResult {decision:'redact'|'block'|'review';output:Buffer|null;mime:'text/plain';filename:'aidr-sanitized.txt';reason:string;}
/** Deliberately text-only: original Office/PDF/mail containers and attachments NEVER pass through. */
export class DocumentCdr {
 #active=0;
 constructor(private options:{python:string;worker:string;workerSha256:string;protector:TextProtector;timeoutMs?:number}){
  for(const p of [options.python,options.worker])if(!isAbsolute(p)||!lstatSync(p).isFile()||lstatSync(p).isSymbolicLink())deny('PARSER_CONFIG');
  if(bytesDigest(readFileSync(options.worker))!==options.workerSha256)deny('PARSER_PIN');
 }
 async protect(input:Uint8Array,kind:string):Promise<DocumentResult>{
  const rejected=(reason:string,review=false):DocumentResult=>({decision:review?'review':'block',output:null,mime:'text/plain',filename:'aidr-sanitized.txt',reason});
  if(this.#active>=2)return rejected('PARSER_BUSY');this.#active++;
  try{
   if(!(input instanceof Uint8Array)||input.length>8388608||!/^[a-z]{1,8}$/.test(kind))return rejected('PARSER_INPUT');
   if(bytesDigest(readFileSync(this.options.worker))!==this.options.workerSha256)return rejected('PARSER_PIN');
   const body=Buffer.from(JSON.stringify({kind,data:Buffer.from(input).toString('base64')}));
   const output=await new Promise<string>((resolve,reject)=>{
    const child=spawn(this.options.python,['-I',this.options.worker],{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',PYTHONHASHSEED:'0'},cwd:'/'});let n=0;const chunks:Buffer[]=[];let done=false;
    const fail=()=>{if(done)return;done=true;child.kill('SIGKILL');reject(new Error('PARSER_FAILURE'));};
    const timer=setTimeout(fail,this.options.timeoutMs??12000);
    child.stdout.on('data',(b:Buffer)=>{n+=b.length;if(n>2097152)fail();else chunks.push(b);});child.stderr.on('data',()=>{});child.on('error',fail);child.stdin.on('error',fail);
    child.on('close',code=>{clearTimeout(timer);if(done)return;done=true;if(code!==0)reject(new Error('PARSER_FAILURE'));else resolve(Buffer.concat(chunks).toString('utf8'));});child.stdin.end(body);
   });
   const r=parseJsonStrict(output,8,10000) as {ok:boolean;segments:string[];reason?:string;sandbox?:string};
   if(r.ok!==true||r.sandbox!=='linux-seccomp-no-network-filesystem-open-exec')return rejected(r.reason&&/^[A-Z_]{1,64}$/.test(r.reason)?r.reason:'PARSER_FAILURE');
   if(!Array.isArray(r.segments)||r.segments.length>1000||r.segments.some(s=>typeof s!=='string'))return rejected('PARSER_RESPONSE');
   const text=r.segments.join('\n\n');if(Buffer.byteLength(text)>524288)return rejected('PARSER_TEXT_LIMIT');
   const result=await this.options.protector.protect(text);
   if(result.output===null||!['allow','redact'].includes(result.decision))return rejected('DOCUMENT_POLICY',result.decision==='review');
   return {decision:'redact',output:Buffer.from(result.output,'utf8'),mime:'text/plain',filename:'aidr-sanitized.txt',reason:'TEXT_ONLY_RECONSTRUCTION'};
  }catch{return rejected('PARSER_FAILURE');}finally{this.#active--;}
 }
}
