import { createHash, sign, verify, type KeyObject } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync, readdirSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { parseJsonStrict } from '../json.js';
import { canonical, deny, integer, frozen } from '../enterprise/util.js';
export interface TensorInspection {tensors:number;parameters:string;dataBytes:number;}
/** Structural check only: no pickle, imports, inference or arbitrary model code is executed. */
export function inspectSafetensors(bytes:Uint8Array):TensorInspection{
 const b=Buffer.from(bytes);if(b.length<10||b.length>268435456)deny('TENSOR_SIZE');const n=Number(b.readBigUInt64LE(0));if(!Number.isSafeInteger(n)||n<2||n>1048576||8+n>b.length||b[8]!==123)deny('TENSOR_HEADER');
 const h=parseJsonStrict(new TextDecoder('utf8',{fatal:true}).decode(b.subarray(8,8+n)),12,100000);if(!h||typeof h!=='object'||Array.isArray(h))deny('TENSOR_HEADER');const widths:Record<string,number>={BOOL:1,U8:1,I8:1,F8_E4M3:1,F8_E5M2:1,I16:2,U16:2,F16:2,BF16:2,I32:4,U32:4,F32:4,I64:8,U64:8,F64:8};const ranges:{s:number;e:number}[]=[];let parameters=0n;
 for(const [name,v]of Object.entries(h)){if(name==='__metadata__'){if(!v||typeof v!=='object'||Array.isArray(v)||Object.values(v).some(x=>typeof x!=='string'))deny('TENSOR_METADATA');continue;}
  if(!v||typeof v!=='object'||Array.isArray(v))deny('TENSOR_SCHEMA');const r=v as Record<string,unknown>;if(Object.keys(r).sort().join(',')!=='data_offsets,dtype,shape'||typeof r.dtype!=='string'||!widths[r.dtype]||!Array.isArray(r.shape)||r.shape.length>16||!Array.isArray(r.data_offsets)||r.data_offsets.length!==2)deny('TENSOR_SCHEMA');let count=1n;
  for(const dim of r.shape){integer(dim,0,2147483647);count*=BigInt(dim as number);if(count>2147483648n)deny('TENSOR_SHAPE');}const [s,e]=r.data_offsets as number[];integer(s,0,b.length);integer(e,s!,b.length);if(BigInt(e!-s!)!==count*BigInt(widths[r.dtype]!))deny('TENSOR_LENGTH');ranges.push({s:s!,e:e!});parameters+=count;
 }
 ranges.sort((a,b)=>a.s-b.s||a.e-b.e);let end=0;for(const r of ranges){if(r.s!==end)deny('TENSOR_OVERLAP_OR_HOLE');end=r.e;}if(end!==b.length-8-n)deny('TENSOR_TRAILING_DATA');return {tensors:ranges.length,parameters:parameters.toString(),dataBytes:end};
}
export interface ReleaseManifest {format:'aidr-release-v1';version:string;files:Readonly<Record<string,string>>;}
export function manifestFor(root:string,version:string):ReleaseManifest{
 const base=resolve(root);if(realpathSync(base)!==base)deny('RELEASE_ROOT');const files:Record<string,string>={};let total=0;
 const walk=(dir:string,depth:number)=>{if(depth>12)deny('RELEASE_DEPTH');for(const name of readdirSync(dir).sort()){const p=join(dir,name),s=lstatSync(p);if(s.isSymbolicLink())deny('RELEASE_SYMLINK');if(s.isDirectory()){walk(p,depth+1);continue;}if(!s.isFile()||s.nlink!==1||s.size>268435456||Object.keys(files).length>=20000||(total+=s.size)>536870912)deny('RELEASE_FILE');const rel=relative(base,p).replaceAll('\\','/');files[rel]=createHash('sha256').update(readFileSync(p)).digest('hex');}};walk(base,0);return frozen({format:'aidr-release-v1',version,files});
}
export function signRelease(manifest:ReleaseManifest,key:KeyObject):string{return sign(null,Buffer.from(canonical(manifest,4194304)),key).toString('base64url');}
export function verifyRelease(root:string,manifest:ReleaseManifest,signature:string,key:KeyObject):boolean{try{return manifest.format==='aidr-release-v1'&&verify(null,Buffer.from(canonical(manifest,4194304)),key,Buffer.from(signature,'base64url'))&&canonical(manifestFor(root,manifest.version),4194304)===canonical(manifest,4194304);}catch{return false;}}
export function inspectModelDirectory(root:string,allowedLicenses:readonly string[],license:string){
 if(!allowedLicenses.includes(license))deny('MODEL_LICENSE');const manifest=manifestFor(root,'inspection');const tensors:Record<string,TensorInspection>={};
 for(const path of Object.keys(manifest.files)){
  if(!/\.(json|txt|md|safetensors|model|vocab|merges)$/i.test(path)||/\.(pkl|pickle|pt|pth|bin|py|so|dll|exe|js)$/i.test(path))deny('MODEL_EXECUTABLE_FORMAT');
  const b=readFileSync(join(root,path));if(path.endsWith('.safetensors'))tensors[path]=inspectSafetensors(b);
  if(path.endsWith('.json')){const c=parseJsonStrict(b.toString('utf8'),32,200000);const stack:unknown[]=[c];while(stack.length){const v=stack.pop();if(v&&typeof v==='object'){for(const [k,x]of Object.entries(v)){if(k==='auto_map'||k==='trust_remote_code'&&x!==false)deny('MODEL_REMOTE_CODE');stack.push(x);}}}}
 }
 return frozen({manifest,tensors,license,vulnerabilityDatabaseChecked:false,modelBehaviorEvaluated:false});
}
