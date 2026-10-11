import { constants, closeSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, resolve, join, relative, extname } from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, id, integer, deny, frozen } from '../enterprise/util.js';
import type { TenantState } from './state.js';
import type { ContextResolver, AuthenticatedPrincipal } from './identity.js';
export type DataClass='public'|'internal'|'confidential'|'restricted';
export interface SourceDocument {id:string;text:string;groups:readonly string[];classification:DataClass;}
export interface SourceRecord {id:string;sourceId:string;generation:number;contentDigest:string;groups:readonly string[];classification:DataClass;text:string;}
/** Atomic complete snapshot replacement. Incomplete listings NEVER delete previous records.
 * Local encrypted store; provider-specific Drive/SharePoint ACL APIs are not implemented. */
export class DspmRepository {
 /** `admit` receives the complete record set the snapshot would leave and throws to refuse it before commit
  * (an over-capacity or unsupported index is rejected at synchronization, not discovered afterwards). */
 constructor(readonly state:TenantState,private identity:ContextResolver,private clock:()=>number=Date.now,private admit?:(records:readonly SourceRecord[])=>void){}
 replace(p:AuthenticatedPrincipal,sourceId:string,generation:number,documents:readonly SourceDocument[],complete:boolean):void{
  this.identity.assertPrincipal(p,'security-admin');id(sourceId);integer(generation,1);if(!complete||documents.length>1000)deny('DSPM_INCOMPLETE');const seen=new Set<string>();let total=0;
  const docs=documents.map(d=>{id(d.id);if(seen.has(d.id)||!['public','internal','confidential','restricted'].includes(d.classification)||!Array.isArray(d.groups)||d.groups.length>128||!d.groups.length||new Set(d.groups).size!==d.groups.length)deny('DSPM_SCHEMA');seen.add(d.id);for(const g of d.groups)id(g);if(typeof d.text!=='string'||Buffer.byteLength(d.text)>524288||(total+=Buffer.byteLength(d.text))>8388608)deny('DSPM_LIMIT');return {...d,sourceId,generation,contentDigest:createHash('sha256').update(d.text).digest('hex')};});
  this.state.transaction(tx=>{const old=tx.get<{generation:number;ids:string[]}>('dspm-sources',sourceId);if(old&&generation<=old.value.generation)deny('DSPM_GENERATION');
   for(const d of docs){const key=docKey(sourceId,d.id),row=tx.get('dspm-documents',key);tx.put('dspm-documents',key,d,row?.version??null);}
   for(const oldId of old?.value.ids??[])if(!seen.has(oldId)){const key=docKey(sourceId,oldId),row=tx.get('dspm-documents',key);if(row)tx.remove('dspm-documents',key,row.version);}
   tx.put('dspm-sources',sourceId,{generation,ids:docs.map(d=>d.id)},old?.version??null);
   // One row past the index capacity is enough to refuse an oversized total. A removal (empty snapshot) is
   // always admitted so an administrator can repair a store that is already over the supported size.
   if(this.admit&&docs.length)this.admit(tx.list('dspm-documents',1001).map(r=>r.cell.value as SourceRecord));
   const revision=tx.get<number>('dspm-policy','revision');tx.put('dspm-policy','revision',(revision?.value??0)+1,revision?.version??null);
   tx.event('SOURCE_SYNCHRONIZED',p.subjectId,sourceId,this.clock());
  });
 }
 read(p:AuthenticatedPrincipal,sourceId:string,documentId:string):SourceRecord{
  this.identity.assertPrincipal(p);const d=this.state.get<SourceRecord>('dspm-documents',docKey(id(sourceId),id(documentId)))?.value;if(!d||!d.groups.some(g=>p.groups.includes(g)))deny('DSPM_ACCESS');return frozen(d);
 }
 removeSource(p:AuthenticatedPrincipal,sourceId:string,generation:number):void{this.replace(p,sourceId,generation,[],true);}
}
function docKey(s:string,d:string):string{return createHash('sha256').update(canonical([s,d])).digest('hex');}
/** Explicit authorized root only. Symlinks, hardlinks, unsafe formats and in-flight changes block
 * the COMPLETE snapshot rather than silently omitting inaccessible files. No shell/remote APIs. */
export function readAuthorizedDirectory(options:{root:string;groups:readonly string[];classification:DataClass}):readonly SourceDocument[]{
 // Only an existing local directory is a source; a remote (SharePoint/Drive/S3/URL) location has no connector and is refused.
 let root='';try{if(typeof options.root==='string'&&isAbsolute(options.root))root=resolve(options.root);if(root&&(realpathSync(root)!==root||!lstatSync(root).isDirectory()))root='';}catch{root='';}if(!root)deny('SOURCE_ROOT');const docs:SourceDocument[]=[];let bytes=0;
 const walk=(dir:string,depth:number)=>{if(depth>8)deny('SOURCE_DEPTH');for(const name of readdirSync(dir).sort()){const path=join(dir,name),st=lstatSync(path);if(st.isSymbolicLink())deny('SOURCE_SYMLINK');if(st.isDirectory()){walk(path,depth+1);continue;}if(!st.isFile()||st.nlink!==1||st.size>524288||docs.length>=1000||!['.txt','.md','.csv','.tsv','.json','.ts','.js','.py','.rs','.go','.java','.c','.h','.yaml','.yml'].includes(extname(name).toLowerCase()))deny('SOURCE_FILE');
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);let b:Buffer;try{const before=fstatSync(fd);if(before.ino!==st.ino||before.dev!==st.dev||before.size!==st.size)deny('SOURCE_CHANGED');b=readFileSync(fd);const after=fstatSync(fd);if(after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs||b.length!==before.size)deny('SOURCE_CHANGED');}finally{closeSync(fd);}bytes+=b.length;if(bytes>8388608)deny('SOURCE_LIMIT');const text=new TextDecoder('utf8',{fatal:true}).decode(b),rel=relative(root,path);docs.push({id:createHash('sha256').update(rel).digest('hex'),text,groups:[...options.groups],classification:options.classification});
 }};walk(root,0);return frozen(docs);
}
