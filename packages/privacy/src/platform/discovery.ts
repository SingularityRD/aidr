import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash, type KeyObject, sign, verify } from 'node:crypto';
import { canonical,id,integer,deny,frozen } from '../enterprise/util.js';
import { parseJsonStrict } from '../json.js';
import { PinnedJwtVerifier } from './identity.js';
import type { TenantState } from './state.js';
export interface CatalogEntry {id:string;domains:readonly string[];category:'ai'|'mcp';risk:'approved'|'review'|'blocked';}
export interface RiskCatalog {version:number;expiresAt:number;entries:readonly CatalogEntry[];}
export function signCatalog(catalog:RiskCatalog,key:KeyObject):{catalog:RiskCatalog;signature:string}{return {catalog,signature:sign(null,Buffer.from(canonical(catalog)),key).toString('base64url')};}
/** Ingest only explicit, authorized collectors. Never trusts browser-provided source/tenant IDs. */
export class DiscoveryInventory {
 #catalog:RiskCatalog|null=null;
 constructor(private state:TenantState,private verifier:PinnedJwtVerifier,private catalogKey:KeyObject,private sources:readonly string[],private clock:()=>number=Date.now){}
 install(envelope:{catalog:RiskCatalog;signature:string}):void{const c=envelope.catalog;integer(c.version,1);integer(c.expiresAt,this.clock()+1);if(catalogBytes(c)>524288||!verify(null,Buffer.from(canonical(c)),this.catalogKey,Buffer.from(envelope.signature,'base64url')))deny('CATALOG_SIGNATURE');
  const seen=new Set<string>();for(const e of c.entries){id(e.id);if(!['ai','mcp'].includes(e.category)||!['approved','review','blocked'].includes(e.risk))deny('CATALOG_SCHEMA');for(const d of e.domains){if(!/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(d)||d.includes('..')||seen.has(d))deny('CATALOG_DOMAIN');seen.add(d);}}
  this.state.transaction(tx=>{const old=tx.get<number>('catalog','revision');if(old&&c.version<=old.value)deny('CATALOG_ROLLBACK');tx.put('catalog','revision',c.version,old?.version??null);tx.put('catalog','active',c,tx.get('catalog','active')?.version??null);tx.event('CATALOG_INSTALLED','system','catalog',this.clock());});this.#catalog=frozen(c);
 }
 ingest(signedBatch:string):number {const now=this.clock(),c=this.verifier.verify(signedBatch,now);if(c.tenant_id!==this.state.tenantId||!this.sources.includes(c.sub)||c.source_id!==c.sub)deny('TELEMETRY_SOURCE');integer(c.sequence,1);if(!Array.isArray(c.observations)||c.observations.length>100)deny('TELEMETRY_SCHEMA');
  const catalog=this.state.get<RiskCatalog>('catalog','active')?.value;if(!catalog||now>=catalog.expiresAt)deny('CATALOG_EXPIRED');
  const events=(c.observations as Record<string,unknown>[]).map(o=>{if(Object.keys(o).some(k=>!['destination','kind','at'].includes(k)))deny('TELEMETRY_SCHEMA');integer(o.at,now-300000,now+15000);if(!['ai','mcp'].includes(o.kind as string)||typeof o.destination!=='string')deny('TELEMETRY_SCHEMA');const u=new URL(o.destination);if(u.protocol!=='https:'||u.username||u.password)deny('TELEMETRY_DESTINATION');
   const e=catalog.entries.find(e=>e.domains.includes(u.hostname)&&e.category===o.kind);return {origin:u.origin,kind:o.kind,at:o.at,appId:e?.id??'uncatalogued',risk:e?.risk??'review',catalogVersion:catalog.version};});
  this.state.transaction(tx=>{const previous=tx.get<number>('collector-sequence',c.sub);if((c.sequence as number)!==(previous?.value??0)+1)deny('TELEMETRY_SEQUENCE');for(const e of events){const key=createHash('sha256').update(canonical([c.sub,e.origin,e.kind])).digest('hex'),old=tx.get<{count:number}>('inventory',key);tx.put('inventory',key,{...e,count:(old?.value.count??0)+1,source:c.sub},old?.version??null);}tx.put('collector-sequence',c.sub,c.sequence,previous?.version??null);tx.event('TELEMETRY_INGESTED',c.sub,'inventory',now);});return events.length;
 }
 list():readonly unknown[]{return this.state.list('inventory',1000).map(x=>x.cell.value);}
}
function catalogBytes(c:RiskCatalog):number{return Buffer.byteLength(canonical(c,524288));}
export interface McpObservation {serverRef:string;transport:'https'|'stdio';origin:string|null;configurationDigest:string;}
/** Reads only the explicit administrator-approved local config path. Does NOT execute tools,
 * read arbitrary home folders, log env/arguments, or probe remote MCP servers. */
export function discoverMcpConfig(path:string,expectedRealPath:string):readonly McpObservation[]{
 const p=resolve(path),s=lstatSync(p);if(!s.isFile()||s.isSymbolicLink()||s.size>1048576||realpathSync(p)!==expectedRealPath)deny('MCP_CONFIG_PATH');const b=readFileSync(p);const c=parseJsonStrict(b.toString('utf8'),16,50000) as Record<string,unknown>;
 const servers=c.mcpServers;if(!servers||typeof servers!=='object'||Array.isArray(servers)||Object.keys(servers).length>100)deny('MCP_CONFIG_SCHEMA');const out:McpObservation[]=[];
 for(const [name,value]of Object.entries(servers)){if(!value||typeof value!=='object'||Array.isArray(value))deny('MCP_CONFIG_SCHEMA');const o=value as Record<string,unknown>;let transport:McpObservation['transport'],origin:string|null=null;
  if(typeof o.url==='string'){const u=new URL(o.url);if(u.protocol!=='https:'||u.username||u.password)deny('MCP_CONFIG_URL');transport='https';origin=u.origin;}
  else if(typeof o.command==='string'){transport='stdio';}else deny('MCP_CONFIG_SCHEMA');
  out.push({serverRef:createHash('sha256').update(name).digest('hex'),transport,origin,configurationDigest:createHash('sha256').update(canonical(o)).digest('hex')});
 }
 return frozen(out);
}
