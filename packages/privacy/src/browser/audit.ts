import { ENTITY_TYPES, type EntityType } from '../types.js';
import { PROVIDER_IDS, type Provider } from './providers.js';
export const AUDIT_DECISIONS=['allow','redact','block','review','insert','file-block'] as const;
export type AuditDecision=typeof AUDIT_DECISIONS[number];
export interface AuditSnapshot {schemaVersion:1;days:Record<string,Partial<Record<Provider,Partial<Record<AuditDecision,number>>>>>;typesByDay:Record<string,Partial<Record<EntityType,number>>>;types:Partial<Record<EntityType,number>>;}
const record=(x:unknown):Record<string,unknown>=>x!==null&&typeof x==='object'&&!Array.isArray(x)?x as Record<string,unknown>:{};
const count=(n:unknown):number=>Number.isSafeInteger(n)&&(n as number)>=0&&(n as number)<=99999999?n as number:0;
/** Fixed-schema, bounded, retention-filtered metadata. Never forward arbitrary storage fields. */
export function sanitizeAudit(raw:unknown,retentionDays:number,now=Date.now()):AuditSnapshot {
 const out:AuditSnapshot={schemaVersion:1,days:{},typesByDay:{},types:{}};
 if(!Number.isInteger(retentionDays)||retentionDays<1||retentionDays>30)return out;
 const src=record(raw),days=record(src.days),types=record(src.typesByDay);
 for(let offset=retentionDays-1;offset>=0;offset--){
  const day=new Date(now-offset*86400000).toISOString().slice(0,10),old=record(days[day]),bucket:AuditSnapshot['days'][string]={};
  for(const provider of PROVIDER_IDS){const p=record(old[provider]),dst:Partial<Record<AuditDecision,number>>={};for(const d of AUDIT_DECISIONS){const n=count(p[d]);if(n)dst[d]=n;}if(Object.keys(dst).length)bucket[provider]=dst;}
  if(Object.keys(bucket).length)out.days[day]=bucket;
  const t=record(types[day]),dst:Partial<Record<EntityType,number>>={};for(const type of ENTITY_TYPES){const n=count(t[type]);if(n){dst[type]=n;out.types[type]=Math.min(99999999,(out.types[type]??0)+n);}}
  if(Object.keys(dst).length)out.typesByDay[day]=dst;
 }
 return out;
}
export function appendAudit(raw:unknown,retentionDays:number,provider:Provider,decision:AuditDecision,counts:unknown,now=Date.now()):AuditSnapshot {
 const out=sanitizeAudit(raw,retentionDays,now);if(!retentionDays||!PROVIDER_IDS.includes(provider)||!AUDIT_DECISIONS.includes(decision))return out;
 const day=new Date(now).toISOString().slice(0,10),bucket=(out.days[day]??={}),p=(bucket[provider]??={});p[decision]=Math.min(99999999,(p[decision]??0)+1);
 const c=record(counts),t=(out.typesByDay[day]??={});for(const type of ENTITY_TYPES){const n=count(c[type]);if(n){t[type]=Math.min(99999999,(t[type]??0)+n);out.types[type]=Math.min(99999999,(out.types[type]??0)+n);}}
 if(!Object.keys(t).length)delete out.typesByDay[day];return out;
}
