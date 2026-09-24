import { parseJsonStrict } from '../json.js';
import { LiteralMatcher } from '../dictionary.js';
import { ENTITY_TYPES, type EntityType, type LiteralRule } from '../types.js';
import { PROVIDER_IDS, type Provider } from './providers.js';
export interface BrowserPolicy {
  readonly injectionAction:'off'|'review'|'block';readonly sourceCodeAction:'off'|'review'|'block';
  readonly version:1;readonly id:string;readonly mode:'guard'|'secure-compose'|'block';
  readonly textAction:'redact'|'block';readonly requireNativeText:boolean;
  readonly fileHandling:'sanitize'|'block';readonly maxTextBytes:number;readonly maxFileBytes:number;
  readonly blockSites:readonly Provider[];readonly literals:readonly LiteralRule[];
  readonly retentionDays:number;
}
export const DEFAULT_POLICY:BrowserPolicy=Object.freeze({injectionAction:'review',sourceCodeAction:'off',version:1,id:'aidr-browser-default-v1',mode:'guard',textAction:'redact',requireNativeText:false,
  fileHandling:'sanitize',maxTextBytes:65536,maxFileBytes:8388608,blockSites:Object.freeze([]),literals:Object.freeze([]),retentionDays:7});
const KEYS=new Set(Object.keys(DEFAULT_POLICY));
function bad():never{throw new Error('POLICY_INVALID');}
function int(x:unknown,min:number,max:number):number {if(!Number.isSafeInteger(x)||(x as number)<min||(x as number)>max)bad();return x as number;}
/** Only administrator-managed PolicyJSON is accepted; malformed policy quarantines, never defaults. */
export function parsePolicy(raw:unknown):BrowserPolicy {
  if(raw===undefined)return DEFAULT_POLICY;
  if(typeof raw!=='string'||raw.length>131072)bad();
  let x:unknown;try{x=parseJsonStrict(raw,8,10000);}catch{bad();}
  if(!x||Array.isArray(x)||typeof x!=='object'||Object.keys(x).some(k=>!KEYS.has(k)))bad();
  const v={...DEFAULT_POLICY,...x} as Record<string,unknown>;
  if(!['off','review','block'].includes(v.injectionAction as string)||!['off','review','block'].includes(v.sourceCodeAction as string))bad();
  if(v.version!==1||typeof v.id!=='string'||!/^[A-Za-z0-9_.-]{1,64}$/.test(v.id))bad();
  if(!['guard','secure-compose','block'].includes(v.mode as string)||!['redact','block'].includes(v.textAction as string)
    ||typeof v.requireNativeText!=='boolean'||!['sanitize','block'].includes(v.fileHandling as string))bad();
  int(v.maxTextBytes,256,262144);int(v.maxFileBytes,1024,8388608);int(v.retentionDays,0,30);
  if(!Array.isArray(v.blockSites)||v.blockSites.length>3||v.blockSites.some(p=>!PROVIDER_IDS.includes(p as Provider))||new Set(v.blockSites).size!==v.blockSites.length)bad();
  if(!Array.isArray(v.literals)||v.literals.length>1024)bad();
  const literals:LiteralRule[]=[];
  for(const r of v.literals){if(!r||typeof r!=='object'||Object.keys(r).some(k=>!['value','type'].includes(k))||typeof r.value!=='string'||!ENTITY_TYPES.includes(r.type as EntityType))bad();
    literals.push(Object.freeze({value:r.value,type:r.type as EntityType}));}
  try{new LiteralMatcher(literals);}catch{bad();}
  return Object.freeze({...v,literals:Object.freeze(literals),blockSites:Object.freeze([...v.blockSites])}) as unknown as BrowserPolicy;
}
export function policyView(p:BrowserPolicy,epoch:string) {
  return Object.freeze({injectionAction:p.injectionAction,sourceCodeAction:p.sourceCodeAction,id:p.id,mode:p.mode,textAction:p.textAction,requireNativeText:p.requireNativeText,
    fileHandling:p.fileHandling,maxTextBytes:p.maxTextBytes,maxFileBytes:p.maxFileBytes,blockSites:p.blockSites,epoch});
}
export type PolicyView=ReturnType<typeof policyView>;
export function blockedRules(p:BrowserPolicy|null) {
  const ids=p?(p.mode==='block'?PROVIDER_IDS:p.blockSites):PROVIDER_IDS;
  const domains=ids.flatMap(id=>id==='chatgpt'?['chatgpt.com','chat.openai.com']:id==='gemini'?['gemini.google.com']:['claude.ai']);
  if(!domains.length)return [];
  return [
    {id:91001,priority:100,action:{type:'block' as const},condition:{requestDomains:domains}},
    {id:91002,priority:100,action:{type:'block' as const},condition:{initiatorDomains:domains}},
  ];
}
