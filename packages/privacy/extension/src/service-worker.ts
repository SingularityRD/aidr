import { sanitizeAudit, appendAudit, AUDIT_DECISIONS, type AuditDecision } from '../../src/browser/audit.js';
import { BrowserPrivacyEngine } from '../../src/browser/engine.js';
import { parsePolicy, policyView, blockedRules, type BrowserPolicy } from '../../src/browser/policy.js';
import { providerForUrl, approvedOrigin, MATCHES, PROVIDERS, type Provider } from '../../src/browser/providers.js';
import { ENTITY_TYPES, type EntityType } from '../../src/types.js';
import { protectDocument, type DocumentKind } from '../../src/browser/documents.js';
import { fromBase64, toBase64, sha256, TicketVault, type Binding } from '../../src/browser/transport.js';
import { nativeCall } from './native-client.js';
let policy:BrowserPolicy|null=null,epoch=crypto.randomUUID(),digest='',scanner:BrowserPrivacyEngine|undefined,initializing:Promise<void>;
let healthy=false,active=0,revision=0;
interface SafeValue {kind:'text'|'image'|'document';text?:string;data?:string;filename?:string;contentType?:string;}
const tickets=new TicketVault<SafeValue>();
const rate=new Map<string,{at:number;n:number}>();
const safeReasons=(v:unknown):string[]=>Array.isArray(v)?v.filter(x=>typeof x==='string'&&/^[A-Z0-9_]{1,64}$/.test(x)).slice(0,12):['SCAN_DENIED'];
const deny=(code:string)=>({ok:false,decision:'block',output:null,reasons:[code],epoch});
function ensure():BrowserPolicy{if(!healthy||!policy||!scanner)throw new Error('POLICY_UNAVAILABLE');return policy;}
function ui(sender:ChromeSender):boolean {
  if(sender.id!==chrome.runtime.id||typeof sender.url!=='string')return false;
  try{const u=new URL(sender.url);return u.protocol==='chrome-extension:'&&u.hostname===chrome.runtime.id&&u.pathname==='/compose.html';}catch{return false;}
}
function page(sender:ChromeSender):{provider:Provider;tabId:number} {
  const p=providerForUrl(sender.url);
  if(sender.id!==chrome.runtime.id||!p||sender.frameId!==0||!Number.isSafeInteger(sender.tab?.id)||!sender.documentId)throw new Error('SENDER_DENIED');
  return {provider:p,tabId:sender.tab!.id!};
}
function allowed(p:BrowserPolicy,provider:Provider):void{if(p.mode==='block'||p.blockSites.includes(provider))throw new Error('SITE_BLOCKED');}
function limit(key:string):void{const now=Date.now();if(rate.size>100)rate.clear();let x=rate.get(key);if(!x||now-x.at>60000){x={at:now,n:0};rate.set(key,x);}if(++x.n>300)throw new Error('RATE_LIMIT');}
function counts(raw:unknown):Partial<Record<EntityType,number>> {
  const out:Partial<Record<EntityType,number>>={};if(raw&&typeof raw==='object')for(const t of ENTITY_TYPES){const n=(raw as Record<string,unknown>)[t];if(Number.isSafeInteger(n)&&(n as number)>0&&(n as number)<100000)out[t]=n as number;}return out;
}
let auditQueue:Promise<unknown>=Promise.resolve();
function record(provider:Provider,decision:string,rawCounts:unknown):Promise<unknown> {
  const p=policy;if(!p||!p.retentionDays)return Promise.resolve();const c=counts(rawCounts);
  auditQueue=auditQueue.catch(()=>{}).then(async()=>{
    const stored=await chrome.storage.local.get('audit');
    if(AUDIT_DECISIONS.includes(decision as AuditDecision))await chrome.storage.local.set({audit:appendAudit(stored.audit,p.retentionDays,provider,decision as AuditDecision,c)});
  });return auditQueue;
}
async function reload():Promise<void>{
  const rev=++revision;healthy=false;policy=null;scanner=undefined;tickets.clear();epoch=crypto.randomUUID();
  try{
    await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:[91001,91002],addRules:blockedRules(null)});
    const stored=await chrome.storage.managed.get('PolicyJSON');
    const latch=await chrome.storage.local.get('managedPolicyRequired');
    if(stored.PolicyJSON===undefined&&latch.managedPolicyRequired===true)throw new Error('MANAGED_POLICY_MISSING');
    if(stored.PolicyJSON!==undefined)await chrome.storage.local.set({managedPolicyRequired:true});
    const next=parsePolicy(stored.PolicyJSON);
    const nextDigest=await sha256(new TextEncoder().encode(JSON.stringify(next)));if(rev!==revision)return;
    const actions=Object.fromEntries(ENTITY_TYPES.map(t=>[t,next.textAction==='block'||['SECRET','PRIVATE_KEY','INTERNAL','CLASSIFIED'].includes(t)?'block':'redact'])) as Partial<Record<EntityType,'block'|'redact'>>;
    const engine=new BrowserPrivacyEngine({injectionAction:next.injectionAction,sourceCodeAction:next.sourceCodeAction,policyId:next.id,literals:next.literals,actions,maxInputBytes:Math.max(next.maxTextBytes,1048576)});
    await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:[91001,91002],addRules:blockedRules(next)});
    if(rev!==revision)return;policy=next;digest=nextDigest;scanner=engine;healthy=true;
    const local=await chrome.storage.local.get('audit');await chrome.storage.local.set({audit:sanitizeAudit(local.audit,next.retentionDays)});
    await chrome.action.setBadgeText({text:next.mode==='block'?'BLK':''});
  }catch{if(rev===revision){healthy=false;policy=null;await chrome.action.setBadgeText({text:'!'}).catch(()=>{});}}
  const tabs=await chrome.tabs.query({url:MATCHES}).catch(()=>[]);
  for(const tab of tabs)if(tab.id)void chrome.tabs.sendMessage(tab.id,{type:'POLICY_CHANGED',epoch},{frameId:0}).catch(()=>{});
}
async function boot():Promise<void>{
  try{await Promise.all([chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}),chrome.storage.managed.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}),chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'})]);}catch{healthy=false;await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:[91001,91002],addRules:blockedRules(null)}).catch(()=>{});return;}
  await reload();
}
initializing=boot();
chrome.storage.onChanged.addListener((_changes,area)=>{if(area==='managed')initializing=initializing.catch(()=>{}).then(reload);});
async function binding(tabId:unknown):Promise<Binding&{provider:Provider}> {
  if(!Number.isSafeInteger(tabId))throw new Error('TAB_DENIED');const tab=await chrome.tabs.get(tabId as number),origin=approvedOrigin(tab.url),provider=providerForUrl(tab.url);
  if(!origin||!provider)throw new Error('TAB_DENIED');allowed(ensure(),provider);
  const probe=await chrome.tabs.sendMessage(tabId as number,{type:'PROBE'},{frameId:0});
  if(!probe||probe.ok!==true||probe.epoch!==epoch||typeof probe.documentToken!=='string'||!/^[a-f0-9-]{36}$/.test(probe.documentToken)||probe.origin!==origin)throw new Error('ADAPTER_UNAVAILABLE');
  return {tabId:tabId as number,origin,provider,documentToken:probe.documentToken,epoch};
}
async function scanText(text:unknown,native:boolean):Promise<any>{
  const p=ensure(),startEpoch=epoch,engine=scanner!;
  if(typeof text!=='string'||text.length>p.maxTextBytes||new TextEncoder().encode(text).length>p.maxTextBytes)throw new Error('INPUT_LIMIT');
  const local=engine.protect(text);
  if(local.output===null)return {ok:true,decision:local.decision,output:null,counts:local.audit.counts,reasons:local.reasons,epoch,coverage:'rules-only'};
  if(native&&p.requireNativeText&&text.length){
    const r=await nativeCall('text',new TextEncoder().encode(text),digest);
    if(epoch!==startEpoch||!healthy)throw new Error('POLICY_CHANGED');
    if(!r.bytes)return {ok:true,decision:r.meta.decision,output:null,counts:counts(r.meta.counts),reasons:safeReasons(r.meta.reasons),epoch,coverage:r.meta.coverage};
    // A rules-only native host cannot satisfy a requireNativeText policy.
    if(r.meta.coverage!=='rules-and-ner')throw new Error('NATIVE_NER_REQUIRED');
    const output=new TextDecoder('utf-8',{fatal:true}).decode(r.bytes);r.bytes.fill(0);const final=engine.protect(output);
    if(final.output===null)return {ok:true,decision:final.decision,output:null,counts:final.audit.counts,reasons:final.reasons,epoch,coverage:'rules-and-ner'};
    return {ok:true,decision:local.decision==='redact'||r.meta.decision==='redact'||final.decision==='redact'?'redact':'allow',output:final.output,counts:counts({...r.meta.counts,...local.audit.counts}),reasons:[],epoch,coverage:'rules-and-ner'};
  }
  return {ok:true,decision:local.decision,output:local.output,counts:local.audit.counts,reasons:local.reasons,epoch,coverage:'rules-only'};
}
async function handle(m:any,sender:ChromeSender):Promise<any>{
  if(!m||typeof m!=='object'||Array.isArray(m)||typeof m.type!=='string'||sender.id!==chrome.runtime.id)throw new Error('MESSAGE_DENIED');
  await initializing;const p=ensure(),isUi=ui(sender);const ctx=isUi?null:page(sender);limit(isUi?'ui':`tab-${ctx!.tabId}`);
  if(ctx)allowed(p,ctx.provider);
  if(m.type==='POLICY'){if(isUi)throw new Error('MESSAGE_DENIED');return {ok:true,policy:policyView(p,epoch)};}
  if(m.type==='SCAN'){
    if(isUi||!['preview','submit','paste','redact'].includes(m.purpose))throw new Error('MESSAGE_DENIED');
    const r=await scanText(m.text,m.purpose!=='preview');if(m.purpose!=='preview')await record(ctx!.provider,r.decision,r.counts);return r;
  }
  if(m.type==='FILE_BLOCK'){if(isUi)throw new Error('MESSAGE_DENIED');await record(ctx!.provider,'file-block',{});return {ok:true};}
  if(m.type==='OPEN_COMPOSER'){
    if(isUi)throw new Error('MESSAGE_DENIED');await chrome.windows.create({url:chrome.runtime.getURL(`compose.html?tab=${ctx!.tabId}`),type:'popup',width:720,height:860});return {ok:true};
  }
  if(!isUi)throw new Error('MESSAGE_DENIED');
  if(m.type==='STATUS'){
    const tabs=await chrome.tabs.query({url:MATCHES});return {ok:true,policy:policyView(p,epoch),native:'not-probed',targets:tabs.filter(t=>t.id&&providerForUrl(t.url)).map(t=>({id:t.id,provider:providerForUrl(t.url),active:t.active===true}))};
  }
  if(m.type==='AUDIT'){await auditQueue;const stored=await chrome.storage.local.get('audit'),audit=sanitizeAudit(stored.audit,p.retentionDays);await chrome.storage.local.set({audit});return {ok:true,audit};}
  if(m.type==='HEALTH'){const r=await nativeCall('health',new Uint8Array(),digest);return {ok:true,local:r.meta.local,ocr:r.meta.ocr,policyId:r.meta.policyId};}
  if(m.type==='COMPOSE_SCAN'){
    const b=await binding(m.tabId),r=await scanText(m.text,true);if(epoch!==b.epoch)throw new Error('POLICY_CHANGED');await record(b.provider,r.decision,r.counts);
    if(r.output===null)return r;const ticket=tickets.issue({kind:'text',text:r.output},b,new TextEncoder().encode(r.output).length);return {...r,ticket};
  }
  if(m.type==='SANITIZE_FILE'){
    if(p.fileHandling!=='sanitize')throw new Error('FILES_BLOCKED');const b=await binding(m.tabId);
    if(!['image','text','json','csv','tsv'].includes(m.kind))throw new Error('FILE_TYPE_DENIED');
    const bytes=fromBase64(m.data,Math.min(m.kind==='image'?p.maxFileBytes:1048576,p.maxFileBytes));if(!bytes.length)throw new Error('FILE_EMPTY');
    try{
      let value:SafeValue,decision:string,reason:string[]=[],c:Record<string,number>={};
      if(m.kind==='image'){
        const r=await nativeCall('image',bytes,digest);if(epoch!==b.epoch||!healthy)throw new Error('POLICY_CHANGED');
        if(!r.bytes){await record(b.provider,r.meta.decision,{});return {ok:true,decision:r.meta.decision,output:null,reasons:safeReasons(r.meta.reasons),epoch};}
        if(r.meta.contentType!=='image/png'||r.meta.filename!=='aidr-sanitized.png'||r.meta.verification!=='pixel-and-residual-scan')throw new Error('IMAGE_VERIFICATION_MISSING');
        if(p.requireNativeText&&r.meta.coverage!=='rules-and-ner')throw new Error('NATIVE_NER_REQUIRED');
        value={kind:'image',data:toBase64(r.bytes),filename:'aidr-sanitized.png',contentType:'image/png'};r.bytes.fill(0);decision=r.meta.decision;
      }else{
        let text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
        if(p.requireNativeText){const r=await nativeCall(m.kind,bytes,digest);if(!r.bytes)return {ok:true,decision:r.meta.decision,output:null,reasons:safeReasons(r.meta.reasons),epoch};
          if(r.meta.coverage!=='rules-and-ner')throw new Error('NATIVE_NER_REQUIRED');text=new TextDecoder('utf-8',{fatal:true}).decode(r.bytes);r.bytes.fill(0);}
        const r=await protectDocument(text,m.kind as DocumentKind,scanner!,1048576);if(r.output===null)return {ok:true,...r,epoch};
        value={kind:'document',data:toBase64(new TextEncoder().encode(r.output)),filename:r.filename!,contentType:r.contentType!};decision=r.decision;reason=[...r.reasons];c=counts(r.counts);
      }
      if(epoch!==b.epoch||!healthy)throw new Error('POLICY_CHANGED');await record(b.provider,decision,c);
      const ticket=tickets.issue(value,b,value.data!.length);return {ok:true,decision,reasons:reason,epoch,ticket,...value};
    }finally{bytes.fill(0);}
  }
  if(m.type==='APPLY'){
    const b=await binding(m.tabId),value=tickets.consume(m.ticket,b);
    // Revalidate binding immediately before use. A document navigation invalidates the recipient token too.
    const result=await chrome.tabs.sendMessage(b.tabId,{type:'APPLY_SAFE',epoch:b.epoch,documentToken:b.documentToken,value},{frameId:0});
    if(!result||result.ok!==true)throw new Error('ADAPTER_APPLY_FAILED');await record(b.provider,'insert',{});return {ok:true};
  }
  throw new Error('MESSAGE_DENIED');
}
chrome.runtime.onMessage.addListener((m,sender,sendResponse)=>{
  // A bounded active set, plus per-context rate limits. Rejection never contains raw exceptions.
  if(active>=8){sendResponse(deny('CONCURRENCY_LIMIT'));return;}
  active++;void handle(m,sender).then(sendResponse).catch(e=>sendResponse(deny(e instanceof Error&&/^[A-Z0-9_]{1,64}$/.test(e.message)?e.message:'EXTENSION_FAILURE'))).finally(()=>{active--;});return true;
});
