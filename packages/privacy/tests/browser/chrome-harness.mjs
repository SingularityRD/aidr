/** Chrome APIs only are mocks. The bundled policy/scanner/worker code is unmodified. */
import vm from 'node:vm';import fs from 'node:fs';import {webcrypto} from 'node:crypto';
export const ID='hmcbdjjldiobifmolecnmalilknnapcb';
function event(){const listeners=[];return {listeners,addListener:f=>listeners.push(f),removeListener:f=>{const i=listeners.indexOf(f);if(i>=0)listeners.splice(i,1);},emit:(...a)=>listeners.forEach(f=>f(...a))};}
export function workerHarness(policy){
 const onMessage=event(),onChanged=event(),state={managed:policy===undefined?{}:{PolicyJSON:typeof policy==='string'?policy:JSON.stringify(policy)},local:{},session:{},rules:[],badge:'',applied:[],opened:[],access:[],nativeCalls:0,failAuditStore:false,failBadge:false,auditStoreHook:null};
 let epoch='';const docs=new Map([[1,{id:1,url:'https://chatgpt.com/c/fixture',active:true,documentToken:crypto.randomUUID()}],[2,{id:2,url:'https://gemini.google.com/app/fixture',active:false,documentToken:crypto.randomUUID()}]]);
 const chrome={runtime:{id:ID,getURL:path=>`chrome-extension://${ID}/${path}`,onMessage,connectNative:()=>{state.nativeCalls++;throw Error('NATIVE_UNAVAILABLE');}},storage:{onChanged},
  tabs:{query:async()=>[...docs.values()],get:async id=>{if(!docs.has(id))throw Error('TAB_MISSING');return {...docs.get(id)};},sendMessage:async(id,m)=>{const d=docs.get(id);if(!d)throw Error('TAB_MISSING');if(m.type==='POLICY_CHANGED'){epoch=m.epoch;return {ok:true};}if(m.type==='PROBE')return {ok:true,epoch,origin:new URL(d.url).origin,documentToken:d.documentToken};if(m.type==='APPLY_SAFE'){state.applied.push({id,m});return {ok:true};}throw Error('BAD_TEST_MESSAGE');}},
  declarativeNetRequest:{updateDynamicRules:async x=>{state.rules=structuredClone(x.addRules);}},action:{setBadgeText:async x=>{if(state.failBadge)throw Error('BADGE_FAILED');state.badge=x.text;}},windows:{create:async x=>{state.opened.push(x);return {};}}};
 for(const area of ['managed','local','session'])chrome.storage[area]={get:async key=>key?{[key]:structuredClone(state[area][key])}:structuredClone(state[area]),set:async o=>{if(area==='local'&&'audit'in o){if(state.failAuditStore)throw Error('STORAGE_FAILED');await state.auditStoreHook?.(o.audit);}Object.assign(state[area],structuredClone(o));},setAccessLevel:async x=>{state.access.push({area,...x});}};
 const context=vm.createContext({chrome,crypto:webcrypto,URL,TextEncoder,TextDecoder,performance,setTimeout,clearTimeout,AbortController,AbortSignal,Uint8Array,ArrayBuffer,DataView,TextDecoderStream,btoa,atob,structuredClone,console});
 new vm.Script(fs.readFileSync('extension/chrome/service-worker.js','utf8'),{filename:'service-worker.js'}).runInContext(context);
 const ui={id:ID,url:`chrome-extension://${ID}/compose.html`};const page=(id=1)=>({id:ID,url:docs.get(id).url,frameId:0,tab:{id},documentId:docs.get(id).documentToken});
 const send=(message,sender=ui)=>new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('TEST_MESSAGE_TIMEOUT')),3000);const cb=r=>{clearTimeout(timer);resolve(structuredClone(r));};try{onMessage.listeners[0](structuredClone(message),sender,cb);}catch(e){clearTimeout(timer);reject(e);}});
 const setPolicy=async value=>{state.managed={PolicyJSON:typeof value==='string'?value:JSON.stringify(value)};onChanged.emit({},'managed');return send({type:'STATUS'});};
 return {send,state,docs,page,ui,setPolicy};
}
