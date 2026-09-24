/* TEST ONLY: API broker, no extension install or origin-isolation claim. */
(() => {
 const ID='hmcbdjjldiobifmolecnmalilknnapcb';
 const event=()=>{const listeners=[];return {listeners,addListener:f=>listeners.push(f),removeListener:f=>{const i=listeners.indexOf(f);if(i>=0)listeners.splice(i,1);},emit:(...args)=>listeners.forEach(f=>f(...args))};};
 // about:blank is not a secure context in the policy-restricted runner. UUID uses
 // Chromium CSPRNG; SHA-256 is delegated to Python hashlib, not a fake digest.
 if(!crypto.randomUUID)Object.defineProperty(crypto,'randomUUID',{value:()=>{const b=crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;const x=[...b].map(v=>v.toString(16).padStart(2,'0')).join('');return `${x.slice(0,8)}-${x.slice(8,12)}-${x.slice(12,16)}-${x.slice(16,20)}-${x.slice(20)}`;}});
 if(!crypto.subtle)Object.defineProperty(crypto,'subtle',{value:{digest:async(name,bytes)=>{if(name!=='SHA-256')throw Error('TEST_ALGORITHM');return new Uint8Array(await window.__fixtureDigest(Array.from(new Uint8Array(bytes)))).buffer;}}});
 const H={id:ID,bg:event(),content:event(),storageChanged:event(),state:{managed:window.__fixturePolicy===undefined?{}:{PolicyJSON:typeof window.__fixturePolicy==='string'?window.__fixturePolicy:JSON.stringify(window.__fixturePolicy)},local:{},session:{},rules:[],applied:[],events:[],messages:[],opened:[]},tab:{id:1,url:window.__fixtureUrl,active:true},documentId:crypto.randomUUID(),UI:false};
 function dispatch(ev,m,sender){return new Promise((resolve,reject)=>{let done=false;const timer=setTimeout(()=>{if(!done)reject(Error('TEST_BROKER_TIMEOUT'));},4000),cb=r=>{if(!done){done=true;clearTimeout(timer);resolve(structuredClone(r));}};let async=false;for(const f of ev.listeners){if(f(structuredClone(m),structuredClone(sender),cb)===true)async=true;if(done)break;}if(!done&&!async){clearTimeout(timer);resolve(undefined);}});}
 const runtime={id:ID,getURL:path=>`chrome-extension://${ID}/${path}`};
 H.uiSender={id:ID,url:`chrome-extension://${ID}/compose.html`};H.pageSender=()=>({id:ID,url:H.tab.url,frameId:0,tab:{id:1},documentId:H.documentId});
 H.ui=m=>dispatch(H.bg,m,H.uiSender);H.page=m=>dispatch(H.bg,m,H.pageSender());
 H.bgChrome={runtime:{...runtime,onMessage:H.bg,connectNative:()=>{throw Error('NATIVE_UNAVAILABLE');}},storage:{onChanged:H.storageChanged},
 tabs:{query:async()=>[H.tab],get:async id=>{if(id!==1)throw Error('TAB_MISSING');return {...H.tab};},sendMessage:async(id,m)=>{if(id!==1)throw Error('TAB_MISSING');if(H.UI){if(m.type==='PROBE')return {ok:true,epoch:H.epoch,documentToken:H.documentId,origin:new URL(H.tab.url).origin};if(m.type==='POLICY_CHANGED'){H.epoch=m.epoch;return {ok:true};}if(m.type==='APPLY_SAFE'){H.state.applied.push(m);return {ok:true};}}return dispatch(H.content,m,{id:ID,url:`chrome-extension://${ID}/service-worker.js`});}},
 action:{setBadgeText:async()=>{}},declarativeNetRequest:{updateDynamicRules:async x=>{H.state.rules=x.addRules;}},windows:{create:async x=>{H.state.opened.push(x);return {};}}};
 for(const area of ['local','managed','session'])H.bgChrome.storage[area]={get:async key=>({[key]:structuredClone(H.state[area][key])}),set:async o=>Object.assign(H.state[area],structuredClone(o)),setAccessLevel:async()=>{}};
 H.contentChrome={runtime:{...runtime,onMessage:H.content,sendMessage:m=>{H.state.messages.push({type:m.type,purpose:m.purpose});return H.page(m);}}};
 H.uiChrome={runtime:{...runtime,sendMessage:H.ui,onMessage:event()}};
 H.changePolicy=async p=>{H.state.managed={PolicyJSON:typeof p==='string'?p:JSON.stringify(p)};H.storageChanged.emit({},'managed');const s=await H.ui({type:'STATUS'});H.epoch=s.policy?.epoch;return s;};
 H.paste=plain=>{const dt=new DataTransfer();dt.setData('text/plain',plain);const e=new ClipboardEvent('paste',{clipboardData:dt,bubbles:true,cancelable:true,composed:true});return document.activeElement.dispatchEvent(e);};
 H.fileEvent=(type='paste')=>{const dt=new DataTransfer();dt.items.add(new File(['email: a@example.com'],'original-secret.png',{type:'image/png'}));const e=type==='paste'?new ClipboardEvent('paste',{clipboardData:dt,bubbles:true,cancelable:true,composed:true}):new DragEvent(type,{dataTransfer:dt,bubbles:true,cancelable:true,composed:true});return document.activeElement.dispatchEvent(e);};
 window.__H=H;
})();
