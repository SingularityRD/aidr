import { providerForUrl, PROVIDERS } from '../../src/browser/providers.js';
import type { PolicyView } from '../../src/browser/policy.js';
import { fromBase64 } from '../../src/browser/transport.js';
import { editableSnapshot, replaceEditable } from './editable.js';
export function installContentGuard(pageUrl=location.href,pageOrigin=location.origin):void {
const provider=providerForUrl(pageUrl);
if(provider){
 const adapter=PROVIDERS[provider],documentToken=crypto.randomUUID();
 let policy:PolicyView|null=null,writing=false,previewTimer:ReturnType<typeof setTimeout>|undefined,sequence=0;
 let permit:{text:string;epoch:string;expires:number}|null=null,followup:{text:string;expires:number}|null=null;
 let pendingRewrite:{source:string;output:string;epoch:string}|null=null;
 let host:HTMLDivElement|undefined,status:HTMLSpanElement|undefined,redactButton:HTMLButtonElement|undefined;
 const visible=(e:HTMLElement)=>e.getClientRects().length>0&&!e.closest('[aria-hidden="true"]');
 const editor=():HTMLElement|null=>{
  const found=[...new Set(adapter.editors.flatMap(s=>[...document.querySelectorAll<HTMLElement>(s)]))].filter(e=>visible(e)&&!(e instanceof HTMLInputElement&&e.type==='password'));
  return found.length===1?found[0]!:null;
 };
 const current=()=>{const e=editor();return e?editableSnapshot(e).text:null;};
 const inside=(event:Event)=>!!host&&event.composedPath().includes(host);
 const element=(event:Event):HTMLElement|null=>event.composedPath().find(n=>n instanceof HTMLElement) as HTMLElement|undefined??null;
 const editing=(event:Event):boolean=>{const target=element(event),e=editor();return !!target&&(!!e&&(target===e||e.contains(target))||!!target.closest('textarea,[contenteditable="true"],[role="textbox"]'));};
 const stop=(event:Event)=>{if(event.cancelable)event.preventDefault();event.stopImmediatePropagation();};
 const invalidate=()=>{permit=null;followup=null;pendingRewrite=null;sequence++;if(redactButton)redactButton.hidden=true;};
 const mount=()=>{
  if(host?.isConnected)return;if(!document.documentElement)return;
  host=document.createElement('div');host.id='aidr-guard-status';host.setAttribute('role','status');host.setAttribute('aria-live','polite');
  const root=host.attachShadow({mode:'closed'}),style=document.createElement('style');
  style.textContent=':host{all:initial;position:fixed;bottom:18px;right:18px;z-index:2147483647;font:13px/1.45 system-ui,sans-serif;color:#eef4ff}section{display:flex;align-items:center;gap:12px;max-width:520px;padding:12px 15px;border:1px solid #52627d;border-radius:12px;background:#111a2b;box-shadow:0 8px 36px #0005}b{letter-spacing:.12em;color:#72e3c7}button{font:inherit;color:#eef4ff;background:#293b56;border:1px solid #62718a;border-radius:7px;padding:6px 10px;cursor:pointer}button:hover{background:#3e5475}button[hidden]{display:none}span{max-width:290px}';
  const section=document.createElement('section'),brand=document.createElement('b');brand.textContent='AIDR';status=document.createElement('span');status.textContent='Koruma başlatılıyor';
  redactButton=document.createElement('button');redactButton.textContent='Maskele';redactButton.hidden=true;redactButton.addEventListener('click',()=>void rewrite());
  const compose=document.createElement('button');compose.textContent='Güvenli yaz';compose.addEventListener('click',()=>{void chrome.runtime.sendMessage({type:'OPEN_COMPOSER'}).catch(()=>show('error','Eklenti bağlantısı yok. Göndermeyin.'));});
  section.append(brand,status,redactButton,compose);root.append(style,section);document.documentElement.append(host);
 };
 const show=(state:string,message:string,canRedact=false)=>{mount();if(status)status.textContent=message;if(host){host.dataset.aidrState=state;host.setAttribute('aria-label',`AIDR: ${message}`);}if(redactButton)redactButton.hidden=!canRedact;};
 const scan=async(text:string,purpose:string):Promise<any>=>{
  const response=await chrome.runtime.sendMessage({type:'SCAN',text,purpose});
  if(!response||response.ok!==true||response.epoch!==policy?.epoch||!['allow','redact','block','review'].includes(response.decision))throw new Error('SCAN_DENIED');return response;
 };
 const setSafe=async(text:string):Promise<void>=>{
  const e=editor();if(!e||!policy)throw new Error('EDITOR_UNSUPPORTED');const epoch=policy.epoch;
  writing=true;try{replaceEditable(e,text);}finally{writing=false;}
  await new Promise(resolve=>setTimeout(resolve,0));
  if(current()!==text||policy?.epoch!==epoch)throw new Error('EDITOR_CHANGED');
  pendingRewrite=null;permit={text,epoch,expires:Date.now()+30000};show('clear','Maskeli içerik hazır. Göndermeyi siz onaylayın.');
 };
 async function rewrite():Promise<void>{
  const p=pendingRewrite;if(!p||current()!==p.source||policy?.epoch!==p.epoch){invalidate();show('blocked','Metin değişti. Yeniden kontrol edin.');return;}
  try{const r=await scan(p.source,'redact');if(current()!==p.source||r.output===null)throw new Error();await setSafe(r.output);}catch{invalidate();show('blocked','Maskeleme tamamlanamadı. Gönderim durduruldu.');}
 }
 const display=(r:any,source:string)=>{
  if(r.output===null){pendingRewrite=null;show('blocked',r.decision==='review'?'İnceleme gerekiyor. Gönderim durduruldu.':'Hassas içerik veya tarama hatası. Gönderim durduruldu.');}
  else if(r.decision==='redact'){pendingRewrite={source,output:r.output,epoch:r.epoch};show('sensitive','Hassas bilgi bulundu. Önce maskeleyin.',true);}
  else show('clear',policy?.requireNativeText?'Ön tarama temiz; yerel NER gönderimde çalışır.':'Yerel kural taraması: bulgu yok.');
 };
 function preview():void{
  invalidate();if(previewTimer)clearTimeout(previewTimer);const id=sequence;
  previewTimer=setTimeout(()=>{const text=current();if(text===null||!policy)return;
    void scan(text,'preview').then(r=>{if(sequence===id&&current()===text)display(r,text);}).catch(()=>{if(sequence===id)show('error','Tarayıcı kullanılamıyor. Gönderim kapalı.');});},250);
 }
 async function submitCheck(text:string):Promise<void>{
  const id=++sequence;permit=null;show('busy','Göndermeden önce kontrol ediliyor.');
  try{const r=await scan(text,'submit');if(sequence!==id||current()!==text)return;
    if(r.decision==='allow'&&r.output===text){permit={text,epoch:r.epoch,expires:Date.now()+30000};show('clear','Kontrol edildi. Göndermek için tekrar basın.');}
    else display(r,text);
  }catch{permit=null;show('error','Kontrol tamamlanamadı. Gönderim durduruldu.');}
 }
 function gate(event:Event):void{
  if(inside(event))return;
  const text=current();
  if(event.type==='submit'&&followup&&text===followup.text&&Date.now()<followup.expires){followup=null;return;}
  if(!policy||policy.mode==='block'||policy.blockSites.includes(provider!)){stop(event);show('blocked','Kurum politikası gönderime izin vermiyor.');return;}
  if(text===null){stop(event);show('blocked','Yazım alanı tanınamadı. Gönderim durduruldu.');return;}
  if(permit&&permit.text===text&&permit.epoch===policy.epoch&&permit.expires>Date.now()){
    permit=null;followup={text,expires:Date.now()+200};setTimeout(()=>{followup=null;},0);show('clear','Kontrol edilen içerik siteye bırakıldı.');return;
  }
  stop(event);void submitCheck(text);
 }
 function rejectFiles(event:Event):void{
  stop(event);invalidate();const target=element(event);
  if(target instanceof HTMLInputElement&&target.type==='file')target.value='';
  show('blocked','Doğrudan ek yükleme kapalı. Güvenli yaz alanında temizleyin.');void chrome.runtime.sendMessage({type:'FILE_BLOCK'}).catch(()=>{});
 }
 async function pastePlain(plain:string):Promise<void>{
  const e=editor(),p=policy;if(!e||!p)throw new Error('EDITOR_UNSUPPORTED');
  const snapshot=editableSnapshot(e),candidate=snapshot.text.slice(0,snapshot.start)+plain+snapshot.text.slice(snapshot.end),epoch=p.epoch;
  show('busy','Yapıştırılan metin siteye verilmeden taranıyor.');
  const r=await scan(candidate,'paste');if(current()!==snapshot.text||policy?.epoch!==epoch)throw new Error('EDITOR_CHANGED');
  if(r.output===null){display(r,candidate);return;}await setSafe(r.output);
 }
 window.addEventListener('beforeinput',event=>{
  if(writing||inside(event)||!editing(event))return;invalidate();
  if(!policy||policy.mode!=='guard'){stop(event);show('blocked','Bu politikada yalnız Güvenli yaz alanını kullanın.');}
 },true);
 window.addEventListener('keydown',event=>{
  if(inside(event)||!editing(event))return;
  if(!policy||policy.mode!=='guard'){
    if(event.key.length===1&&!event.ctrlKey&&!event.metaKey||['Backspace','Delete'].includes(event.key)){stop(event);show('blocked','Ham metni siteye değil Güvenli yaz alanına yazın.');return;}
  }
  if(event.key==='Enter'&&!event.shiftKey&&!event.isComposing&&event.keyCode!==229)gate(event);
 },true);
 window.addEventListener('submit',event=>{if(!inside(event)&&(editor()||document.querySelector('textarea,[contenteditable="true"]')))gate(event);},true);
 window.addEventListener('click',event=>{
  if(writing||inside(event))return;const target=element(event);if(!target)return;
  if(target instanceof HTMLInputElement&&target.type==='file'){rejectFiles(event);return;}
  const button=target.closest('button,[role="button"],input[type="submit"]');if(!button)return;
  const label=button.getAttribute('aria-label')??'';
  if(/\b(voice|microphone|dictate|sesli|mikrofon)\b/i.test(label)){stop(event);show('blocked','Ses kanalı bu sürümde taranmıyor; kullanım durduruldu.');return;}
  if(adapter.send.some(s=>button.matches(s))||button instanceof HTMLButtonElement&&button.type==='submit'&&!!button.closest('form')&&(!!editor()||!!button.closest('form')?.querySelector('textarea,[contenteditable="true"]')))gate(event);
 },true);
 for(const type of ['input','change'])window.addEventListener(type,event=>{
  if(writing||inside(event))return;const t=element(event);if(t instanceof HTMLInputElement&&t.type==='file'){rejectFiles(event);return;}
  if(type==='input'&&editing(event))preview();
 },true);
 window.addEventListener('paste',event=>{
  if(inside(event))return;const data=event.clipboardData;
  if(data&&([...data.items].some(i=>i.kind==='file')||data.files.length)){rejectFiles(event);return;}
  if(!editing(event)){stop(event);show('blocked','Yapıştırma alanı tanınamadı. Güvenli yaz alanını kullanın.');return;}stop(event);invalidate();
  if(!policy||policy.mode!=='guard'){show('blocked','Yapıştırmayı Güvenli yaz alanında yapın.');return;}
  const plain=data?.getData('text/plain');if(plain===undefined){show('blocked','Pano biçimi desteklenmiyor.');return;}
  void pastePlain(plain).catch(()=>show('blocked','Yapıştırma kontrolü tamamlanamadı. İçerik eklenmedi.'));
 },true);
 window.addEventListener('dragover',event=>{if(!inside(event)&&event.dataTransfer&&[...event.dataTransfer.types].includes('Files'))stop(event);},true);
 window.addEventListener('drop',event=>{
  if(inside(event))return;const data=event.dataTransfer;if(data&&([...data.items].some(i=>i.kind==='file')||data.files.length)){rejectFiles(event);return;}
  if(editing(event)){stop(event);invalidate();if(policy?.mode==='guard')void pastePlain(data?.getData('text/plain')??'').catch(()=>show('blocked','Sürüklenen içerik eklenmedi.'));}else if(data?.types.length){stop(event);show('blocked','Sürükleme alanı tanınamadı. Güvenli yaz alanını kullanın.');}
 },true);
 const load=async()=>{
  invalidate();policy=null;show('busy','Kurum politikası yükleniyor.');
  try{const r=await chrome.runtime.sendMessage({type:'POLICY'});if(!r||r.ok!==true||!r.policy||typeof r.policy.epoch!=='string')throw new Error();policy=r.policy;
    show('ready',policy?.mode==='guard'?'Yerel PII kontrolü etkin.':'Güvenli yaz alanı zorunlu.');
  }catch{show('error','Politika alınamadı. Gönderim kapalı.');}
 };
 chrome.runtime.onMessage.addListener((message,sender,respond)=>{
  if(sender.id!==chrome.runtime.id||sender.tab)return;
  if(message?.type==='POLICY_CHANGED'){void load();respond({ok:true});return;}
  if(message?.type==='PROBE'){respond({ok:!!policy&&!!editor(),documentToken,origin:pageOrigin,epoch:policy?.epoch});return;}
  if(message?.type==='APPLY_SAFE'){
    void (async()=>{
      if(!policy||message.epoch!==policy.epoch||message.documentToken!==documentToken||policy.mode==='block')throw new Error();
      const v=message.value;if(!v||typeof v!=='object')throw new Error();invalidate();
      if(v.kind==='text'){
        if(typeof v.text!=='string'||v.text.length>524288)throw new Error();await setSafe(v.text);
      }else if(v.kind==='image'||v.kind==='document'){
        if(policy.fileHandling!=='sanitize'||!['aidr-sanitized.png','aidr-sanitized.txt','aidr-sanitized.json','aidr-sanitized.csv','aidr-sanitized.tsv'].includes(v.filename)||typeof v.contentType!=='string')throw new Error();
        const data=fromBase64(v.data,16777216);if(!data.length)throw new Error();
        const inputs=[...document.querySelectorAll<HTMLInputElement>('input[type="file"]')].filter(i=>!i.disabled);
        if(inputs.length!==1)throw new Error();
        const transfer=new DataTransfer();transfer.items.add(new File([new Uint8Array(data).buffer],v.filename,{type:v.contentType,lastModified:0}));data.fill(0);
        writing=true;try{inputs[0]!.files=transfer.files;inputs[0]!.dispatchEvent(new Event('input',{bubbles:true,composed:true}));inputs[0]!.dispatchEvent(new Event('change',{bubbles:true,composed:true}));}finally{writing=false;}
        show('clear','Yalnız temizlenmiş dosya siteye aktarıldı.');
      }else throw new Error();
      respond({ok:true});
    })().catch(()=>{invalidate();show('blocked','Site adaptörü içeriği kabul etmedi. Otomatik gönderim yapılmadı.');respond({ok:false});});return true;
  }
 });
 mount();if(!document.documentElement)document.addEventListener('DOMContentLoaded',mount,{once:true});void load();
}

}
