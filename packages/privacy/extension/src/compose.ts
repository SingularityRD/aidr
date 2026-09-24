import { COACHING_TR } from '../../src/enterprise/signals.js';
import { toBase64, fromBase64 } from '../../src/browser/transport.js';
const $=<T extends HTMLElement>(id:string)=>document.getElementById(id) as T;
const raw=$<HTMLTextAreaElement>('raw'),safe=$<HTMLTextAreaElement>('safe'),target=$<HTMLSelectElement>('target'),apply=$<HTMLButtonElement>('apply'),download=$<HTMLButtonElement>('download');
let ticket:string|null=null,currentBlob:Blob|null=null,previewUrl:string|null=null,busy=false,epoch='',generation=0;
let maxText=65536,maxFile=8388608;
const message=(text:string)=>{$('status').textContent=text;};
const clear=()=>{ticket=null;currentBlob=null;generation++;apply.disabled=true;download.disabled=true;safe.value='';$('result-section').hidden=true;if(previewUrl){URL.revokeObjectURL(previewUrl);previewUrl=null;}$<HTMLImageElement>('image-preview').removeAttribute('src');};
const rpc=(payload:Record<string,unknown>)=>chrome.runtime.sendMessage(payload);
const denied=(r:any)=>{clear();const reasons:string[]=(Array.isArray(r?.reasons)?r.reasons:[]).filter((x:unknown)=>typeof x==='string'&&/^[A-Z][A-Z0-9_]{0,63}$/.test(x)).slice(0,8);const coaching=[...new Set(reasons.map(x=>COACHING_TR[x]).filter(Boolean))].slice(0,2).join(' ');message(`İşlem durduruldu: ${reasons.join(', ')||'EXTENSION_UNAVAILABLE'}. ${coaching}`);};
const lock=(v:boolean)=>{busy=v;$<HTMLButtonElement>('scan').disabled=v;$<HTMLInputElement>('file').disabled=v;apply.disabled=v||!ticket;};
const tab=()=>{const id=Number(target.value);if(!Number.isSafeInteger(id)||id<1)throw new Error('TARGET_REQUIRED');return id;};
async function status():Promise<void>{
  const r=await rpc({type:'STATUS'});if(!r?.ok){denied(r);$('health').textContent='Gönderim kapalı';return;}
  if(epoch&&epoch!==r.policy.epoch)clear();epoch=r.policy.epoch;maxText=r.policy.maxTextBytes;maxFile=r.policy.maxFileBytes;
  const selected=target.value||new URLSearchParams(location.search).get('tab')||String(r.targets.find((t:any)=>t.active)?.id??'');
  target.replaceChildren();for(const t of r.targets){const opt=document.createElement('option');opt.value=String(t.id);opt.textContent=`${t.provider} · Sekme ${t.id}`;target.append(opt);}
  if([...target.options].some(o=>o.value===selected))target.value=selected;
  $('health').textContent=r.policy.mode==='block'?'Siteler engelli':'Yerel koruma';$('policy').textContent=JSON.stringify(r.policy,null,2);
  $('coverage').textContent=r.policy.requireNativeText?'Gönderimde onaylı yerel NER zorunlu. Native host yoksa gönderim durur.':'Metin: yerel kurallar. Öğrenilmiş NER bu tarayıcı kipinde yoktur.';
  if(!r.targets.length)message('ChatGPT, Gemini veya Claude sekmesini açın. Eklenti yeni kurulduysa sekmeyi yenileyin.');
}
function result(r:any,isFile=false):void{
  if(!r?.ok||!r.ticket){denied(r);return;}ticket=r.ticket;epoch=r.epoch;$('result-section').hidden=false;$('verdict').textContent=r.decision==='redact'?'Maskelendi':'Kontrol edildi';
  safe.hidden=false;$('image-preview').hidden=true;currentBlob=null;
  if(isFile){const bytes=fromBase64(r.data,16777216);currentBlob=new Blob([new Uint8Array(bytes).buffer],{type:r.contentType});
    if(r.kind==='image'){safe.hidden=true;previewUrl=URL.createObjectURL(currentBlob);$<HTMLImageElement>('image-preview').src=previewUrl;$('image-preview').hidden=false;}
    else safe.value=new TextDecoder('utf-8',{fatal:true}).decode(bytes);bytes.fill(0);
    download.dataset.filename=r.filename;download.disabled=false;
  }else{safe.value=r.output;currentBlob=new Blob([r.output],{type:'text/plain;charset=utf-8'});download.dataset.filename='aidr-sanitized.txt';download.disabled=false;}
  apply.disabled=false;$('findings').textContent=r.counts?Object.entries(r.counts).map(([k,v])=>`${k}: ${v}`).join(' · '):'Yalnız temizlenmiş dosya aktarılabilir.';
  message('Çıktıyı inceleyin. Aktarma tek kullanımlıktır ve hedef sekmeye bağlıdır.');
}
$('scan').addEventListener('click',()=>{void (async()=>{
  if(busy)return;clear();const id=generation;lock(true);message('Metin yerel olarak taranıyor.');
  try{const bytes=new TextEncoder().encode(raw.value);if(bytes.length>maxText)throw new Error('INPUT_LIMIT');
    const r=await rpc({type:'COMPOSE_SCAN',tabId:tab(),text:raw.value});if(generation===id)result(r);
  }catch{message('Tarama tamamlanamadı. Hiçbir içerik aktarılmadı.');}finally{lock(false);}
})();});
raw.addEventListener('input',()=>{clear();$('byte-count').textContent=`${new TextEncoder().encode(raw.value).length} byte`;});
target.addEventListener('change',clear);
$('refresh').addEventListener('click',()=>{clear();void status().catch(()=>message('Eklenti bağlantısı yok.'));});
function kindOf(file:File,bytes:Uint8Array):'image'|'text'|'json'|'csv'|'tsv'{
  if(bytes.length>=8&&bytes[0]===137&&bytes[1]===80&&bytes[2]===78&&bytes[3]===71||bytes.length>=3&&bytes[0]===255&&bytes[1]===216&&bytes[2]===255
    ||bytes.length>=12&&new TextDecoder().decode(bytes.subarray(0,4))==='RIFF'&&new TextDecoder().decode(bytes.subarray(8,12))==='WEBP')return 'image';
  const ext=file.name.split('.').at(-1)?.toLowerCase();if(ext==='txt')return 'text';if(ext==='json'||ext==='csv'||ext==='tsv')return ext;throw new Error('FILE_TYPE_DENIED');
}
async function fileScan(file:File):Promise<void>{
  if(busy)return;clear();const id=generation;lock(true);let bytes:Uint8Array|undefined;message('Dosya yerel olarak inceleniyor. Orijinal dosya AI sitesine verilmez.');
  try{if(!file.size||file.size>maxFile)throw new Error('FILE_LIMIT');bytes=new Uint8Array(await file.arrayBuffer());const kind=kindOf(file,bytes);
    const r=await rpc({type:'SANITIZE_FILE',tabId:tab(),kind,data:toBase64(bytes)});if(generation===id)result(r,true);
  }catch{message('Dosya temizlenemedi veya yerel OCR bağlı değil. Dosya aktarılmadı.');}finally{bytes?.fill(0);$<HTMLInputElement>('file').value='';lock(false);}
}
$('file').addEventListener('change',()=>{const f=$<HTMLInputElement>('file').files;if(f?.length===1)void fileScan(f[0]!);});
window.addEventListener('paste',event=>{const files=event.clipboardData?.files;if(files?.length){event.preventDefault();if(files.length===1)void fileScan(files[0]!);else message('Aynı anda yalnız bir dosyayı kontrol edin.');}});
apply.addEventListener('click',()=>{void(async()=>{
  if(!ticket||busy)return;const id=ticket;ticket=null;apply.disabled=true;lock(true);
  try{const r=await rpc({type:'APPLY',tabId:tab(),ticket:id});if(!r?.ok){denied(r);return;}raw.value='';message('Yalnız kontrol edilen çıktı aktarıldı. Metin otomatik gönderilmedi.');}
  catch{message('Aktarma gerçekleşmedi. Hedef sekmeyi ve adaptörü kontrol edin.');}finally{lock(false);}
})();});
download.addEventListener('click',()=>{if(!currentBlob)return;save(currentBlob,download.dataset.filename??'aidr-sanitized.txt');});
function save(blob:Blob,name:string):void{const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('native-health').addEventListener('click',()=>{void rpc({type:'HEALTH'}).then(r=>message(r?.ok?(r.ocr?'Yerel OCR bağlı; politika eşleşiyor.':'Yerel host bağlı; OCR yapılandırılmamış.'):`Yerel bağlantı kullanılamıyor: ${(r?.reasons??['NATIVE_UNAVAILABLE']).join(', ')}`)).catch(()=>message('Yerel bağlantı kullanılamıyor.'));});
$('export-audit').addEventListener('click',()=>{void rpc({type:'AUDIT'}).then(r=>{if(r?.ok)save(new Blob([JSON.stringify(r.audit,null,2)],{type:'application/json'}),'aidr-audit-metadata.json');else denied(r);}).catch(()=>message('Sayaç raporu alınamadı.'));});
window.addEventListener('pagehide',()=>{raw.value='';safe.value='';clear();});
void status().catch(()=>message('Eklenti başlatılamadı. Gönderim kapalı.'));
