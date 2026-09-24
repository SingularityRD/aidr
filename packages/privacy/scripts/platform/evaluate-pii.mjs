import {writeFileSync}from'node:fs';import{PrivacyEngine}from'../../dist/index.js';import{scoreDataset,qualification,validateSplit}from'../../dist/platform/evaluation.js';
const samples=[];
function add(language,text,values){const spans=values.map(([value,type])=>({start:text.indexOf(value),end:text.indexOf(value)+value.length,type}));samples.push({id:'sample-'+samples.length,documentId:'document-'+samples.length,language,origin:'synthetic',text,spans});}
for(const l of ['tr','en']){
 add(l,l==='tr'?'E-posta: deniz@example.com':'Email: jane@example.com',[[l==='tr'?'deniz@example.com':'jane@example.com','EMAIL']]);
 add(l,l==='tr'?'Telefon: 0532 123 45 67':'Phone: +1 212 555 0123',[[l==='tr'?'0532 123 45 67':'+1 212 555 0123','PHONE']]);
 add(l,l==='tr'?'Ad Soyad: Ahmet Yılmaz':'Full name: Jane Smith',[[l==='tr'?'Ahmet Yılmaz':'Jane Smith','PERSON']]);
 add(l,'IBAN: TR33 0006 1005 1978 6457 8413 26',[['TR33 0006 1005 1978 6457 8413 26','IBAN']]);
 add(l,'Card: 4111 1111 1111 1111',[['4111 1111 1111 1111','CREDIT_CARD']]);
 add(l,l==='tr'?'Ahmet yarın toplantıya geliyor.':'Jane arrives tomorrow.',[[l==='tr'?'Ahmet':'Jane','PERSON']]);
 add(l,l==='tr'?'Adres: Atatürk Mahallesi 12. Sokak No: 5 Ankara':'Address: 123 Main Street, Boston, MA 02110',[[l==='tr'?'Atatürk Mahallesi 12. Sokak No: 5 Ankara':'123 Main Street, Boston, MA 02110','ADDRESS']]);
 add(l,l==='tr'?'Herkese açık toplantı özeti.':'A public meeting summary.',[]);
}
validateSplit([],samples);const engine=new PrivacyEngine({profile:'strict'}),predictions=new Map();
for(const s of samples){const r=await engine.protect(s.text);predictions.set(s.id,{spans:r.findings.map(f=>({start:f.start,end:f.end,type:f.type})),decision:r.decision});}
const report=scoreDataset(samples,predictions);writeFileSync('evaluation/synthetic-pii.jsonl',samples.map(x=>JSON.stringify(x)).join('\n')+'\n');writeFileSync('reports/platform/pii-evaluation.json',JSON.stringify({report,qualification:qualification(report,['PERSON','EMAIL','PHONE','IBAN','CREDIT_CARD','ADDRESS'])},null,2)+'\n');console.log(JSON.stringify({samples:report.samples,qualification:qualification(report,['PERSON','EMAIL','PHONE','IBAN','CREDIT_CARD','ADDRESS'])}));
