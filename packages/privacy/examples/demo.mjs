import { PrivacyEngine } from '../dist/index.js';
const engine=new PrivacyEngine({profile:'strict',mask:'label'});
for(const text of [
 'Ad Soyad: Ahmet Yılmaz; E-posta: ahmet@example.com; Telefon: 0532 123 45 67',
 'Name: Jane Doe; Email: jane@example.com; SSN: 123-45-6789',
 'GİZLİ\nProje gereksinimleri.',
]) {
 const r=await engine.protect(text);
 console.log(JSON.stringify({decision:r.decision,output:r.output,reasons:r.reasons}));
}
const json=await engine.protectJson(JSON.stringify({name:'Çağrı Öztürk',email:'cagri@example.com',description:'Build 42 approved.'}));
console.log(JSON.stringify(json));
engine.dispose();
