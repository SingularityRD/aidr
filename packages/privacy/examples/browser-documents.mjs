import {BrowserPrivacyEngine} from '../dist/browser/index.js';
import {protectDocument} from '../dist/browser/documents.js';
const scanner=new BrowserPrivacyEngine();
for(const [kind,text]of [['text','E-posta: synthetic@example.com'],['json','{"name":"Jane Doe","email":"jane@example.com"}'],['csv','name,email\nJane Doe,jane@example.com']]){
 const result=await protectDocument(text,kind,scanner);
 if(result.output===null)throw Error('AIDR_DOCUMENT_DENIED');
 console.log(kind+': '+result.output); // Synthetic example, sanitized output only.
}
