/** Static TypeScript-to-IIFE bundler. No eval, new Function, CDN, remote code or runtime transpilation. */
import fs from 'node:fs';import path from 'node:path';import ts from 'typescript';import {createHash} from 'node:crypto';
const root=process.cwd(),out=path.join(root,'extension/chrome');fs.rmSync(out,{recursive:true,force:true});fs.mkdirSync(out,{recursive:true});
export function bundle(entry){
 const modules=[],seen=new Map();
 const load=file=>{
  file=path.resolve(file);if(seen.has(file))return seen.get(file);if(!file.startsWith(root+path.sep)||!file.endsWith('.ts'))throw Error('BUILD_IMPORT_DENIED');
  const id=modules.length;seen.set(file,id);modules.push(null);
  const source=fs.readFileSync(file,'utf8');const result=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,strict:true,esModuleInterop:true},fileName:file,reportDiagnostics:true});
  const errors=result.diagnostics?.filter(d=>d.category===ts.DiagnosticCategory.Error);if(errors?.length)throw Error(ts.formatDiagnosticsWithColorAndContext(errors,{getCanonicalFileName:f=>f,getCurrentDirectory:()=>root,getNewLine:()=> '\n'}));
  const code=result.outputText.replace(/require\(["']([^"']+)["']\)/g,(_m,spec)=>{
    if(!spec.startsWith('.'))throw Error('BUILD_EXTERNAL_IMPORT_DENIED: '+spec);
    const dependency=path.resolve(path.dirname(file),spec.replace(/\.js$/,'.ts'));return `__load(${load(dependency)})`;
  });
  if(/\brequire\(/.test(code))throw Error('BUILD_DYNAMIC_REQUIRE_DENIED');
  modules[id]={file:path.relative(root,file).replaceAll('\\','/'),code};return id;
 };
 const entryId=load(path.join(root,entry));
 const body=`/* Singularity AIDR 0.5.0-rc.1. Generated from reviewed local sources. */\n(()=>{\n'use strict';\nconst __modules=[\n${modules.map(m=>`/* ${m.file} */\nfunction(module,exports,__load){\n${m.code}\n}`).join(',\n')}\n];\nconst __cache=Object.create(null);\nfunction __load(id){if(__cache[id])return __cache[id].exports;const module={exports:{}};__cache[id]=module;__modules[id](module,module.exports,__load);return module.exports;}\n__load(${entryId});\n})();\n`;
 return body;
}
for(const [name,entry]of [['service-worker.js','extension/src/service-worker.ts'],['content.js','extension/src/content-entry.ts'],['compose.js','extension/src/compose.ts']])fs.writeFileSync(path.join(out,name),bundle(entry));
for(const name of ['compose.html','ui.css','managed-schema.json'])fs.copyFileSync(path.join(root,'extension',name),path.join(out,name));
const identity=JSON.parse(fs.readFileSync('extension/identity.json','utf8'));
const manifest={manifest_version:3,name:'Singularity AIDR · AI Privacy Guard',version:'0.5.0',version_name:'0.5.0-rc.1',description:'Local Turkish/English PII checks and secure composition for ChatGPT, Gemini and Claude.',
 minimum_chrome_version:'120',key:identity.publicKey,permissions:['storage','nativeMessaging','declarativeNetRequest'],
 host_permissions:['https://chatgpt.com/*','https://chat.openai.com/*','https://gemini.google.com/*','https://claude.ai/*'],
 background:{service_worker:'service-worker.js'},action:{default_title:'AIDR · Güvenli Yaz',default_popup:'compose.html'},
 content_scripts:[{matches:['https://chatgpt.com/*','https://chat.openai.com/*','https://gemini.google.com/*','https://claude.ai/*'],js:['content.js'],run_at:'document_start',all_frames:true}],
 storage:{managed_schema:'managed-schema.json'},incognito:'not_allowed',
 content_security_policy:{extension_pages:"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}};
fs.writeFileSync(path.join(out,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
const inventory=fs.readdirSync(out).sort().map(name=>({name,bytes:fs.statSync(path.join(out,name)).size,sha256:createHash('sha256').update(fs.readFileSync(path.join(out,name))).digest('hex')}));
fs.writeFileSync('reports/browser/extension-build.json',JSON.stringify({version:'0.5.0-rc.1',typescript:ts.version,extensionId:identity.extensionId,files:inventory},null,2)+'\n');
console.log(JSON.stringify({extensionId:identity.extensionId,files:inventory.length,totalBytes:inventory.reduce((n,f)=>n+f.bytes,0)}));
