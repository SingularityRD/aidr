/** Run only to generate reviewable files. Does NOT install policies, CRX or native software. */
import {writeFileSync,readFileSync} from 'node:fs';
import {chromeManagedPolicies} from '../dist/platform/deployment.js';
const development=JSON.parse(readFileSync(new URL('../extension/identity.json',import.meta.url)));
const extensionId=process.env.AIDR_EXTENSION_ID??development.extensionId;
const updateUrl=process.env.AIDR_EXTENSION_UPDATE_URL??'https://updates.example.invalid/aidr/update.xml';
const policy={version:1,id:'aidr-quarantine-until-accepted',mode:'block',requireNativeText:true,fileHandling:'block'};
const p=chromeManagedPolicies(extensionId,updateUrl,{PolicyJSON:JSON.stringify(policy)});
writeFileSync(new URL('./chrome-linux.json',import.meta.url),JSON.stringify(p.linux,null,2)+'\n');
writeFileSync(new URL('./chrome-windows.reg',import.meta.url),p.windowsRegistry);
writeFileSync(new URL('./chrome-macos-fragment.json',import.meta.url),JSON.stringify(p.macOS,null,2)+'\n');
writeFileSync(new URL('./extension-managed.json',import.meta.url),JSON.stringify(p.extensionManaged,null,2)+'\n');
console.log(p.warning+' Default URL is deliberately non-routable; replace with your approved signed distribution.');
