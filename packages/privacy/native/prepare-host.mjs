#!/usr/bin/env node
/** Prepare a local native-host launcher and manifest. Does not modify browser/OS
 * policies or register anything. Admin reviews files, permissions and deployment. */
import fs from 'node:fs';import path from 'node:path';import{fileURLToPath}from'node:url';import{parsePolicy}from'../dist/browser/policy.js';
const args=process.argv.slice(2),kv={};for(let i=0;i<args.length;i+=2){if(!['--config','--out','--extension-id','--node','--platform'].includes(args[i])||!args[i+1]||kv[args[i]]!==undefined)throw Error('ARGUMENT_INVALID');kv[args[i]]=args[i+1];}
const config=kv['--config'],out=kv['--out'],id=kv['--extension-id']??'hmcbdjjldiobifmolecnmalilknnapcb',node=kv['--node']??process.execPath,platform=kv['--platform']??process.platform;
if(!config||!out||!path.isAbsolute(config)||!path.isAbsolute(out)||!path.isAbsolute(node)||!(/^[a-p]{32}$/).test(id)||!['linux','darwin','win32'].includes(platform))throw Error('ARGUMENT_INVALID');
for(const p of[config,node]){const st=fs.lstatSync(p);if(!st.isFile()||st.isSymbolicLink())throw Error('INPUT_INVALID');}
const text=fs.readFileSync(config,'utf8');if(Buffer.byteLength(text)>131072)throw Error('CONFIG_LIMIT');const cfg=JSON.parse(text);parsePolicy(cfg.browserPolicyJSON);if(cfg.version!==1||!Array.isArray(cfg.allowedExtensionIds)||!cfg.allowedExtensionIds.includes(id))throw Error('CONFIG_INVALID');
const host=fileURLToPath(new URL('../dist/native/host.js',import.meta.url));if(!fs.statSync(host).isFile())throw Error('BUILD_REQUIRED');
// Create a new admin-selected staging directory. Never silently overwrite a launcher.
fs.mkdirSync(out,{recursive:false,mode:0o700});
let launcher;
if(platform==='win32'){
 launcher=path.join(out,'aidr-native-launcher.exe');
 fs.copyFileSync(fileURLToPath(new URL('./windows-launcher.cs',import.meta.url)),path.join(out,'windows-launcher.cs'));
 fs.copyFileSync(fileURLToPath(new URL('./build-windows.ps1',import.meta.url)),path.join(out,'build-windows.ps1'));
 fs.writeFileSync(path.join(out,'launcher-settings.json'),JSON.stringify({node,host,config},null,2)+'\n',{flag:'wx',mode:0o600});
}else{
 launcher=path.join(out,'aidr-native-host');const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
 fs.writeFileSync(launcher,`#!/bin/sh\n# Admin-owned file; stdout is a binary Chrome protocol.\nexec ${quote(node)} ${quote(host)} --config ${quote(config)} "$@"\n`,{flag:'wx',mode:0o700});
}
const manifest={name:'com.singularity.aidr_privacy',description:'Singularity AIDR local text and screenshot privacy scanner',path:launcher,type:'stdio',allowed_origins:[`chrome-extension://${id}/`]};
fs.writeFileSync(path.join(out,'com.singularity.aidr_privacy.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
console.log('Native host files prepared. Review permissions and register through your approved deployment process.');
if(platform==='win32')console.log('Windows launcher source must be compiled and signed before registration. Windows execution is not validated in this release.');
