#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { parsePolicy } from '../browser/policy.js';
import { BrowserPrivacyEngine } from '../browser/engine.js';
import { ENTITY_TYPES, type Action } from '../types.js';
import { endianness } from 'node:os';
import { PrivacyEngine } from '../engine.js';
import { LocalNerProcess, type LocalNerOptions } from '../ner-process.js';
import { LocalImageProcess, type LocalImageOptions } from '../visual/local-process.js';
import { VisualPrivacyEngine } from '../visual/engine.js';
import { readBoundedFile } from '../visual/file-io.js';
import type { VisualOptions } from '../visual/types.js';
import type { EngineOptions } from '../types.js';
import { parseJsonStrict } from '../json.js';
import { FrameDecoder, encodeFrame } from './framing.js';
import { NativeSession } from './session.js';
import { deriveEdmKey, readEdmSecret } from './edm.js';
import { isAbsolute } from 'node:path';
/** Idle time before a one-document client's host exits, and before a persistent (Browser Guard) host exits. */
const IDLE_MS=120_000,PERSISTENT_IDLE_MS=15*60_000;
import { once } from 'node:events';
async function main():Promise<void>{
  let text:PrivacyEngine|undefined,ner:LocalNerProcess|undefined,visual:VisualPrivacyEngine|undefined,session:NativeSession|undefined,edmSecret:Buffer|undefined;
  let timer:ReturnType<typeof setTimeout>|undefined;const decoder=new FrameDecoder();
  const terminate=()=>{session?.close();ner?.close();visual?.dispose();edmSecret?.fill(0);process.stdin.destroy();};
  // A persistent client keeps one host (and its warm NER worker) for many scans; it still exits when idle.
  const reset=()=>{if(timer)clearTimeout(timer);timer=setTimeout(terminate,session?.persistent?PERSISTENT_IDLE_MS:IDLE_MS);};
  try{
    if(endianness()!=='LE')throw new Error();
    const args=process.argv.slice(2);if(args[0]!=='--config'||!args[1])throw new Error();
    // Browser appends the invoking extension origin; launcher must preserve it verbatim.
    const origin=args[2];if(typeof origin!=='string'||!/^chrome-extension:\/\/[a-p]{32}\/$/.test(origin))throw new Error();
    if(args.slice(3).some(a=>!/^--parent-window=[0-9]+$/.test(a)))throw new Error();
    const bytes=await readBoundedFile(args[1],131072);let config:Record<string,unknown>;
    try{const x=parseJsonStrict(new TextDecoder('utf-8',{fatal:true}).decode(bytes),16,10000);if(!x||Array.isArray(x)||typeof x!=='object')throw new Error();config=x as Record<string,unknown>;}finally{bytes.fill(0);}
    if(config.version!==1||Object.keys(config).some(k=>!['version','allowedExtensionIds','text','ner','visual','browserPolicyJSON','exactData'].includes(k))||!Array.isArray(config.allowedExtensionIds)
      ||!config.allowedExtensionIds.length||config.allowedExtensionIds.some(id=>typeof id!=='string'||!(/^[a-p]{32}$/).test(id))||!config.allowedExtensionIds.includes(origin.slice(19,-1)))throw new Error();
    if(config.exactData!==undefined){
      const e=config.exactData as Record<string,unknown>;
      if(!e||typeof e!=='object'||Array.isArray(e)||Object.keys(e).some(k=>k!=='secretFile')||typeof e.secretFile!=='string'||!isAbsolute(e.secretFile))throw new Error();
      edmSecret=await readEdmSecret(e.secretFile);
    }
    if(config.ner)ner=await LocalNerProcess.open(config.ner as unknown as LocalNerOptions);
    const textConfig=config.text??{};if(!textConfig||Array.isArray(textConfig)||typeof textConfig!=='object'||Object.keys(textConfig).some(k=>!['profile','mask','literals','actions','maxInputBytes','maxFindings','maxScanMs','nerTimeoutMs','policyId'].includes(k)))throw new Error();
    const policy=parsePolicy(config.browserPolicyJSON);
    const policyDigest=createHash('sha256').update(JSON.stringify(policy)).digest('hex');
    const tc=textConfig as EngineOptions,actions:Partial<Record<typeof ENTITY_TYPES[number],Action>>={...tc.actions};
    for(const t of ENTITY_TYPES){if(policy.textAction==='block'||['SECRET','PRIVATE_KEY','INTERNAL','CLASSIFIED'].includes(t))actions[t]='block';}
    text=new PrivacyEngine({maxInputBytes:1048576,...tc,actions,literals:[...(tc.literals??[]),...policy.literals],policyId:policy.id,...(ner?{ner}:{})});
    // Apply the same signal and strict-input controls to native documents and OCR text.
    const guard=new BrowserPrivacyEngine({injectionAction:policy.injectionAction,sourceCodeAction:policy.sourceCodeAction,policyId:policy.id,maxInputBytes:1048576});
    const guardedText={
      protect:async(input:string)=>{const r=guard.protect(input);return r.output===null?r:text!.protect(input);},
      protectJson:async(input:string)=>{const r=guard.protectJson(input);return r.output===null?r:text!.protectJson(input);},
    };
    if(config.visual){const v=config.visual as {backend:LocalImageOptions;policy?:Partial<VisualOptions>};
      if(!v||typeof v!=='object'||Object.keys(v).some(k=>!['backend','policy'].includes(k))||!v.backend||Object.keys(v.policy??{}).some(k=>!['release','mode','granularity','barcodeAction','uncertainText','minConfidence','minWordHeight','paddingPx','maxInputBytes','maxPixels','maxDimension','maxWords','maxTextBytes','maxRegions','timeoutMs','maxConcurrent','policyId','requireNer'].includes(k)))throw new Error();
      visual=new VisualPrivacyEngine({...v.policy,backend:new LocalImageProcess(v.backend),textEngine:guardedText});
    }
    const probe=await guardedText.protect('');const secret=edmSecret;
    session=new NativeSession({text:guardedText,...(visual?{visual}:{}),...(secret?{exactDataKey:(id:string)=>deriveEdmKey(secret,id).toString('base64')}:{}),policyId:probe.audit.policyId,policyDigest});
    process.stdin.once('end',terminate);process.once('SIGTERM',terminate);process.once('SIGINT',terminate);reset();
    for await(const chunk of process.stdin){
      for(const request of decoder.push(chunk as Buffer)){
        reset();const response=await session.handle(request),frame=encodeFrame(response);
        if(!process.stdout.write(frame))await once(process.stdout,'drain');reset();
      }
    }
    decoder.finish();
  }catch{
    // Never return request bodies, paths, exception messages or OCR text as diagnostics.
    try{process.stdout.write(encodeFrame({v:1,ok:false,code:'NATIVE_HOST_FAILURE'}));}catch{}
    process.exitCode=2;
  }finally{if(timer)clearTimeout(timer);session?.close();decoder.close();ner?.close();visual?.dispose();text?.dispose();edmSecret?.fill(0);}
}
await main();
