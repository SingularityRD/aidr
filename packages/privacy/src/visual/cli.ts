#!/usr/bin/env node
import { PrivacyEngine } from '../engine.js';
import { LocalImageProcess, type LocalImageOptions } from './local-process.js';
import { VisualPrivacyEngine } from './engine.js';
import type { VisualOptions } from './types.js';
import { readBoundedFile, publishExclusive } from './file-io.js';
const POLICY_KEYS=new Set(['release','mode','granularity','barcodeAction','uncertainText','minConfidence','minWordHeight','paddingPx','maxInputBytes','maxPixels','maxDimension','maxWords','maxTextBytes','maxRegions','timeoutMs','maxConcurrent','policyId','requireNer']);
async function main():Promise<void>{
 const args=process.argv.slice(2);
 if(args.length!==6||args[0]!=='--config'||args[2]!=='--input'||args[4]!=='--output'){
  process.stderr.write('Usage: aidr-visual --config approved-config.json --input screenshot --output sanitized.png\n');process.exitCode=64;return;
 }
 let bytes:Buffer|undefined;let image:VisualPrivacyEngine|undefined;let text:PrivacyEngine|undefined;
 const abort=new AbortController();const stop=()=>abort.abort();process.once('SIGINT',stop);process.once('SIGTERM',stop);
 try{
  const configBytes=await readBoundedFile(args[1]!,65536);let config:Record<string,unknown>;
  try{config=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(configBytes)) as Record<string,unknown>;}finally{configBytes.fill(0);}
  if(!config||Array.isArray(config)||Object.keys(config).some(k=>!['backend','policy'].includes(k))||!config.backend)throw new Error();
  const policy=config.policy??{};
  if(typeof policy!=='object'||!policy||Array.isArray(policy)||Object.keys(policy).some(k=>!POLICY_KEYS.has(k)))throw new Error();
  text=new PrivacyEngine({profile:'strict',maxInputBytes:262144});
  image=new VisualPrivacyEngine({...policy as Partial<VisualOptions>,backend:new LocalImageProcess(config.backend as LocalImageOptions),textEngine:text});
  bytes=await readBoundedFile(args[3]!,8*1024*1024);
  const result=await image.protect(bytes,abort.signal);
  if(result.output===null){process.stdout.write(JSON.stringify({decision:result.decision,reasons:result.reasons,audit:result.audit})+'\n');process.exitCode=2;return;}
  try{if(abort.signal.aborted)throw new Error();await publishExclusive(args[5]!,result.output);}
  finally{result.output.fill(0);}
  // No source path, OCR content, original content hash or image bytes in stdout.
  process.stdout.write(JSON.stringify({decision:result.decision,reasons:result.reasons,audit:result.audit})+'\n');
 }catch{process.stdout.write('{"decision":"block","reasons":["IMAGE_CLI_FAILURE"]}\n');process.exitCode=2;}
 finally{bytes?.fill(0);image?.dispose();text?.dispose();process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);}
}
await main();
