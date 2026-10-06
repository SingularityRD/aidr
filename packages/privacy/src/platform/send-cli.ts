#!/usr/bin/env node
import {isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';
import {TextGatewayClient} from './client.js';
// Text enters stdin, not argv/process listings. No network fallback or automatic retry.
try{
  const args=process.argv.slice(2);if(args.length!==2||args[0]!=='--config'||!isAbsolute(args[1]!))throw new Error();
  const config=await import(pathToFileURL(args[1]!).href),client=new TextGatewayClient(config.default);let size=0;const chunks:Buffer[]=[];
  for await(const p of process.stdin){const b=Buffer.from(p);size+=b.length;if(size>500000)throw new Error();chunks.push(b);}
  const result=await client.send(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
  process.stdout.write(JSON.stringify(result)+'\n');if(result.decision!=='sent'||result.outputText===null)process.exitCode=2;
}catch{process.stderr.write('TEXT_SEND_FAILED_OUTCOME_UNKNOWN\n');process.exitCode=1;}
