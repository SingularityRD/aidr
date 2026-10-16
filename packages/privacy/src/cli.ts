#!/usr/bin/env node
import { PrivacyEngine } from './engine.js';
import { AtomicTextGate } from './stream.js';
/** stdin only: avoid putting secrets into process arguments or shell history. */
async function main():Promise<void> {
  const args=process.argv.slice(2);
  if(args.some(a=>!['--json','--redact'].includes(a))) {process.stderr.write('Usage: aidr-privacy [--json] [--redact] < input\n');process.exitCode=64;return;}
  const engine=new PrivacyEngine({profile:'strict',mask:args.includes('--redact')?'redact':'label'});
  const gate=new AtomicTextGate(engine);
  try {
    if(args.includes('--json')) {
      const chunks:Buffer[]=[];let size=0;
      try {
        for await(const chunk of process.stdin){const b=Buffer.from(chunk as Uint8Array);size+=b.length;if(size>engine.maxInputBytes)throw new Error();chunks.push(b);}
        const bytes=Buffer.concat(chunks);let text:string;
        try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}finally{bytes.fill(0);}
        const result=await engine.protectJson(text);
        process.stdout.write(JSON.stringify(result)+'\n');if(result.output===null)process.exitCode=2;
      } finally{for(const c of chunks)c.fill(0);gate.abort();}
    } else {
      for await(const chunk of process.stdin)gate.push(chunk as Uint8Array);
      const result=await gate.finish();process.stdout.write(JSON.stringify(result)+'\n');if(result.output===null)process.exitCode=2;
    }
  } catch {gate.abort();process.stdout.write('{"decision":"block","output":null,"reasons":["CLI_INPUT_FAILURE"]}\n');process.exitCode=2;}
  finally{engine.dispose();}
}
// No top-level await: the same entry is bundled as CommonJS into the AIDR runtime binary.
main().catch(()=>{process.stdout.write('{"decision":"block","output":null,"reasons":["CLI_INPUT_FAILURE"]}\n');process.exitCode=2;});
