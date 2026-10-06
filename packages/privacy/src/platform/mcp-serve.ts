#!/usr/bin/env node
import {isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';
import {startPrivateMcpService} from './mcp-service.js';

const controller=new AbortController();let service:Awaited<ReturnType<typeof startPrivateMcpService>>|undefined,stopping=false;
const stop=()=>{if(stopping)return;stopping=true;controller.abort();service?.close().catch(()=>{process.stderr.write('MCP_STOP_FAILED\n');process.exitCode=1;});};
process.once('SIGINT',stop);process.once('SIGTERM',stop);
try{
 const args=process.argv.slice(2);if(args.length!==2||args[0]!=='--config'||!isAbsolute(args[1]!))throw new Error();
 // Administrator-owned config may use the existing OS vault. No caller dependency overrides.
 const config=await import(pathToFileURL(args[1]!).href);service=await startPrivateMcpService(config.default,controller.signal);
 if(stopping)await service.close();else process.stdout.write('MCP_PRIVACY_READY\n');
}catch{if(!stopping){process.stderr.write('MCP_START_FAILED\n');process.exitCode=1;}}
