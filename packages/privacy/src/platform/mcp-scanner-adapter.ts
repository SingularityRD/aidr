import {createHash} from 'node:crypto';
import {TextGatewayClient} from './client.js';
/** Matches the main gateway's documented callback structurally, without a public/private dependency. */
export interface McpScannerContext {
 payload:unknown;direction:'to_upstream'|'to_client';method:string;signal:AbortSignal;
 tenantId:string;clientId:string;serverId:string;requestId:string|number|null;
 inputSha256:string;payloadSha256:string;runtime:'mcp-gateway';sessionId:string|null;
 protocolVersion:string;toolsetHash:string;
}
export function mcpPrivacyGuards(client:TextGatewayClient){
 const scan=async(context:McpScannerContext):Promise<{allowed:boolean;coverage:'full';opaqueInspected:false}>=>{
  try{
   context.signal.throwIfAborted();const text=JSON.stringify(context.payload);if(typeof text!=='string'||createHash('sha256').update(text).digest('hex')!==context.payloadSha256)return {allowed:false,coverage:'full',opaqueInspected:false};
   const {signal,payload,...binding}=context;const result=await client.protect(text,{binding,signal});signal.throwIfAborted();
   // The main gateway releases its original JSON. Sanitized replacement is NOT permission for it.
   return {allowed:result.decision==='allow'&&result.output===text,coverage:'full',opaqueInspected:false};
  }catch{return {allowed:false,coverage:'full',opaqueInspected:false};}
 };
 return {toolGuard:scan,outputGuard:scan};
}
