import type { TLSSocket } from 'node:tls';
import { ToolCallGuard, type ToolRequest } from '../enterprise/tools.js';
import { ContextResolver, type RequestCredentials } from './identity.js';
import { DurableDispatchLedger } from './durable.js';
import type { TenantState } from './state.js';
import type { ByteTransport } from './network.js';
import { hash,id,deny,frozen } from '../enterprise/util.js';
import { parseJsonStrict } from '../json.js';
/** Guarded JSON-RPC tools/call dispatch, not a complete MCP OAuth/StreamableHTTP session proxy.
 * The server connection and definition registry are trusted configuration; clients cannot set URLs. */
export class EnforcedMcpCall {
 #ledger:DurableDispatchLedger;
 constructor(private o:{state:TenantState;identity:ContextResolver;guard:ToolCallGuard;origin:string;serverId:string;transport:ByteTransport;definitions:ReadonlyMap<string,unknown>;policyEpoch:()=>string;clock?:()=>number}){this.o={...o,definitions:new Map(o.definitions)};this.#ledger=new DurableDispatchLedger(o.state);}
 async callOnTls(credentials:RequestCredentials,request:Parameters<EnforcedMcpCall['call']>[1],socket:TLSSocket):Promise<unknown>{return this.call(this.o.identity.bindTlsCredentials(credentials,socket),request);}
 async call(credentials:RequestCredentials,request:{requestId:string;name:string;argumentsJSON:string;approvalToken?:string}):Promise<unknown>{
  const req={requestId:id(request.requestId),name:id(request.name),argumentsJSON:request.argumentsJSON,approvalToken:request.approvalToken};
  const now=this.o.clock??Date.now,c=this.o.identity.resolve(credentials,this.o.origin,'api');if(c.principal.tenantId!==this.o.state.tenantId)deny('TENANT_MISMATCH');const epoch=this.o.policyEpoch(),definition=this.o.definitions.get(id(req.name));if(!definition)deny('MCP_TOOL_UNREGISTERED');
  const q:ToolRequest={serverId:this.o.serverId,name:req.name,definition:frozen(definition),argumentsJSON:req.argumentsJSON};const action=hash({q,epoch,subject:c.principal.subjectId,session:c.principal.sessionId});this.#ledger.reserve(id(req.requestId),action,c.principal.subjectId,c.principal.sessionId,now());let dispatched=false;
  try{return await this.o.guard.execute(q,{tenantId:c.principal.tenantId,subjectId:c.principal.subjectId,sessionId:c.principal.sessionId,scopes:c.context.scopes},async args=>{
   this.o.identity.assertContext(c);if(epoch!==this.o.policyEpoch())deny('POLICY_CHANGED');this.#ledger.transition(req.requestId,'reserved','dispatched',now());dispatched=true;
   const response=await this.o.transport.send(Buffer.from(JSON.stringify({jsonrpc:'2.0',id:req.requestId,method:'tools/call',params:{name:req.name,arguments:args}})));
   const body=parseJsonStrict(response.body.toString('utf8'),16,20000) as Record<string,unknown>;if(body.jsonrpc!=='2.0'||body.id!==req.requestId||!Object.hasOwn(body,'result')||Object.hasOwn(body,'error'))deny('MCP_RESPONSE');
   this.#ledger.transition(req.requestId,'dispatched','completed',now());dispatched=false;return body.result; // untrusted tool output: never interpreted as new policy/instructions
  },req.approvalToken);}catch(e){try{this.#ledger.transition(req.requestId,dispatched?'dispatched':'reserved',dispatched?'unknown':'failed',now());}catch{}throw new Error(dispatched?'MCP_OUTCOME_UNKNOWN':'MCP_DISPATCH_DENIED');}
 }
}
