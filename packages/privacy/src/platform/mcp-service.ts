import {TextGatewayClient,type TextGatewayClientOptions} from './client.js';
import {mcpPrivacyGuards} from './mcp-scanner-adapter.js';
import {deny,id} from '../enterprise/util.js';

export interface PrivateMcpServiceOptions {
 tenantId:string;client:TextGatewayClientOptions;gateway:Record<string,unknown>;
}
interface InstalledMcpGateway {
 listen():Promise<{address:string;port:number}>;
 close():Promise<void>;
}
/** Single-tenant, text-only host. The installed signed gateway owns routing and attestation. */
export async function startPrivateMcpService(options:PrivateMcpServiceOptions,signal?:AbortSignal){
 const tenantId=id(options.tenantId),config=structuredClone(options.gateway);
 if(!Array.isArray(config.clients)||!config.clients.length||!Array.isArray(config.servers)||!config.servers.length||
  [...config.clients,...config.servers].some(row=>!row||row.tenantId!==tenantId))deny('MCP_TENANT_CONFIG');
 // Complete canonical JSON must fit the local scanner; there is no large/binary fallback.
 if(config.maxBodyBytes!==undefined&&(!Number.isSafeInteger(config.maxBodyBytes)||(config.maxBodyBytes as number)>262144))deny('MCP_BODY_LIMIT');
 config.maxBodyBytes??=262144;config.routingRequired=true;
 const client=new TextGatewayClient(options.client),text='{"status":"gateway readiness"}';
 signal?.throwIfAborted();const probe=await client.protect(text,{binding:{tenantId,runtime:'mcp-gateway',method:'startup'},...(signal?{signal}:{})});
 if(probe.decision!=='allow'||probe.output!==text)deny('MCP_PRIVACY_UNAVAILABLE');signal?.throwIfAborted();
 // Variable import resolves the installed optional peer, never a checkout/source alias.
 // Its public entry independently verifies the signed gateway artifact before exporting the factory.
 const packageName='@singularityrd/aidr-mcp-gateway',module=await import(packageName);
 if(typeof module.createMcpGateway!=='function')deny('MCP_GATEWAY_PACKAGE');
 signal?.throwIfAborted();
 const gateway:InstalledMcpGateway=module.createMcpGateway(config,mcpPrivacyGuards(client));
 try{
  const address=await gateway.listen();signal?.throwIfAborted();
  return {address,close:()=>gateway.close()};
 }catch(error){await gateway.close().catch(()=>undefined);throw error;}
}
