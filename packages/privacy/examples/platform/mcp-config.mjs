import {readFileSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import client,{loadSecret} from './client-config.mjs';
// Signed gateway's JSON contains approved manifests, pins and token references, never privacy keys.
const path=process.env.AIDR_PRIVACY_MCP_CONFIG;if(!path||!isAbsolute(path))throw new Error('MCP_CONFIG_PATH');
const config=JSON.parse(readFileSync(path,'utf8'));
const required=new Set([...config.gateway.clients.map(c=>c.probeTokenEnv),...config.gateway.servers.map(s=>s.upstreamAuthEnv)]);
for(const name of required){if(typeof name!=='string'||!/^[A-Z][A-Z0-9_]{0,127}$/.test(name)||typeof config.gatewayTokenRefs?.[name]!=='string')throw new Error('MCP_VAULT_REFERENCE');process.env[name]=loadSecret(config.gatewayTokenRefs[name]);}
export default {tenantId:config.tenantId,client,gateway:config.gateway};
