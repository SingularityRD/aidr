import { createServer, type Server as HttpsServer } from 'node:https';
import type { KeyObject } from 'node:crypto';
import { PrivacyEngine } from '../engine.js';
import { EnterprisePrivacyGate } from '../enterprise/engine.js';
import { PolicyRegistry, type SignedPolicy } from '../enterprise/policy.js';
import type { NerProvider } from '../types.js';
import { SqliteControlStore, type Keyring } from './state.js';
import { PinnedJwtVerifier, ContextResolver, type JwtTrust } from './identity.js';
import { PersistentAuditJournal } from './persistent-audit.js';
import { DurableBudget, DurablePolicyCheckpoint } from './durable.js';
import { EnforcedEgress } from './egress.js';
import { createEgressHandler } from './gateway-http.js';
import { providerTransport, type ProviderKind } from './network.js';
import { hash, deny } from '../enterprise/util.js';
export interface RuntimeOptions {
 tenantId:string;databasePath:string;encryption:Keyring;audit:{keyId:string;key:Uint8Array};
 identity:{user:JwtTrust;device:JwtTrust;provider:JwtTrust;roleGroups:Readonly<Record<string,readonly string[]>>;scopes:readonly string[]};
 policy:{signed:SignedPolicy;keys:ReadonlyMap<string,KeyObject>};
 destinations:readonly {id:string;kind:ProviderKind;model:string;apiKey:string}[];
 /** Default defense profile requires approved learned TR/EN PERSON+ADDRESS coverage declarations.
  * Declarations still need independent accuracy qualification. */
 ner?:NerProvider;profile?:'strict'|'defense';clock?:()=>number;
}
/** Wire the existing engine, actual durable audit, pinned policy and strict channel-bound identity.
 * One database per organization/runtime. Shared control state is SAME-HOST, not multi-node HA. */
export async function createPlatformRuntime(o:RuntimeOptions){
 const clock=o.clock??Date.now,store=new SqliteControlStore(o.databasePath,new Map([[o.tenantId,o.encryption]]));
 try{
  const state=store.tenant(o.tenantId),checkpoint=new DurablePolicyCheckpoint(state),old=checkpoint.read();const registry=new PolicyRegistry(o.tenantId,o.policy.keys,old);
  await registry.installDurable(o.policy.signed,c=>checkpoint.write(c),clock);
  const identity=new ContextResolver({tenantId:o.tenantId,state,user:new PinnedJwtVerifier({...o.identity.user,purpose:'user'}),device:new PinnedJwtVerifier({...o.identity.device,purpose:'device'}),provider:new PinnedJwtVerifier({...o.identity.provider,purpose:'provider'}),roleGroups:o.identity.roleGroups,allowedScopes:o.identity.scopes,requireTransportBinding:true,clock});
  const audit=new PersistentAuditJournal(state,'decisions',o.audit.keyId,o.audit.key),text=new PrivacyEngine({profile:o.profile??'defense',...(o.ner?{ner:o.ner}:{})});
  const gate=new EnterprisePrivacyGate({registry,audit,textEngine:text,clock});
  const destinations=o.destinations.map(d=>({id:d.id,kind:d.kind,model:d.model,...providerTransport(d.kind,d.model,d.apiKey)}));
  const egress=new EnforcedEgress({state,identity,destinations,gate:()=>gate,policyEpoch:()=>hash(registry.active(clock())),clock,budget:new DurableBudget(state)});
  return {store,state,identity,registry,gate,egress,handler:createEgressHandler(egress),close(){audit.dispose();store.close();}};
 }catch(e){store.close();throw e;}
}
/** Direct mTLS listener. Client CA must represent enrolled devices; JWT device cnf binds exact key.
 * Provider credentials stay server-side. Do not grant callers a direct network route around it. */
export function listenPlatform(runtime:Awaited<ReturnType<typeof createPlatformRuntime>>,tls:{key:Buffer;cert:Buffer;clientCa:Buffer},port=8443,host='127.0.0.1'):Promise<HttpsServer>{
 if(!Number.isInteger(port)||port<1||port>65535)deny('LISTEN_PORT');
 const server=createServer({key:tls.key,cert:tls.cert,ca:tls.clientCa,requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.2'},runtime.handler);server.maxHeadersCount=24;server.headersTimeout=10000;server.requestTimeout=15000;server.maxConnections=64;server.setTimeout(60000);
 return new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>resolve(server));});
}
