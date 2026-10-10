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
import { ReviewWorkflow } from './review.js';
import {DurableDataPolicy} from './data-policy.js';
import {DspmRepository} from './dspm.js';
export interface RuntimeOptions {
 tenantId:string;databasePath:string;encryption:Keyring;
 /** Startup refuses (AUDIT_KEY_MISMATCH) a key that does not verify the stored chain. To rotate, keep the old key
  * in `rotateFrom` for the restart: the old segment is closed with a signed checkpoint and a new segment starts. */
 audit:{keyId:string;key:Uint8Array;rotateFrom?:{keyId:string;key:Uint8Array}};
 identity:{user:JwtTrust;device:JwtTrust;provider:JwtTrust;roleGroups:Readonly<Record<string,readonly string[]>>;scopes:readonly string[]};
 policy:{signed:SignedPolicy;keys:ReadonlyMap<string,KeyObject>};
 destinations:readonly {id:string;kind:ProviderKind;model:string;apiKey:string}[];
 /** Opt-in institution data labels, ingested by authenticated security-admin through the repository. */
 dataPolicy?:{keyId:string;key:Uint8Array};
 /** Default defense profile requires approved learned TR/EN PERSON+ADDRESS coverage declarations.
  * Declarations still need independent accuracy qualification. */
 ner?:NerProvider;profile?:'strict'|'defense';clock?:()=>number;
}
/** Wire the existing engine, actual durable audit, pinned policy and strict channel-bound identity.
 * One database per organization/runtime. Shared control state is SAME-HOST, not multi-node HA. */
export async function createPlatformRuntime(o:RuntimeOptions){
 const clock=o.clock??Date.now,store=new SqliteControlStore(o.databasePath,new Map([[o.tenantId,o.encryption]]));let dataPolicy:DurableDataPolicy|undefined;
 try{
  const state=store.tenant(o.tenantId),checkpoint=new DurablePolicyCheckpoint(state),old=checkpoint.read();const registry=new PolicyRegistry(o.tenantId,o.policy.keys,old);
  await registry.installDurable(o.policy.signed,c=>checkpoint.write(c),clock);
  const identity=new ContextResolver({tenantId:o.tenantId,state,user:new PinnedJwtVerifier({...o.identity.user,purpose:'user'}),device:new PinnedJwtVerifier({...o.identity.device,purpose:'device'}),provider:new PinnedJwtVerifier({...o.identity.provider,purpose:'provider'}),roleGroups:o.identity.roleGroups,allowedScopes:o.identity.scopes,requireTransportBinding:true,clock});
  const audit=PersistentAuditJournal.open(state,'decisions',o.audit.keyId,o.audit.key,o.audit.rotateFrom?{rotateFrom:o.audit.rotateFrom,at:clock()}:{}),text=new PrivacyEngine({profile:o.profile??'defense',...(o.ner?{ner:o.ner}:{})});
  if(o.dataPolicy){dataPolicy=new DurableDataPolicy(state,o.dataPolicy.keyId,Buffer.from(o.dataPolicy.key));dataPolicy.scan('');}
  const gate=new EnterprisePrivacyGate({registry,audit,textEngine:text,clock,...(dataPolicy?{indexes:[dataPolicy]}:{})});
  const sources=new DspmRepository(state,identity,clock);
  const destinations=o.destinations.map(d=>({id:d.id,kind:d.kind,model:d.model,...providerTransport(d.kind,d.model,d.apiKey)}));
  const policyEpoch=()=>hash({policy:registry.active(clock()),dataRevision:dataPolicy?state.get<number>('dspm-policy','revision')?.value??0:null});
  const reviews=new ReviewWorkflow(state,identity,clock),egress=new EnforcedEgress({state,identity,destinations,gate:()=>gate,policyEpoch,clock,budget:new DurableBudget(state),reviews});
  return {store,state,identity,registry,audit,gate,reviews,egress,sources,dataPolicy,policyEpoch,handler:createEgressHandler(egress),close(){dataPolicy?.dispose();text.dispose();audit.dispose();store.close();}};
 }catch(e){dataPolicy?.dispose();store.close();throw e;}
}
/** Direct mTLS listener. Client CA must represent enrolled devices; JWT device cnf binds exact key.
 * Provider credentials stay server-side. Do not grant callers a direct network route around it. */
export function listenPlatform(runtime:Awaited<ReturnType<typeof createPlatformRuntime>>,tls:{key:Buffer;cert:Buffer;clientCa:Buffer},port=8443,host='127.0.0.1'):Promise<HttpsServer>{
 if(!Number.isInteger(port)||port<1||port>65535)deny('LISTEN_PORT');
 const server=createServer({key:tls.key,cert:tls.cert,ca:tls.clientCa,requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.2',maxHeaderSize:81920},runtime.handler);server.maxHeadersCount=24;server.headersTimeout=10000;server.requestTimeout=15000;server.maxConnections=64;server.setTimeout(60000);
 return new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>resolve(server));});
}
