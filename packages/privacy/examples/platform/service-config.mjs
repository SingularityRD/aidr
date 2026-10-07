/** Executable service configuration: install both private privacy and released core packages.
 * Administrator JSON contains references/paths only. Never use file-acl for this service. */
import {readFileSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {createPublicKey} from 'node:crypto';
import {resolveSecretStore,platformSecretStoreKind} from '@singularityrd/aidr-core';
import {ConfiguredSessionBroker} from '@singularityrd/aidr-privacy/platform';

const path=process.env.AIDR_PRIVACY_CONFIG;if(!path||!isAbsolute(path))throw new Error('SERVICE_CONFIG_PATH');
const config=JSON.parse(readFileSync(path,'utf8'));
const vault=resolveSecretStore({selection:config.secretStore});
if(!vault.osProtected||vault.location!=='os-vault'||vault.kind!==platformSecretStoreKind())throw new Error('SERVICE_VAULT_REQUIRED');
const secret=ref=>{const s=vault.get(ref);if(!s)throw new Error('SERVICE_SECRET_MISSING');return s;};
const key32=ref=>{const s=secret(ref),b=Buffer.from(s,'base64');if(b.length!==32||b.toString('base64')!==s)throw new Error('SERVICE_KEY_INVALID');return b;};
const file=path=>{if(!isAbsolute(path))throw new Error('SERVICE_CONFIG_PATH');return readFileSync(path);};
const broker=await ConfiguredSessionBroker.open({
 oidc:{...config.oidc,clientSecret:secret(config.oidc.clientSecretRef),tls:{ca:file(config.oidc.caPath)}},
 broker:{issuer:config.broker.issuer,audience:config.broker.audience,destination:config.destination.origin,
  tls:{ca:file(config.broker.caPath),cert:file(config.broker.certPath),key:Buffer.from(secret(config.broker.keyRef))}},
},AbortSignal.timeout(30000));
const destination=config.destination;
if(destination.origin!==(destination.kind==='openai-responses'?'https://api.openai.com':destination.kind==='gemini-generate-content'?'https://generativelanguage.googleapis.com':null))throw new Error('SERVICE_DESTINATION');
export default {
 runtime:{tenantId:config.tenantId,databasePath:config.databasePath,
  encryption:{active:config.encryption.active,keys:config.encryption.keys.map(k=>({id:k.id,key:key32(k.secretRef)}))},
  audit:{keyId:config.audit.keyId,key:key32(config.audit.secretRef)},
  ...(config.dataPolicy?{dataPolicy:{keyId:config.dataPolicy.keyId,key:key32(config.dataPolicy.secretRef)}}:{}),
  identity:{user:broker.trust,device:broker.trust,provider:broker.trust,roleGroups:config.roleGroups,scopes:config.scopes},
  policy:{signed:JSON.parse(file(config.policy.signedPath)),keys:new Map(config.policy.keys.map(k=>[k.id,createPublicKey(file(k.path))]))},
  destinations:[{id:destination.id,kind:destination.kind,model:destination.model,apiKey:secret(destination.secretRef)}]},
 ner:config.ner,...(config.documents?{documents:config.documents}:{}),...(config.audioMode?{audioMode:config.audioMode}:{}),tls:{key:Buffer.from(secret(config.tls.keyRef)),cert:file(config.tls.certPath),clientCa:file(config.tls.clientCaPath)},
 initializeBroker:(runtime,signal)=>broker.initialize(runtime,signal),host:config.host,port:config.port,
};
