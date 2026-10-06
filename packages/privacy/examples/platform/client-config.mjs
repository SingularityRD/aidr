import {readFileSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {resolveSecretStore,platformSecretStoreKind} from '@singularityrd/aidr-core';
const path=process.env.AIDR_PRIVACY_CLIENT_CONFIG;if(!path||!isAbsolute(path))throw new Error('CLIENT_CONFIG_PATH');
const config=JSON.parse(readFileSync(path,'utf8')),vault=resolveSecretStore({selection:config.secretStore});
if(!vault.osProtected||vault.location!=='os-vault'||vault.kind!==platformSecretStoreKind())throw new Error('CLIENT_VAULT_REQUIRED');
const secret=ref=>{const s=vault.get(ref);if(!s)throw new Error('CLIENT_SECRET_MISSING');return s;};
export const loadSecret=secret;
export function saveCredentials(value){
 if(!value||Object.keys(value).sort().join(',')!=='deviceToken,providerToken,userToken'||Object.values(value).some(x=>typeof x!=='string'||!x))throw new Error('CLIENT_SESSION_DENIED');
 vault.put(config.credentialsRef,JSON.stringify(value));
}
export default {origin:config.origin,destinationId:config.destinationId,
 tls:{ca:readFileSync(config.caPath),cert:readFileSync(config.certPath),key:Buffer.from(secret(config.keyRef))},
 credentials:()=>JSON.parse(secret(config.credentialsRef))};
