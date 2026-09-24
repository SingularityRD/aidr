/** Offline integration demo. Synthetic input, ephemeral keys and a direct trusted SDK context.
 * NOT an IdP login, network egress or enrolled-device proof. Nothing is sent outside. */
import {mkdtempSync,chmodSync,rmSync} from 'node:fs';import {join} from 'node:path';import {tmpdir} from 'node:os';import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {createPlatformRuntime,PersistentAuditJournal} from '../../dist/platform/index.js';
import {signPolicy,verifyAudit} from '../../dist/enterprise/index.js';
const root=mkdtempSync(join(tmpdir(),'aidr-platform-demo-'));chmodSync(root,0o700);const keys=generateKeyPairSync('ed25519'),now=Date.now();let runtime;
try{
 const policy={schemaVersion:1,tenantId:'demo',policyId:'pilot',revision:1,notBefore:now-1000,expiresAt:now+600000,destinations:[{id:'approved-api',origin:'https://api.example.com',accounts:['enterprise'],requireVerifiedAccount:true,requireManagedDevice:true,requireProvenance:false,maxClassification:'internal',groups:['staff']}],unknownDestination:'block',piiAction:'redact',injectionAction:'review',blockActiveContent:true,maxInputBytes:65536};
 const trust={issuer:'https://issuer.example.com',audience:'aidr',keys:new Map([['signer',keys.publicKey]])},auditKey=randomBytes(32);
 runtime=await createPlatformRuntime({tenantId:'demo',databasePath:join(root,'control.sqlite'),encryption:{active:'data1',keys:[{id:'data1',key:randomBytes(32)}]},audit:{keyId:'audit1',key:auditKey},identity:{user:trust,device:trust,provider:trust,roleGroups:{},scopes:[]},policy:{signed:signPolicy(policy,'signer',keys.privateKey),keys:new Map([['signer',keys.publicKey]])},destinations:[],profile:'strict'});
 // Direct SDK only. HTTP clients cannot supply this JSON as their identity.
 const ctx={tenantId:'demo',subjectId:'operator',sessionId:'demo-session',groups:['staff'],scopes:[],device:'managed',account:'enterprise',accountVerified:true,destination:'https://api.example.com',channel:'api',assetIds:[]};
 const r=await runtime.gate.protect('Full name: Jane Smith; Email: jane@example.com',ctx);
 const audit=new PersistentAuditJournal(runtime.state,'decisions','audit1',auditKey);
 console.log(JSON.stringify({mode:'OFFLINE_SYNTHETIC_SDK_DEMO',decision:r.decision,sanitizedText:r.output,persistedDecisions:audit.records().length,auditVerified:verifyAudit(audit.records(),audit.checkpoint(),auditKey),note:'No NER, real SSO, provider or MDM assertion in this demo.'},null,2));audit.dispose();auditKey.fill(0);
}finally{runtime?.close();rmSync(root,{recursive:true,force:true});}
