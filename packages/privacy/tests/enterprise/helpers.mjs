import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {PolicyRegistry,signPolicy,AuditJournal,EnterprisePrivacyGate,ToolCallGuard,ApprovalLedger,toolDefinitionHash} from '../../dist/enterprise/index.js';
export const NOW=1_800_000_000_000;
export const key=()=>randomBytes(32);
export const keys=generateKeyPairSync('ed25519');
export function policy(patch={}){return {schemaVersion:1,tenantId:'tenant-a',policyId:'enterprise-v1',revision:1,notBefore:NOW-1000,expiresAt:NOW+60000,
 destinations:[{id:'corp-ai',origin:'https://ai.example.com',accounts:['enterprise'],requireVerifiedAccount:true,requireManagedDevice:true,requireProvenance:false,maxClassification:'internal',groups:['engineering']}],
 unknownDestination:'block',piiAction:'redact',injectionAction:'review',blockActiveContent:true,maxInputBytes:65536,...patch};}
export function context(patch={}){return {tenantId:'tenant-a',subjectId:'subject-1',sessionId:'session-1',groups:['engineering'],scopes:['data:read'],device:'managed',account:'enterprise',accountVerified:true,destination:'https://ai.example.com',channel:'api',assetIds:[],...patch};}
export function registry(p=policy(),now=NOW){const r=new PolicyRegistry(p.tenantId,new Map([['k1',keys.publicKey]]));r.install(signPolicy(p,'k1',keys.privateKey),now);return r;}
export function fixture(options={}){const records=[],auditKey=key();const audit=new AuditJournal('tenant-a','log-a','audit-k1',auditKey,async r=>{records.push(r);});
 const reg=options.registry??registry(options.policy??policy());let time=NOW;
 const gate=new EnterprisePrivacyGate({registry:reg,audit,clock:()=>time,...options});return {gate,records,audit,auditKey,registry:reg,setNow:x=>time=x};}
export const definition={name:'lookup',description:'Lookup a public item by opaque identifier',inputSchema:{type:'object',properties:{item:{type:'string'}},required:['item'],additionalProperties:false}};
export function rule(patch={}){return {serverId:'server-1',name:'lookup',definitionHash:toolDefinitionHash(definition),effect:'read',requiredScopes:['data:read'],allowedOrigins:['https://api.example.com'],requireApproval:false,
 arguments:{type:'object',properties:{item:{type:'string',maxLength:128,format:'opaque-id'}},required:['item'],additionalProperties:false},...patch};}
export function toolContext(patch={}){return {tenantId:'tenant-a',subjectId:'subject-1',sessionId:'session-1',scopes:['data:read'],...patch};}
export function request(patch={}){return {serverId:'server-1',name:'lookup',definition,argumentsJSON:'{"item":"item-a"}',...patch};}
export function toolFixture(options={}){let now=NOW;const approvals=new ApprovalLedger(key());const guard=new ToolCallGuard({tenantId:'tenant-a',policyRevision:1,key:key(),rules:[rule()],approvals,clock:()=>now,...options});return {guard,approvals,setNow:x=>now=x};}
export const approver={tenantId:'tenant-a',subjectId:'reviewer-1',roles:['security-approver']};
