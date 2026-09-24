import {execFileSync} from 'node:child_process';
import {mkdtempSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {generateKeyPairSync} from 'node:crypto';
import {SqliteControlStore} from '../../dist/platform/state.js';
import {ContextResolver,PinnedJwtVerifier,issueJwt,provisionSession} from '../../dist/platform/identity.js';
export const NOW=1_800_000_000_000;
export function fixture(){const root=mkdtempSync(join(tmpdir(),'aidr-p5-'));chmodSync(root,0o700);const path=join(root,'control.sqlite');const rings=new Map(['alpha','beta'].map((t,i)=>[t,{active:'k1',keys:[{id:'k1',key:Buffer.alloc(32,i+11)}]}]));const store=new SqliteControlStore(path,rings);return {root,path,rings,store,state:store.tenant('alpha'),close(){store.close();rmSync(root,{recursive:true,force:true});}};}
export function authFixture(f,clock=()=>NOW,identityOverrides={}){const keys={user:generateKeyPairSync('ed25519'),device:generateKeyPairSync('ed25519'),provider:generateKeyPairSync('ed25519')};const issuer='https://identity.example.com';
 const v=purpose=>new PinnedJwtVerifier({issuer,audience:'aidr-platform',purpose,keys:new Map([['signer',keys[purpose].publicKey]])});
 const resolver=new ContextResolver({tenantId:'alpha',state:f.state,user:v('user'),device:v('device'),provider:v('provider'),allowedScopes:['read','write'],requireTransportBinding:false,roleGroups:{'security-reviewer':['reviewers'],'security-approver':['reviewers'],'security-admin':['admins']},clock,...identityOverrides});
 for(const [sid,sub]of [['s1','alice'],['s2','bob']])provisionSession(f.state,{sessionId:sid,subjectId:sub,version:1,deviceId:'d1',active:true,expiresAt:NOW+600000},NOW);
 function token(purpose,extra={},sub='alice',sid='s1'){return issueJwt({iss:issuer,aud:'aidr-platform',sub,iat:NOW/1000,exp:NOW/1000+300,jti:purpose+'-'+sid,token_use:purpose,tenant_id:'alpha',sid,session_version:1,...(purpose==='user'?{groups:['reviewers','admins']}:{device_id:'d1'}),...(purpose==='device'?{managed:true,compliant:true}:{}),...(purpose==='provider'?{destination:'https://api.example.com',account:'enterprise',verified:true,logged_in:true,scopes:['read','write']}:{ }),...extra},'signer',keys[purpose].privateKey);}
 const credentials=()=>({userToken:token('user'),deviceToken:token('device'),providerToken:token('provider')});
 return {keys,resolver,token,credentials,user:()=>resolver.authenticate(token('user')),reviewer:()=>resolver.authenticate(token('user',{},'bob','s2')),context:()=>resolver.resolve(credentials(),'https://api.example.com')};}

export function pythonExecutable(){return process.env.AIDR_PYTHON??execFileSync('python3',['-c','import os,sys; print(os.path.realpath(sys.executable))'],{encoding:'utf8'}).trim();}
