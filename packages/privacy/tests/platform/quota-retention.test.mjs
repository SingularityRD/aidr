import test from 'node:test';import assert from 'node:assert/strict';import {spawn} from 'node:child_process';
import {SqliteControlStore} from '../../dist/platform/state.js';
import {DurableBudget,DurableApprovalLedger,DurableDispatchLedger} from '../../dist/platform/durable.js';
import {PersistentAuditJournal} from '../../dist/platform/persistent-audit.js';
import {fixture,NOW} from './helpers.mjs';
const rows=(state,ns)=>state.transaction(tx=>tx.count(ns,true));
const WINDOW=1000;

test('quota retention: multi-window load keeps physical quota rows bounded',()=>{const f=fixture();try{
 const q=new DurableBudget(f.state,WINDOW,5,1000),subjects=Array.from({length:10},(_,i)=>'user'+i);let max=0;
 for(let w=0;w<200;w++){for(const s of subjects)assert(q.consume('alpha',s,1,NOW+w*WINDOW));max=Math.max(max,rows(f.state,'quotas'));}
 // Without purge this would be 2000 rows (10 subjects x 200 windows); with it only the live and just-expired windows remain.
 assert(max<=2*subjects.length,'max rows '+max);assert(rows(f.state,'quotas')<=2*subjects.length);
 // A burst of 100 subjects in one window is drained in bounded batches (64 per consume), never all at once.
 const burst=NOW+1000*WINDOW;for(let i=0;i<100;i++)assert(q.consume('alpha','burst'+i,1,burst));assert.equal(rows(f.state,'quotas'),100,'live window rows are never purged');
 q.consume('alpha','late',1,burst+WINDOW);assert.equal(rows(f.state,'quotas'),100-64+1);q.consume('alpha','late',1,burst+WINDOW+1);assert.equal(rows(f.state,'quotas'),1);
}finally{f.close();}});
test('quota retention: purge never removes the live window, so limits hold within a window and after restart',()=>{const f=fixture();try{
 const q=new DurableBudget(f.state,WINDOW,3,1000);for(let i=0;i<3;i++)assert(q.consume('alpha','alice',1,NOW+i));assert(!q.consume('alpha','alice',1,NOW+WINDOW-1));
 const restarted=new SqliteControlStore(f.path,f.rings);try{const r=new DurableBudget(restarted.tenant('alpha'),WINDOW,3,1000);
  assert(!r.consume('alpha','alice',1,NOW+WINDOW-1),'live window survives restart');
  assert(r.consume('alpha','alice',1,NOW+WINDOW));assert.equal(rows(restarted.tenant('alpha'),'quotas'),1,'expired window purged after restart');
  assert.throws(()=>r.consume('alpha','alice',1,NOW),/CLOCK_ROLLBACK/,'a purged window cannot be re-entered by rolling the clock back');
 }finally{restarted.close();}
}finally{f.close();}});
test('quota retention: purge is tenant scoped',()=>{const f=fixture();try{
 const beta=f.store.tenant('beta'),qa=new DurableBudget(f.state,WINDOW,2,1000),qb=new DurableBudget(beta,WINDOW,2,1000);
 for(let w=0;w<5;w++)assert(qb.consume('beta','bob',1,NOW+w*WINDOW));assert(qb.consume('beta','bob',1,NOW+4*WINDOW+1));
 const betaRows=rows(beta,'quotas');for(let w=0;w<20;w++)qa.consume('alpha','alice',1,NOW+(50+w)*WINDOW);
 assert.equal(rows(beta,'quotas'),betaRows,'alpha consumes never purge beta rows');assert(!qb.consume('beta','bob',1,NOW+4*WINDOW+2),'beta live window intact');
 assert.throws(()=>qa.consume('beta','bob',1,NOW+100*WINDOW),/TENANT_MISMATCH/);
}finally{f.close();}});
test('quota retention: replay, clock, dispatch and audit namespaces are never purged by TTL',async()=>{const f=fixture();try{
 for(const ns of ['approvals','dispatch','internal','audit-records','audit-head','audit-rotations','jti','data'])assert.throws(()=>f.state.transaction(tx=>tx.purgeExpiredTransient(ns,NOW)),/STATE_TRANSIENT_NAMESPACE/,ns);
 const binding={tenantId:'alpha',subjectId:'alice',sessionId:'s1',policyRevision:1,actionDigest:'a'.repeat(64)},a=new DurableApprovalLedger(f.state);a.approve(binding,{tenantId:'alpha',subjectId:'bob',roles:['security-approver']},NOW,1000);
 new DurableDispatchLedger(f.state).reserve('req1','b'.repeat(64),'alice','s1',NOW);const j=new PersistentAuditJournal(f.state,'decisions','ak',Buffer.alloc(32,7));await j.append({eventId:'e1',at:NOW,actorRef:j.actor('alice'),destinationId:'p',policyRevision:1,decision:'allow',classification:'public',reasons:[],counts:{},inputBytes:1});
 const q=new DurableBudget(f.state,WINDOW,5,1000);for(let w=0;w<10;w++)q.consume('alpha','alice',1,NOW+w*WINDOW);
 assert.equal(rows(f.state,'approvals'),1,'expired approval tag is kept for replay protection');assert.equal(rows(f.state,'dispatch'),1);assert.equal(rows(f.state,'audit-records'),1);assert(f.state.get('internal','clock'));
}finally{f.close();}});
test('quota retention: concurrent processes over expired windows still grant exactly the limit',async()=>{const f=fixture();try{
 const pre=new DurableBudget(f.state,WINDOW,10,1000);for(let w=0;w<30;w++)pre.consume('alpha','user'+(w%7),1,NOW+w*WINDOW);
 const at=NOW+40*WINDOW,module=new URL('../../dist/platform/state.js',import.meta.url).href,durable=new URL('../../dist/platform/durable.js',import.meta.url).href;
 const script=`import{SqliteControlStore}from${JSON.stringify(module)};import{DurableBudget}from${JSON.stringify(durable)};const s=new SqliteControlStore(process.argv[1],new Map([['alpha',{active:'k1',keys:[{id:'k1',key:Buffer.alloc(32,11)}]}]]));const q=new DurableBudget(s.tenant('alpha'),${WINDOW},10,1000);let n=0;for(let i=0;i<12;i++)if(q.consume('alpha','alice',1,${at}))n++;s.close();console.log(n);`;
 const tasks=Array.from({length:6},()=>new Promise((res,rej)=>{const p=spawn(process.execPath,['--input-type=module','-e',script,f.path],{stdio:['ignore','pipe','pipe']});let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('exit',code=>code?rej(Error(err)):res(Number(out.trim())));p.on('error',rej);}));
 assert.equal((await Promise.all(tasks)).reduce((a,b)=>a+b,0),10);assert.equal(rows(f.state,'quotas'),1,'only the live window remains');
}finally{f.close();}});
