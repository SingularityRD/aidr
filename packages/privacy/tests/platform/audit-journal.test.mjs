import test from 'node:test';import assert from 'node:assert/strict';
import {SqliteControlStore} from '../../dist/platform/state.js';
import {PersistentAuditJournal} from '../../dist/platform/persistent-audit.js';
import {verifyAudit,verifyAuditRotation,AuditChainVerifier} from '../../dist/enterprise/audit.js';
import {hash,mac} from '../../dist/enterprise/util.js';
import {fixture,NOW} from './helpers.mjs';
const K1=Buffer.alloc(32,41),K2=Buffer.alloc(32,42),K3=Buffer.alloc(32,43);
const event=(j,i,at=NOW)=>({eventId:'event'+i,at,actorRef:j.actor('alice'),destinationId:'provider',policyRevision:1,decision:'allow',classification:'public',reasons:[],counts:{},inputBytes:1});
async function fill(j,n,start=0,at=NOW){for(let i=0;i<n;i++)await j.append(event(j,start+i,at));}
/** Page through one segment with the bounded page API and verify continuity across pages. */
function exportSegment(j,key,checkpoint,pageSize=7){const v=new AuditChainVerifier(key,checkpoint.tenantId,checkpoint.logId),all=[];let from=1;
 for(;;){const p=j.page(from,pageSize,{logId:checkpoint.logId,upTo:checkpoint.sequence});assert(p.records.length<=pageSize);assert(v.accept(p.records));all.push(...p.records);if(p.next===null)break;assert.equal(p.next,from+p.records.length);from=p.next;}
 return {ok:v.finish(checkpoint),records:all};}

// Item 13: the stored chain is bound to its key; restarts must not silently mix keys.
test('audit key: normal restart with the same key continues one verifiable chain',async()=>{const f=fixture();try{
 const a=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(a,2);a.dispose();
 const restarted=new SqliteControlStore(f.path,f.rings);try{const b=new PersistentAuditJournal(restarted.tenant('alpha'),'decisions','ak1',K1);await fill(b,2,2);
  assert.equal(b.checkpoint().sequence,4);assert.equal(b.checkpoint().logId,'decisions');assert(verifyAudit(b.records(),b.checkpoint(),K1));assert(b.records().every(r=>r.keyId==='ak1'));b.dispose();}finally{restarted.close();}
}finally{f.close();}});
test('audit key: a different keyId or different key bytes is refused at open and nothing is appended',async()=>{const f=fixture();try{
 const a=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(a,3);const before=a.checkpoint();
 assert.throws(()=>new PersistentAuditJournal(f.state,'decisions','ak2',K2),/AUDIT_KEY_MISMATCH/);
 assert.throws(()=>new PersistentAuditJournal(f.state,'decisions','ak1',K2),/AUDIT_KEY_MISMATCH/);
 assert.throws(()=>PersistentAuditJournal.open(f.state,'decisions','ak2',K2),/AUDIT_KEY_MISMATCH/);
 assert.deepEqual(a.checkpoint(),before);assert(verifyAudit(a.records(),a.checkpoint(),K1));
}finally{f.close();}});
test('audit key: a pre-binding head without keyId is verified through its last record',async()=>{const f=fixture();try{
 const a=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(a,2);
 f.state.transaction(tx=>{const c=tx.get('audit-head','decisions');const {keyId,...legacy}=c.value;assert.equal(keyId,'ak1');tx.put('audit-head','decisions',legacy,c.version);});
 assert.equal(f.state.get('audit-head','decisions').value.keyId,undefined);
 assert.throws(()=>new PersistentAuditJournal(f.state,'decisions','ak2',K2),/AUDIT_KEY_MISMATCH/);
 assert.throws(()=>new PersistentAuditJournal(f.state,'decisions','ak1',K2),/AUDIT_KEY_MISMATCH/);
 const b=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(b,1,2);assert.equal(f.state.get('audit-head','decisions').value.keyId,'ak1');assert(verifyAudit(b.records(),b.checkpoint(),K1));
}finally{f.close();}});
test('audit key: a head whose last record is missing or tampered fails closed as integrity',async()=>{const f=fixture();try{
 const a=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(a,2);
 f.state.transaction(tx=>{const c=tx.get('audit-head','decisions');tx.put('audit-head','decisions',{...c.value,head:'f'.repeat(64)},c.version);});
 assert.throws(()=>new PersistentAuditJournal(f.state,'decisions','ak1',K1),/AUDIT_INTEGRITY/);await assert.rejects(a.append(event(a,9)),/AUDIT_INTEGRITY/);
}finally{f.close();}});
test('audit key: legitimate rotation closes the old segment; both segments and the link verify independently',async()=>{const f=fixture();try{
 const a=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(a,5);const oldHead=a.checkpoint();
 const rotation=PersistentAuditJournal.rotate(f.state,'decisions',{keyId:'ak1',key:K1},{keyId:'ak2',key:K2},NOW+10);
 assert.equal(rotation.segment,1);assert.equal(rotation.closing.logId,'decisions');assert.equal(rotation.closing.sequence,5);assert.equal(rotation.closing.head,oldHead.head);assert.equal(rotation.toLogId,'decisions:s1');assert.equal(rotation.previous,'0'.repeat(64));
 // The old key can no longer extend the chain, in this handle or a new one.
 await assert.rejects(a.append(event(a,50,NOW+11)),/AUDIT_KEY_MISMATCH/);assert.throws(()=>new PersistentAuditJournal(f.state,'decisions','ak1',K1),/AUDIT_KEY_MISMATCH/);
 const b=new PersistentAuditJournal(f.state,'decisions','ak2',K2);assert.equal(b.checkpoint().sequence,0);await fill(b,4,100,NOW+10);
 await assert.rejects(b.append(event(b,200,NOW)),/CLOCK_ROLLBACK/);
 // Old segment: old key + closing checkpoint signed by the old key (both via bulk and paged export).
 const old=exportSegment(b,K1,b.rotations()[0].closing,2);assert(old.ok);assert.equal(old.records.length,5);assert(verifyAudit(old.records,rotation.closing,K1));assert(!verifyAudit(old.records,rotation.closing,K2));
 // New segment: new key only.
 const cp=b.checkpoint();assert.equal(cp.logId,'decisions:s1');assert(verifyAudit(b.records(),cp,K2));assert(!verifyAudit(b.records(),cp,K1));assert(b.records()[0].previousHash==='0'.repeat(64));
 // Link: endorsed by both keys and bound to the old head.
 assert.deepEqual(b.rotations(),[rotation]);assert(verifyAuditRotation(rotation,K1,K2));assert(!verifyAuditRotation(rotation,K2,K1));assert(!verifyAuditRotation(rotation,K1,K3));
 for(const tamper of [{closing:{...rotation.closing,head:'e'.repeat(64)}},{closing:{...rotation.closing,sequence:4}},{toKeyId:'ak3'},{toLogId:'decisions:s9'},{at:NOW+11},{previous:'1'.repeat(64)}])assert(!verifyAuditRotation({...rotation,...tamper},K1,K2),JSON.stringify(tamper));
 // A second rotation chains to the first; the old key of a closed segment cannot rotate again.
 assert.throws(()=>PersistentAuditJournal.rotate(f.state,'decisions',{keyId:'ak1',key:K1},{keyId:'ak3',key:K3},NOW+20),/AUDIT_KEY_MISMATCH/);
 const second=PersistentAuditJournal.rotate(f.state,'decisions',{keyId:'ak2',key:K2},{keyId:'ak3',key:K3},NOW+20);
 const {oldAuth,newAuth,...firstBody}=rotation;assert.equal(second.previous,hash(firstBody));assert.equal(second.closing.logId,'decisions:s1');
 assert(verifyAuditRotation(second,K2,K3,rotation));assert(!verifyAuditRotation(second,K2,K3));assert(!verifyAuditRotation(second,K2,K3,{...rotation,toKeyId:'other'}));
 const c=new PersistentAuditJournal(f.state,'decisions','ak3',K3);await fill(c,1,300,NOW+20);assert(verifyAudit(c.records(),c.checkpoint(),K3));assert.equal(c.checkpoint().logId,'decisions:s2');
 assert(exportSegment(c,K2,c.rotations()[1].closing).ok);assert.equal(c.rotations()[1].closing.sequence,4);assert(exportSegment(c,K1,c.rotations()[0].closing).ok);
 assert(f.state.events().some(e=>e.kind==='AUDIT_KEY_ROTATED'));assert(f.state.verify());
}finally{f.close();}});
test('audit key: rotation refuses same key id, backwards time, wrong old key and is atomic',async()=>{const f=fixture();try{
 const a=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(a,1);
 assert.throws(()=>PersistentAuditJournal.rotate(f.state,'decisions',{keyId:'ak1',key:K1},{keyId:'ak1',key:K2},NOW),/AUDIT_ROTATION_INVALID/);
 assert.throws(()=>PersistentAuditJournal.rotate(f.state,'decisions',{keyId:'ak1',key:K1},{keyId:'ak2',key:K2},NOW-1),/CLOCK_ROLLBACK/);
 assert.throws(()=>PersistentAuditJournal.rotate(f.state,'decisions',{keyId:'ak1',key:K3},{keyId:'ak2',key:K2},NOW),/AUDIT_KEY_MISMATCH/);
 assert.equal(a.rotations().length,0);await fill(a,1,1);assert(verifyAudit(a.records(),a.checkpoint(),K1));
 // open({rotateFrom}) rotates exactly once; a later restart that still carries rotateFrom does not rotate again.
 const b=PersistentAuditJournal.open(f.state,'decisions','ak2',K2,{rotateFrom:{keyId:'ak1',key:K1},at:NOW});await fill(b,1,2);
 const again=PersistentAuditJournal.open(f.state,'decisions','ak2',K2,{rotateFrom:{keyId:'ak1',key:K1},at:NOW});assert.equal(again.rotations().length,1);assert.equal(again.checkpoint().sequence,1);
 assert.throws(()=>PersistentAuditJournal.open(f.state,'decisions','ak3',K3,{rotateFrom:{keyId:'ak1',key:K1},at:NOW}),/AUDIT_KEY_MISMATCH/);
 // Rotating an empty log is allowed and its empty old segment verifies.
 const e=PersistentAuditJournal.rotate(f.state,'empty',{keyId:'ak1',key:K1},{keyId:'ak2',key:K2},NOW);assert.equal(e.closing.sequence,0);assert(verifyAudit([],e.closing,K1));assert(verifyAuditRotation(e,K1,K2));
}finally{f.close();}});
test('audit key: a concurrent handle on another connection sees the rotation and stops appending',async()=>{const f=fixture();const second=new SqliteControlStore(f.path,f.rings);try{
 const other=new PersistentAuditJournal(second.tenant('alpha'),'decisions','ak1',K1);await fill(other,1);
 PersistentAuditJournal.rotate(f.state,'decisions',{keyId:'ak1',key:K1},{keyId:'ak2',key:K2},NOW);
 await assert.rejects(other.append(event(other,1)),/AUDIT_KEY_MISMATCH/);
 const b=new PersistentAuditJournal(f.state,'decisions','ak2',K2);assert.equal(b.checkpoint().sequence,0);assert(verifyAudit(b.page(1,10,{logId:'decisions'}).records,b.rotations()[0].closing,K1));
}finally{second.close();f.close();}});

// Item 17: bounded, verifiable paged export.
test('audit export: bounded pages verify continuity; gaps, duplicates, reorders and truncation are rejected',async()=>{const f=fixture();try{
 const j=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(j,25);const cp=j.checkpoint();
 const {ok,records}=exportSegment(j,K1,cp,10);assert(ok);assert.deepEqual(records.map(r=>r.sequence),Array.from({length:25},(_,i)=>i+1));
 assert.throws(()=>j.page(1,1001),/CONTROL_INVALID/);assert.throws(()=>j.page(0,10),/CONTROL_INVALID/);assert.throws(()=>j.page(1,10,{upTo:26}),/AUDIT_EXPORT_RANGE/);assert.throws(()=>j.page(1,10,{logId:'decisions:s1'}),/AUDIT_SEGMENT_UNKNOWN/);
 assert.deepEqual(j.page(26,10).records,[]);assert.equal(j.page(26,10).next,null);
 const pages=[j.page(1,10),j.page(11,10),j.page(21,10)];
 const run=(seq,checkpoint=cp)=>{const v=new AuditChainVerifier(K1,'alpha','decisions');let ok=true;for(const p of seq)ok=v.accept(p)&&ok;return v.finish(checkpoint)&&ok;};
 assert.equal(run(pages.map(p=>p.records)),true);
 assert.equal(run([pages[0].records,pages[2].records]),false,'gap');
 assert.equal(run([pages[0].records,pages[0].records,pages[1].records,pages[2].records]),false,'duplicate page');
 assert.equal(run([pages[0].records,pages[1].records.slice(0,5),pages[1].records.slice(4),pages[2].records]),false,'overlapping record');
 assert.equal(run([pages[1].records,pages[0].records,pages[2].records]),false,'reorder');
 assert.equal(run([pages[0].records,pages[1].records]),false,'truncated');
 assert.equal(run([pages[0].records,[...pages[1].records.slice(0,3),{...pages[1].records[3],event:{...pages[1].records[3].event,decision:'block'}},...pages[1].records.slice(4)],pages[2].records]),false,'edited');
 assert.equal(run(pages.map(p=>p.records),{...cp,head:'a'.repeat(64)}),false,'forged checkpoint');
 const v=new AuditChainVerifier(K2,'alpha','decisions');assert.equal(v.accept(pages[0].records),false,'wrong key');
}finally{f.close();}});
test('audit export: appends from another connection between pages do not break a pinned export',async()=>{const f=fixture();const second=new SqliteControlStore(f.path,f.rings);try{
 const j=new PersistentAuditJournal(f.state,'decisions','ak1',K1),writer=new PersistentAuditJournal(second.tenant('alpha'),'decisions','ak1',K1);await fill(j,12);
 const cp=j.checkpoint(),v=new AuditChainVerifier(K1,'alpha','decisions');let p=j.page(1,5,{upTo:cp.sequence});assert(v.accept(p.records));
 await fill(writer,3,100);p=j.page(p.next,5,{upTo:cp.sequence});assert(v.accept(p.records));
 await Promise.all([fill(writer,2,200),fill(j,2,300)]);p=j.page(p.next,5,{upTo:cp.sequence});assert(v.accept(p.records));assert.equal(p.next,null);assert.equal(v.sequence,12);
 // The pinned export continues from its last hash to the newer checkpoint without re-reading earlier pages.
 const later=j.checkpoint();assert.equal(later.sequence,19);assert(!v.finish(later));
 const resume=new AuditChainVerifier(K1,'alpha','decisions');for(let from=1;;){const q=j.page(from,5,{upTo:later.sequence});assert(resume.accept(q.records));if(q.next===null)break;from=q.next;}assert(resume.finish(later));
}finally{second.close();f.close();}});
test('audit export: more than 100000 decisions export completely across bounded pages with sequence/hash verification',{timeout:300000},async()=>{const f=fixture();try{
 // Synthetic but authentic chain: records are produced exactly like append() (same body, hash and MAC) inside one
 // transaction, so building it does not pay 100k fsyncs. Real appends then extend it through the public API.
 const N=100001;let head='0'.repeat(64);
 f.state.transaction(tx=>{for(let i=1;i<=N;i++){const body={format:'aidr-audit-v1',tenantId:'alpha',logId:'decisions',keyId:'ak1',sequence:i,previousHash:head,event:{eventId:'e'+i,at:NOW,actorRef:'a'.repeat(64),destinationId:'provider',policyRevision:1,decision:'allow',classification:'public',reasons:[],counts:{},inputBytes:1}},entryHash=hash(body);
  tx.put('audit-records','decisions.'+String(i).padStart(12,'0'),{...body,entryHash,auth:mac(K1,'aidr-audit-auth-v1',entryHash)},null);head=entryHash;}tx.put('audit-head','decisions',{sequence:N,head,lastAt:NOW,keyId:'ak1'},null);});
 const j=new PersistentAuditJournal(f.state,'decisions','ak1',K1);await fill(j,2,N+1);const cp=j.checkpoint();assert.equal(cp.sequence,N+2);
 assert.throws(()=>j.records(),/AUDIT_EXPORT_LIMIT/,'the unpaged in-memory export stays bounded');
 const v=new AuditChainVerifier(K1,'alpha','decisions');let from=1,pages=0,count=0,last=0;
 for(;;){const p=j.page(from,1000,{upTo:cp.sequence});assert(p.records.length<=1000);assert.equal(p.records[0].sequence,last+1);last=p.records.at(-1).sequence;count+=p.records.length;pages++;assert(v.accept(p.records));if(p.next===null)break;from=p.next;}
 assert.equal(count,N+2);assert.equal(pages,Math.ceil((N+2)/1000));assert.equal(v.head,cp.head);assert(v.finish(cp));
}finally{f.close();}});
