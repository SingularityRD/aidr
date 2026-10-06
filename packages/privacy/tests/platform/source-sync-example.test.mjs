import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {synchronizeDirectory} from '../../examples/platform/source-sync.mjs';

test('operator directory snapshot preserves approved label/ACL and refuses partial or denied synchronization',async()=>{
 const root=await mkdtemp(join(tmpdir(),'aidr-source-example-'));let calls=0;
 const config={sourceId:'approved-source',generation:7,root,groups:['document-readers'],classification:'restricted'};
 const client={async synchronizeSource(sourceId,generation,documents){
  calls++;assert.equal(sourceId,'approved-source');assert.equal(generation,7);assert.equal(documents.length,1);
  assert.equal(documents[0].text,'authorized text');assert.deepEqual(documents[0].groups,['document-readers']);
  assert.equal(documents[0].classification,'restricted');return {synchronized:true};
 }};
 try{
  await writeFile(join(root,'record.txt'),'authorized text');await synchronizeDirectory(client,config);assert.equal(calls,1);
  await assert.rejects(synchronizeDirectory(client,{...config,groups:'document-readers'}),/SOURCE_CONFIG/);
  await writeFile(join(root,'uninspected.bin'),Buffer.from([0,1]));
  await assert.rejects(synchronizeDirectory(client,config),/SOURCE_FILE/);assert.equal(calls,1);
  await rm(join(root,'uninspected.bin'));
  await assert.rejects(synchronizeDirectory({synchronizeSource:async()=>({decision:'block',output:null})},config),/SOURCE_SYNCHRONIZATION_DENIED/);
 }finally{await rm(root,{recursive:true,force:true});}
});
