import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,readdir,rm,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';

test('portable reference preparation cannot overwrite approved operator inputs',async()=>{
 const root=await mkdtemp(join(tmpdir(),'aidr-private-preparation-')),output=join(root,'operator');
 const script=fileURLToPath(new URL('../../deployment/prepare-private.mjs',import.meta.url));
 const run=path=>spawnSync(process.execPath,[script,path],{encoding:'utf8',windowsHide:true});
 try{
  const prepared=run(output);assert.equal(prepared.status,0,prepared.stderr);assert.match(prepared.stdout,/CUSTOMER_INPUTS_AND_ACCEPTANCE_REQUIRED/);
  assert.equal((await readdir(output)).length,11);
  const inputs=JSON.parse(await readFile(join(output,'operator-inputs.json'),'utf8'));
  assert.equal(inputs.status,'NOT_CONFIGURED_OR_ACCEPTED');
  const service=JSON.parse(await readFile(join(output,'service.json'),'utf8'));
  assert.ok(service.dataPolicy.secretRef);assert.ok(service.documents.workerSha256.startsWith('REPLACE_'));
  await writeFile(join(output,'service.json'),'approved-operator-input');
  const repeated=run(output);assert.equal(repeated.status,1);assert.equal(await readFile(join(output,'service.json'),'utf8'),'approved-operator-input');
  assert.equal(run('relative-operator').status,1);
 }finally{await rm(root,{recursive:true,force:true});}
});
