import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { PrivacyEngine } from '../dist/index.js';
import { createToolGuard } from '../examples/aidr-tool-guard.mjs';
const cli=new URL('../dist/cli.js',import.meta.url);
function run(input,args=[]){return spawnSync(process.execPath,[cli.pathname,...args],{input,encoding:'utf8',timeout:5000});}
test('CLI text redacts and never logs raw input',()=>{
 const r=run('Contact alice@example.com');assert.equal(r.status,0);assert.equal(r.stderr,'');
 assert.equal(JSON.parse(r.stdout).output,'Contact [EMAIL]');assert.ok(!r.stdout.includes('alice@example.com'));
});
test('CLI fixed redaction mode',()=>assert.equal(JSON.parse(run('alice@example.com',['--redact']).stdout).output,'[REDACTED]'));
test('CLI JSON schema redaction',()=>{const r=run('{"name":"Jane Doe","email":"jane@example.com"}',['--json']);assert.equal(r.status,0);assert.equal(JSON.parse(JSON.parse(r.stdout).output).name,'[PERSON]');});
test('CLI classification blocks with exit 2',()=>{const r=run('TOP SECRET\ninternal material');assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).output,null);});
test('CLI invalid JSON blocks',()=>{const r=run('{"password":"secret",}',['--json']);assert.equal(r.status,2);assert.ok(!r.stdout.includes('secret'));});
test('CLI duplicate keys block',()=>{const r=run('{"x":"safe","x":"secret"}',['--json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).output,null);});
test('CLI invalid UTF8 blocks',()=>{const r=run(Buffer.from([0xff,0xfe]));assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).output,null);});
test('CLI size bound blocks',()=>{const r=run('x'.repeat(65537));assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).output,null);});
test('CLI unknown option is rejected without echoing it',()=>{const r=run('x',['--private-secret-value']);assert.equal(r.status,64);assert.ok(!r.stderr.includes('private-secret-value'));});
test('Tool guard passes only protected arguments',async()=>{
 let sent;const guard=createToolGuard(new PrivacyEngine(),async(name,args)=>{sent={name,args};return 'ok';});
 assert.equal(await guard('search','{"email":"alice@example.com","query":"documentation"}'),'ok');
 assert.deepEqual(sent,{name:'search',args:{email:'[EMAIL]',query:'documentation'}});
});
test('Tool guard never calls sink on block',async()=>{
 let calls=0;const guard=createToolGuard(new PrivacyEngine(),async()=>calls++);
 await assert.rejects(guard('search','{"text":"TOP SECRET\\noperations"}'),/AIDR_EGRESS_DENIED/);assert.equal(calls,0);
});
test('Tool guard never calls sink on review',async()=>{
 let calls=0;const guard=createToolGuard(new PrivacyEngine({actions:{EMAIL:'review'}}),async()=>calls++);
 await assert.rejects(guard('search','{"email":"alice@example.com"}'),/AIDR_EGRESS_DENIED/);assert.equal(calls,0);
});
test('Tool guard never falls back when NER missing',async()=>{
 let calls=0;const guard=createToolGuard(new PrivacyEngine({profile:'defense'}),async()=>calls++);
 await assert.rejects(guard('search','{"text":"benign"}'),/AIDR_EGRESS_DENIED/);assert.equal(calls,0);
});
