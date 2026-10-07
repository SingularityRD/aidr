import test from'node:test';import assert from'node:assert/strict';import{readFileSync,realpathSync}from'node:fs';import{resolve}from'node:path';import{execFileSync}from'node:child_process';import{inflateRawSync}from'node:zlib';
import{pythonExecutable}from'./helpers.mjs';import{DocumentCdr,alignReplacements,unitEdits,OFFICE_MIME}from'../../dist/platform/documents.js';import{bytesDigest}from'../../dist/platform/state.js';import{PrivacyEngine}from'../../dist/index.js';
// The real worker installs Linux seccomp before parsing and refuses to run elsewhere (PARSER_SANDBOX_UNAVAILABLE).
const linux={skip:process.platform!=='linux'&&'parser worker requires Linux seccomp'};
const worker=resolve('parsers/worker.py');
function cdr(protector=new PrivacyEngine({profile:'strict'})){return new DocumentCdr({python:realpathSync(pythonExecutable()),worker,workerSha256:bytesDigest(readFileSync(worker)),protector});}
/** Fixtures come from the Python test builders, so both suites exercise the same generated packages. */
function fixture(kind){return execFileSync(pythonExecutable(),['-c',`import sys,test_office_redaction as t;sys.stdout.buffer.write(t.${kind}())`],{cwd:resolve('parsers')});}
/** Minimal central-directory ZIP reader (stored/deflate) used only to inspect test output. */
function unzip(b){const out={};let eocd=b.length-22;while(b.readUInt32LE(eocd)!==0x06054b50)eocd--;let p=b.readUInt32LE(eocd+16);for(let i=0;i<b.readUInt16LE(eocd+10);i++){const method=b.readUInt16LE(p+10),size=b.readUInt32LE(p+20),nameLen=b.readUInt16LE(p+28),extra=b.readUInt16LE(p+30),comment=b.readUInt16LE(p+32),local=b.readUInt32LE(p+42),name=b.subarray(p+46,p+46+nameLen).toString();const start=local+30+b.readUInt16LE(local+26)+b.readUInt16LE(local+28),raw=b.subarray(start,start+size);out[name]=method===8?inflateRawSync(raw):raw;p+=46+nameLen+extra+comment;}return out;}

test('office redaction: engine findings align to markers and map across units in code points',async()=>{
 const engine=new PrivacyEngine({profile:'strict'}),units=['😀 Contact: jane.doe@example.com today','card 4111111111111111','plain'],text=units.join('\n\n');
 const r=await engine.protect(text);assert.equal(r.decision,'redact');
 const reps=alignReplacements(text,r.output,r.findings);assert.deepEqual(reps,['[EMAIL]','[CREDIT_CARD]']);
 const edits=unitEdits(units,r.findings,reps);
 // The emoji is two UTF-16 units but one code point (the worker indexes Python str by code point).
 assert.deepEqual(edits,[[0,11,31,'[EMAIL]'],[1,5,21,'[CREDIT_CARD]']]);
});
test('office redaction: a span crossing a unit boundary is redacted in every unit, marker once',()=>{
 const units=['abc','def'];assert.deepEqual(unitEdits(units,[{start:1,end:7}],['[X]']),[[0,1,3,'[X]'],[1,0,2,'']]);
 assert.throws(()=>unitEdits(units,[{start:3,end:5}],['[X]']),/REDACTION_ALIGNMENT/);
});
test('office redaction: protector output that does not reconstruct exactly is refused',()=>{
 assert.equal(alignReplacements('a jane@example.com b','a [EMAIL] c',[{start:2,end:18}]),null);
 assert.equal(alignReplacements('a jane@example.com b','a EMAIL b',[{start:2,end:18}]),null);
 assert.equal(alignReplacements('a jane@example.com b','a [EMAIL] b',[{start:2,end:30}]),null);
 assert.deepEqual(alignReplacements('x','x',[]),[]);
});
test('office redaction: explicit opt-in only; unsupported formats never fall back to the original',async()=>{
 const c=cdr();for(const kind of ['pdf','zip','txt','toString','constructor']){const r=await c.protect(Buffer.from('x'),kind,{output:'office'});assert.equal(r.output,null);assert.equal(r.decision,'block');}
 assert.equal((await c.protect(Buffer.from('x'),'pdf',{output:'office'})).reason,'FORMAT_PRESERVING_UNSUPPORTED');
 assert.equal((await c.protect(Buffer.from('x'),'docx',{output:'html'})).reason,'PARSER_INPUT');
});
for(const kind of ['docx','xlsx','pptx'])test(`office redaction: real sandboxed ${kind} redacted in place, re-scanned clean, metadata dropped`,linux,async()=>{
 const r=await cdr().protect(fixture(kind),kind,{output:'office'});
 assert.equal(r.decision,'redact',r.reason);assert.equal(r.reason,'FORMAT_PRESERVING_REDACTION');assert.equal(r.mime,OFFICE_MIME[kind]);assert.equal(r.filename,`aidr-redacted.${kind}`);
 const parts=unzip(r.output),all=Buffer.concat(Object.values(parts)).toString('latin1');
 assert(!all.includes('example.com'));assert(!all.includes('Jane Doe'));assert(!all.includes('4111111111111111'));assert(all.includes('[EMAIL]'));
 assert(!Object.keys(parts).some(n=>n.startsWith('docProps/')));
});
test('office redaction: default output for an Office file stays text-only',linux,async()=>{
 const r=await cdr().protect(fixture('docx'),'docx');assert.equal(r.mime,'text/plain');assert.equal(r.filename,'aidr-sanitized.txt');assert.equal(r.reason,'TEXT_ONLY_RECONSTRUCTION');
});
test('office redaction: protector without spans, protected formula text and residual PII fail closed',linux,async()=>{
 const noSpans={protect:async t=>({decision:'redact',output:t.replaceAll('example.com','[X]')})};
 assert.equal((await cdr(noSpans).protect(fixture('docx'),'docx',{output:'office'})).reason,'REDACTION_SPANS_REQUIRED');
 // A detector miss on the first pass is caught by the independent re-parse + re-scan.
 const engine=new PrivacyEngine({profile:'strict'});let calls=0;const missFirst={protect:async t=>calls++===0?{decision:'allow',output:t,findings:[]}:engine.protect(t)};
 const miss=await cdr(missFirst).protect(fixture('docx'),'docx',{output:'office'});assert.equal(miss.output,null);assert.equal(miss.reason,'REDACTION_RESIDUAL');
 const formula=execFileSync(pythonExecutable(),['-c',`import sys,test_office_redaction as t;sys.stdout.buffer.write(t.xlsx(sheet='<sheetData><row r="1"><c r="A1"><f>"formula.user@example.com"</f></c></row></sheetData>'))`],{cwd:resolve('parsers')});
 const f=await cdr().protect(formula,'xlsx',{output:'office'});assert.equal(f.output,null);assert.equal(f.reason,'REDACT_PROTECTED_TEXT');
});
