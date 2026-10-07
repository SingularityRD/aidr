import test from'node:test';import assert from'node:assert/strict';import{readFileSync,realpathSync}from'node:fs';import{resolve}from'node:path';import{execFileSync}from'node:child_process';
import{pythonExecutable}from'./helpers.mjs';import{DocumentCdr,PDF_MIME}from'../../dist/platform/documents.js';import{bytesDigest}from'../../dist/platform/state.js';import{PrivacyEngine}from'../../dist/index.js';
// The real worker installs Linux seccomp before parsing and refuses to run elsewhere (PARSER_SANDBOX_UNAVAILABLE).
const linux={skip:process.platform!=='linux'&&'parser worker requires Linux seccomp'};
const worker=resolve('parsers/worker.py');
function cdr(protector=new PrivacyEngine({profile:'strict'})){return new DocumentCdr({python:realpathSync(pythonExecutable()),worker,workerSha256:bytesDigest(readFileSync(worker)),protector});}
/** Fixtures come from the Python test builder (hand-written base-14 font PDFs), so both suites share them. */
function fixture(args=''){return execFileSync(pythonExecutable(),['-c',`import sys,test_pdf_redaction as t;sys.stdout.buffer.write(t.pdf(${args}))`],{cwd:resolve('parsers')});}
/** Independent inspection of the output with both extractors (outside the worker). */
function inspect(b){return JSON.parse(execFileSync(pythonExecutable(),['-c','import sys,io,json,pypdfium2 as p;from pypdf import PdfReader;b=sys.stdin.buffer.read();r=PdfReader(io.BytesIO(b));d=p.PdfDocument(b);print(json.dumps({"pages":len(r.pages),"pdfium":len(d),"text":[x.extract_text() for x in r.pages],"chars":[d[i].get_textpage().count_chars() for i in range(len(d))],"meta":r.metadata is not None or any(d.get_metadata_dict().values())}))'],{input:b,encoding:'utf8'}));}

test('pdf redaction: explicit opt-in only; other kinds never fall back to the original',async()=>{
 const c=cdr();
 for(const kind of ['docx','zip','txt','eml']){const r=await c.protect(Buffer.from('x'),kind,{output:'pdf'});assert.equal(r.output,null);assert.equal(r.decision,'block');assert.equal(r.reason,'FORMAT_PRESERVING_UNSUPPORTED');}
 assert.equal((await c.protect(Buffer.from('x'),'pdf',{output:'office'})).reason,'FORMAT_PRESERVING_UNSUPPORTED');
 assert.equal((await c.protect(Buffer.from('x'),'pdf',{output:'png'})).reason,'PARSER_INPUT');
});
test('pdf redaction: real sandboxed PDF becomes an image-only PDF with no text and no metadata',linux,async()=>{
 const r=await cdr().protect(fixture(),'pdf',{output:'pdf'});
 assert.equal(r.decision,'redact',r.reason);assert.equal(r.reason,'FORMAT_PRESERVING_REDACTION');assert.equal(r.mime,PDF_MIME);assert.equal(r.filename,'aidr-redacted.pdf');
 const raw=r.output.toString('latin1');assert(raw.startsWith('%PDF-1.4\n'));
 for(const needle of ['example','Jane Doe','Secret Producer','/Info','/Font','4111111111111111'])assert(!raw.includes(needle),needle);
 const seen=inspect(r.output);assert.equal(seen.pages,2);assert.equal(seen.pdfium,2);assert.deepEqual(seen.chars,[0,0]);assert(seen.text.every(t=>t.trim()===''));assert.equal(seen.meta,false);
});
test('pdf redaction: default output for a PDF stays text-only',linux,async()=>{
 const r=await cdr().protect(fixture(),'pdf');assert.equal(r.mime,'text/plain');assert.equal(r.filename,'aidr-sanitized.txt');assert.equal(r.reason,'TEXT_ONLY_RECONSTRUCTION');
});
test('pdf redaction: missing spans, policy review, inline images and oversized pages fail closed',linux,async()=>{
 const noSpans={protect:async t=>({decision:'redact',output:t.replaceAll('example.com','[X]')})};
 assert.equal((await cdr(noSpans).protect(fixture(),'pdf',{output:'pdf'})).reason,'REDACTION_SPANS_REQUIRED');
 const review=await cdr({protect:async()=>({decision:'review',output:null})}).protect(fixture(),'pdf',{output:'pdf'});assert.equal(review.decision,'review');assert.equal(review.output,null);
 const image=await cdr().protect(fixture(String.raw`extra=b'q 10 0 0 10 300 300 cm BI /W 1 /H 1 /CS /G /BPC 8 ID \x80 EI Q\n'`),'pdf',{output:'pdf'});assert.equal(image.output,null);assert.equal(image.reason,'PDF_ACTIVE_OR_IMAGE');
 const big=await cdr().protect(fixture('mediabox=(0,0,14400,14400)'),'pdf',{output:'pdf'});assert.equal(big.output,null);assert.equal(big.reason,'PDF_PAGE_TOO_LARGE');
});
