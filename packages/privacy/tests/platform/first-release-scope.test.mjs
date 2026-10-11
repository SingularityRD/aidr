// First-release scope: capabilities outside the accepted scope, and inputs over the documented
// capacity, are refused with a stable reason code. Nothing here degrades to an allow or a clean result.
// FEATURE_INVENTORY.json#first_release_scope (scripts/generate-feature-inventory.mjs) cites these tests.
import test from 'node:test';import assert from 'node:assert/strict';
import {readFileSync,realpathSync} from 'node:fs';import {execFileSync} from 'node:child_process';import {resolve} from 'node:path';
import {fixture,authFixture,NOW,pythonExecutable,parserPrerequisiteSkip} from './helpers.mjs';
import {DspmRepository,readAuthorizedDirectory} from '../../dist/platform/dspm.js';
import {DurableDataPolicy,MAX_INDEXED_SOURCE_DOCUMENTS} from '../../dist/platform/data-policy.js';
import {DocumentCdr} from '../../dist/platform/documents.js';
import {AudioPrivacy,unsupportedModalityPolicy,requireCompleteVideoCoverage} from '../../dist/platform/modalities.js';
import {bytesDigest} from '../../dist/platform/state.js';
import {PrivacyEngine} from '../../dist/index.js';

const dataKey=()=>Buffer.alloc(32,7);
const words=(prefix,n)=>Array.from({length:n},(_,i)=>`${prefix}${i.toString(36)}`).join(' ');
const doc=(id,text,classification='restricted')=>({id,text,groups:['reviewers'],classification});
function setup(f){
 const a=authFixture(f),policy=new DurableDataPolicy(f.state,'dk',dataKey());
 const repo=new DspmRepository(f.state,a.resolver,()=>NOW,records=>policy.admit(records));
 const revision=()=>f.state.get('dspm-policy','revision')?.value??0;
 return {a,policy,repo,revision};
}

test('fingerprint scope: a source document over the supported index content size is refused before commit',()=>{
 const f=fixture();try{const {a,policy,repo,revision}=setup(f);
  repo.replace(a.user(),'s1',1,[doc('d1','Sensitive corporate record')],true);assert.equal(revision(),1);
  // 70 KiB passes the 512 KiB DSPM transport limit but not the 64 KiB fingerprint content bound.
  assert.throws(()=>repo.replace(a.user(),'s1',2,[doc('d1',('alpha bravo charlie delta ').repeat(2900))],true),/CONTENT_LIMIT/);
  assert.equal(revision(),1,'refused snapshot must not advance the policy revision');
  assert.equal(repo.read(a.user(),'s1','d1').text,'Sensitive corporate record','previous generation stays in force');
  assert.equal(policy.scan('Sensitive corporate record').length,1,'existing protection is not dropped');
  repo.replace(a.user(),'s1',2,[doc('d1','Sensitive corporate record')],true);
 }finally{f.close();}
});

test('fingerprint scope: more than 8192 normalized tokens in one source is refused with INDEX_CONTENT_LIMIT',()=>{
 const f=fixture();try{const {a,repo,revision}=setup(f);
  assert.throws(()=>repo.replace(a.user(),'s1',1,[doc('d1',words('',8193))],true),/INDEX_CONTENT_LIMIT/);
  assert.equal(revision(),0);
 }finally{f.close();}
});

test('fingerprint scope: exceeding 100,000 fingerprints is refused with INDEX_CAPACITY and nothing commits',()=>{
 const f=fixture();try{const {a,policy,repo,revision}=setup(f);
  // 13 documents x ~8,188 distinct five-token windows > 100,000 fingerprints.
  const documents=Array.from({length:13},(_,i)=>doc('d'+i,words(`t${i}x`,8192)));
  assert.throws(()=>repo.replace(a.user(),'s1',1,documents,true),/INDEX_CAPACITY/);
  assert.equal(revision(),0);assert.equal(f.state.list('dspm-documents',10).length,0);
  repo.replace(a.user(),'s1',1,documents.slice(0,12),true);assert.equal(revision(),1);
  assert.equal(policy.scan(documents[0].text.split(' ').slice(0,2000).join(' ')).length,1,'a quoted fragment above the 20% coverage threshold still matches');
 }finally{f.close();}
});

test('fingerprint scope: more than 1000 indexed source documents across sources is refused with DSPM_POLICY_CAPACITY',()=>{
 const f=fixture();try{const {a,policy,repo,revision}=setup(f);
  const batch=(prefix,n)=>Array.from({length:n},(_,i)=>doc(`${prefix}${i}`,`${prefix} record ${i}`));
  repo.replace(a.user(),'s1',1,batch('a',MAX_INDEXED_SOURCE_DOCUMENTS),true);
  assert.throws(()=>repo.replace(a.user(),'s2',1,batch('b',1),true),/DSPM_POLICY_CAPACITY/);
  assert.equal(revision(),1);assert.equal(policy.scan('a record 5').length,1);
 }finally{f.close();}
});

test('fingerprint scope: an already over-capacity store fails closed on every scan and an empty removal repairs it',()=>{
 const f=fixture();try{const {a,policy,repo}=setup(f);
  // An earlier release (no admission check) could commit more than the supported total.
  const legacy=new DspmRepository(f.state,a.resolver,()=>NOW);
  legacy.replace(a.user(),'s1',1,Array.from({length:1000},(_,i)=>doc('a'+i,'alpha record '+i)),true);
  legacy.replace(a.user(),'s2',1,[doc('b0','bravo record')],true);
  assert.throws(()=>policy.scan('benign public text'),/DSPM_POLICY_CAPACITY/);
  assert.throws(()=>repo.replace(a.user(),'s2',2,[doc('b0','bravo record')],true),/DSPM_POLICY_CAPACITY/);
  repo.removeSource(a.user(),'s2',2);
  assert.deepEqual(policy.scan('benign public text'),[]);
 }finally{f.close();}
});

test('media scope: video, CAD and other specialist modalities are refused, never passed',()=>{
 for(const kind of ['video','face','signature','handwriting','cad','steganography'])assert.deepEqual(unsupportedModalityPolicy(kind),{decision:'block',reason:'SPECIALIST_DETECTOR_REQUIRED'});
 for(const kind of ['mp3','m4a','opus','dwg','unknown'])assert.deepEqual(unsupportedModalityPolicy(kind),{decision:'block',reason:'UNSUPPORTED_MODALITY'});
 assert.throws(()=>requireCompleteVideoCoverage(2,[0],true),/VIDEO_INCOMPLETE/);
});

test('audio scope: compressed and over-limit audio is refused with a stable code; selective audio needs ASR',async()=>{
 const silence=new AudioPrivacy({mode:'silence-all'});
 await assert.rejects(silence.protect(Buffer.from('ID3\u0004 compressed MP3 payload that is not PCM WAV audio')),/AUDIO_FORMAT/);
 await assert.rejects(silence.protect(Buffer.concat([Buffer.from('OggS'),Buffer.alloc(60)])),/AUDIO_FORMAT/);
 // A WAV container carrying a compressed codec (format 0x55, MP3) is not PCM16; 96 kHz is outside 8-48 kHz.
 const wav=({format=1,rate=8000,frames=8}={})=>{const b=Buffer.alloc(44+frames*2);b.write('RIFF');b.writeUInt32LE(b.length-8,4);b.write('WAVEfmt ',8);b.writeUInt32LE(16,16);b.writeUInt16LE(format,20);b.writeUInt16LE(1,22);b.writeUInt32LE(rate,24);b.writeUInt32LE(rate*2,28);b.writeUInt16LE(2,32);b.writeUInt16LE(16,34);b.write('data',36);b.writeUInt32LE(frames*2,40);return b;};
 assert.equal((await silence.protect(wav())).reason,'ALL_AUDIO_REMOVED');
 await assert.rejects(silence.protect(wav({format:0x55})),/AUDIO_PCM16_REQUIRED/);
 await assert.rejects(silence.protect(wav({rate:96000})),/AUDIO_LIMIT/);
 await assert.rejects(new AudioPrivacy({mode:'pii-intervals'}).protect(wav()),/ASR_REQUIRED/);
});

test('document scope: input over 8 MiB and format-preserving output for a non-Office/PDF kind are refused without parsing',async()=>{
 const worker=resolve('parsers/worker.py');
 const cdr=new DocumentCdr({python:realpathSync(pythonExecutable()),worker,workerSha256:bytesDigest(readFileSync(worker)),protector:new PrivacyEngine()});
 const r=await cdr.protect(Buffer.from('plain'),'txt',{output:'office'});
 assert.deepEqual([r.decision,r.output,r.reason],['block',null,'FORMAT_PRESERVING_UNSUPPORTED']);
 const large=await cdr.protect(Buffer.alloc(8388609,0x61),'txt');
 assert.deepEqual([large.decision,large.output,large.reason],['block',null,'PARSER_INPUT']);
});

test('document scope: legacy Office, media and CAD files are refused by the sandboxed parser',{skip:parserPrerequisiteSkip()},async()=>{
 const worker=resolve('parsers/worker.py');
 const cdr=new DocumentCdr({python:realpathSync(pythonExecutable()),worker,workerSha256:bytesDigest(readFileSync(worker)),protector:new PrivacyEngine({profile:'strict'})});
 const ole=Buffer.concat([Buffer.from([0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1]),Buffer.alloc(504)]);
 for(const [kind,bytes] of [['doc',ole],['xls',ole],['ppt',ole],['mov',Buffer.from('....ftypqt')],['wav',Buffer.from('RIFF')],['dwg',Buffer.from('AC1032')],['png',Buffer.from('\x89PNG')],['jpeg',Buffer.from('\xff\xd8\xff')]]){
  const r=await cdr.protect(bytes,kind);
  assert.deepEqual([r.decision,r.output,r.reason],['block',null,'UNSUPPORTED_DOCUMENT'],kind);
 }
 // A scanned (image-only) PDF needs OCR, and Office files with embedded media need a separate scanner: both refused.
 const python=realpathSync(pythonExecutable()),make=code=>execFileSync(python,['-c',code]);
 const scannedPdf=make("import io,sys\nfrom pypdf import PdfWriter\nw=PdfWriter();w.add_blank_page(width=100,height=100);b=io.BytesIO();w.write(b);sys.stdout.buffer.write(b.getvalue())");
 const mediaDocx=make("import io,sys,zipfile\nb=io.BytesIO();z=zipfile.ZipFile(b,'w')\nz.writestr('[Content_Types].xml','<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>')\nz.writestr('word/document.xml','<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>')\nz.writestr('word/media/image1.png',b'png')\nz.close();sys.stdout.buffer.write(b.getvalue())");
 for(const [kind,bytes,reason] of [['pdf',scannedPdf,'PDF_OCR_REQUIRED'],['docx',mediaDocx,'OFFICE_EMBEDDED_CONTENT']]){
  const r=await cdr.protect(bytes,kind);
  assert.deepEqual([r.decision,r.output,r.reason],['block',null,reason],kind);
 }
 // Kinds outside the parser's identifier shape (mp3, mp4, m4a) never reach it.
 for(const kind of ['mp3','mp4','m4a']){
  const r=await cdr.protect(Buffer.from('media'),kind);
  assert.deepEqual([r.decision,r.output,r.reason],['block',null,'PARSER_INPUT'],kind);
 }
});

test('remote source scope: SharePoint, Drive, S3 and URL roots have no connector and are refused with SOURCE_ROOT',()=>{
 for(const root of ['https://tenant.sharepoint.com/sites/finance','s3://bucket/prefix','gdrive://folder/abc','smb://share/docs','/nonexistent/aidr-remote-mount',''])
  assert.throws(()=>readAuthorizedDirectory({root,groups:['staff'],classification:'internal'}),/SOURCE_ROOT/,root);
});
