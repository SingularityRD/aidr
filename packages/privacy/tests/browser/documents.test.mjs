import test from'node:test';import assert from'node:assert/strict';
import{parseDelimited,serializeDelimited,protectDocument}from'../../dist/browser/documents.js';import{BrowserPrivacyEngine}from'../../dist/browser/engine.js';
const engine=new BrowserPrivacyEngine({actions:{SECRET:'block',PRIVATE_KEY:'block',INTERNAL:'block'}});
for(const [name,input,kind]of [
 ['tr text','Ad Soyad: Ahmet Yılmaz; Eposta: ahmet@example.com','text'],
 ['json object','{"name":"Jane Doe","email":"jane@example.com"}','json'],
 ['csv labels','name,email,phone\r\nJane Doe,jane@example.com,5551234\r\n','csv'],
 ['tr csv labels','adsoyad,eposta,tckn\nAhmet Yılmaz,ahmet@example.com,10000000147\n','csv'],
 ['quoted name','"name","note"\r\n"Jane, Doe","a@example.com"\r\n','csv'],
 ['multiline cell','name,address\nJane Doe,"one street\ntwo street"\n','csv'],
 ['tab headers','isim\ttelefon\nAyşe Demir\t5551234','tsv'],
 ['bom','\ufeffname,email\nJane Doe,jane@example.com','csv'],
 ])test(`document ${name}`,async()=>{const r=await protectDocument(input,kind,engine);assert.equal(r.decision,'redact');assert.ok(r.output);for(const pii of ['Jane Doe','Ahmet Yılmaz','jane@example.com','ahmet@example.com','5551234','10000000147','Ayşe Demir'])assert.ok(!r.output.includes(pii));});
for(const [name,input,kind]of [
 ['password','{"password":"sensitive"}','json'],['duplicate JSON','{"a":1,"a":2}','json'],['binary','abc\0def','text'],
 ['malformed quote','name,note\n"Jane,x','csv'],['bad postquote','name,note\n"Jane"x,z','csv'],['ragged','name,note\na,b,c','csv'],
 ['duplicate headers','name,NAME\na,b','csv'],['empty header',',note\na,b','csv'],['prototype','__proto__,note\na,b','csv'],
 ['sensitive header','jane@example.com,note\na,b','csv'],['embedded quote','name,note\na"b,c','csv'],
 ...['=HYPERLINK("x")','+cmd','-1','@SUM(A1)','\t =1'].map((x,i)=>['formula'+i,`name,note\na,"${x.replaceAll('"','""')}"`,'csv']),
 ])test(`document denial ${name}`,async()=>{const r=await protectDocument(input,kind,engine);assert.equal(r.output,null);assert.equal(r.filename,null);});
for(const delimiter of [',','\t'])test(`CSV roundtrip ${delimiter}`,()=>{const rows=[['name','note'],['a,b','two\nlines'],['quoted "cell"',''],['\r\n','üğıİ']];assert.deepEqual(parseDelimited(serializeDelimited(rows,delimiter),delimiter),rows);});
test('document preserves clean string types',async()=>{const r=await protectDocument('code,value\n0012,3.5','csv',engine);assert.equal(r.decision,'allow');assert.deepEqual(parseDelimited(r.output,','),[['code','value'],['0012','3.5']]);});
test('document size bound',async()=>assert.equal((await protectDocument('ü'.repeat(100),'text',engine,100)).output,null));
test('document refuses unapproved kind',async()=>assert.equal((await protectDocument('test','pdf',engine)).output,null));
test('column and cell count limits',()=>{assert.throws(()=>parseDelimited(Array(130).fill('x').join(','),','));assert.throws(()=>parseDelimited('a,b\n1,2',',',3));});
