import test from 'node:test';
import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {scanText,maskText} from '../dist/rules.js';
import {PrivacyEngine} from '../dist/index.js';
import {BrowserPrivacyEngine} from '../dist/browser/engine.js';

// A labelled field (`Ad Soyad:`, `Full name:`) or a contextual name (`Sayın …`) used to run to the end of
// the line, swallowing the next value; mergeFindings then gave the union the higher-priority type, so the
// name was masked as [TC_KIMLIK] / [IBAN] (or, downstream, the combined span failed a shape check).
const spans=text=>scanText(text).findings.map(f=>[f.type,text.slice(f.start,f.end)]);
const IBAN='TR33 0006 1005 1978 6457 8413 26';

for(const [text,expected] of [
  ['Ad Soyad: Ayşe Yılmaz, TCKN 10000000146',[['PERSON','Ayşe Yılmaz'],['TC_KIMLIK','10000000146']]],
  ['Ad Soyad: Ayşe Yılmaz TCKN 10000000146',[['PERSON','Ayşe Yılmaz'],['TC_KIMLIK','10000000146']]],
  ['Adı Soyadı: Ayşe Yılmaz, T.C. Kimlik No 10000000146',[['PERSON','Ayşe Yılmaz'],['TC_KIMLIK','10000000146']]],
  ['AD SOYAD: AYŞE YILMAZ, TCKN: 10000000146',[['PERSON','AYŞE YILMAZ'],['TC_KIMLIK','10000000146']]],
  [`Full name: Jane Doe IBAN ${IBAN}`,[['PERSON','Jane Doe'],['IBAN',IBAN]]],
  [`Full name: Jane Doe, IBAN: ${IBAN}`,[['PERSON','Jane Doe'],['IBAN',IBAN]]],
  ['Full name: Jane Doe, jane.doe@example.com',[['PERSON','Jane Doe'],['EMAIL','jane.doe@example.com']]],
  ['Full name: Jane Doe (jane.doe@example.com)',[['PERSON','Jane Doe'],['EMAIL','jane.doe@example.com)']]],
  ['Ad Soyad: Ayşe Yılmaz e-posta ayse@example.com',[['PERSON','Ayşe Yılmaz'],['EMAIL','ayse@example.com']]],
  ['Name: Jane Doe +90 532 123 45 67',[['PERSON','Jane Doe'],['PHONE','+90 532 123 45 67']]],
  ['Adı Soyadı: Ayşe Yılmaz Tel 0532 123 45 67',[['PERSON','Ayşe Yılmaz'],['PHONE','0532 123 45 67']]],
  ['İsim: Ayşe Yılmaz, GSM: 0532 123 45 67',[['PERSON','Ayşe Yılmaz'],['PHONE','0532 123 45 67']]],
  [`Sayın Ayşe Yılmaz IBAN ${IBAN}`,[['PERSON','Ayşe Yılmaz'],['IBAN',IBAN]]],
  [`Sayın Ayşe Yılmaz, IBAN: ${IBAN}`,[['PERSON','Ayşe Yılmaz'],['IBAN',IBAN]]],
  ['Sayın Ayşe Yılmaz TCKN 10000000146',[['PERSON','Ayşe Yılmaz'],['TC_KIMLIK','10000000146']]],
  ['My name is Jane Doe jane@example.com',[['PERSON','Jane Doe'],['EMAIL','jane@example.com']]],
  ['Full name: Jane Doe AKIAIOSFODNN7EXAMPLE',[['PERSON','Jane Doe'],['SECRET','AKIAIOSFODNN7EXAMPLE']]],
  ['Full name: Jane Doe password=hunter2hunter2',[['PERSON','Jane Doe'],['SECRET','hunter2hunter2']]],
  // Another field type ends before a value introduced by its own label.
  [`Tel: 0532 123 45 67 IBAN ${IBAN}`,[['PHONE','0532 123 45 67'],['IBAN',IBAN]]],
  ['E-posta: ayse@example.com TCKN 10000000146',[['EMAIL','ayse@example.com'],['TC_KIMLIK','10000000146']]],
  ['Doğum tarihi: 01.01.1990 TCKN 10000000146',[['DATE_OF_BIRTH','01.01.1990'],['TC_KIMLIK','10000000146']]],
  // A field holding only the next value's label is dropped, not reported empty.
  ['Name: TCKN 10000000146',[['TC_KIMLIK','10000000146']]],
])test(`field ends before the next validated value: ${text}`,()=>assert.deepEqual(spans(text),expected));

test('masked output keeps the name and the identifier apart (TR and EN)',async()=>{
  const engine=new PrivacyEngine({profile:'balanced'});
  try{
    assert.equal((await engine.protect('Ad Soyad: Ayşe Yılmaz, TCKN 10000000146')).output,'Ad Soyad: [PERSON], TCKN [TC_KIMLIK]');
    assert.equal((await engine.protect(`Full name: Jane Doe IBAN ${IBAN}`)).output,'Full name: [PERSON] IBAN [IBAN]');
  }finally{engine.dispose();}
  const browser=new BrowserPrivacyEngine({maxInputBytes:65536});
  assert.equal(browser.protect(`Sayın Ayşe Yılmaz IBAN ${IBAN}`).output,'Sayın [PERSON] IBAN [IBAN]');
});

test('a value of a type that is not reported does not end the field, so it stays covered',()=>{
  const text='Ad Soyad: Ayşe Yılmaz, TCKN 10000000146 teşekkürler';
  const r=scanText(text,{enabled:['PERSON']});
  assert.deepEqual(r.findings.map(f=>[f.type,text.slice(f.start,f.end)]),[['PERSON','Ayşe Yılmaz, TCKN 10000000146 teşekkürler']]);
});

test('a PERSON field is not cut at a digit run that is not a validated value',()=>{
  assert.deepEqual(spans('Ad Soyad: Ayşe Yılmaz 12345 Ankara'),[['PERSON','Ayşe Yılmaz 12345 Ankara']]);
});

test('ADDRESS stays conservative: only a labelled value splits it',()=>{
  // An unlabelled number inside an address line may be part of the address: nothing is narrowed.
  assert.deepEqual(spans('Adres: Atatürk Mah. No 5 Ankara 0532 123 45 67'),[['ADDRESS','Atatürk Mah. No 5 Ankara 0532 123 45 67']]);
  assert.deepEqual(spans('Adres: Atatürk Mah. 5 Ankara Tel 0532 123 45 67'),[['ADDRESS','Atatürk Mah. 5 Ankara'],['PHONE','0532 123 45 67']]);
});

test('nothing that was masked is exposed: the rest of the line stays covered by the labelled value',()=>{
  const text=`Tel: 0532 123 45 67 IBAN ${IBAN} (Ziraat, Ayşe Yılmaz)`;
  assert.deepEqual(spans(text),[['PHONE','0532 123 45 67'],['IBAN',`${IBAN} (Ziraat, Ayşe Yılmaz)`]]);
  assert.equal(maskText(text,scanText(text).findings),'Tel: [PHONE] IBAN [IBAN]');
});

test('an identifier field is not split at a nested checksum match of another type',()=>{
  // The account number is Luhn-valid (a card-shaped digit run) but has no card label: one BANK_ACCOUNT field.
  const text='Hesap no: 4111 1111 1111 1111 şube 12';
  const found=scanText(text).findings;
  assert.equal(found.length,1);
  assert.equal(text.slice(found[0].start,found[0].end),'4111 1111 1111 1111 şube 12');
});

test('SECRET spans are never split',()=>{
  const text='api_key="Ayşe Yılmaz ayse@example.com 10000000146"';
  assert.deepEqual(spans(text),[['SECRET','Ayşe Yılmaz ayse@example.com 10000000146']]);
});

test('a detector that aborts still reports the narrowed spans found before it',()=>{
  const text="Ad Soyad: Ayşe Yılmaz, TCKN 10000000146\npassword='unterminated";
  const r=scanText(text);
  assert.equal(r.incomplete,true);
  assert.deepEqual(r.reasons,['INCOMPLETE_SECRET']);
  const found=r.findings.map(f=>[f.type,text.slice(f.start,f.end)]);
  assert.deepEqual(found.slice(0,2),[['PERSON','Ayşe Yılmaz'],['TC_KIMLIK','10000000146']]);
});

test('narrowing stays linear on one long line of labelled values',()=>{
  const text='Ad Soyad: Ayşe Yılmaz '+`TCKN 10000000146 IBAN ${IBAN} Tel 0532 123 45 67 `.repeat(3000);
  scanText(text);
  const times=[];for(let i=0;i<3;i++){const t=performance.now();scanText(text);times.push(performance.now()-t);}
  assert.ok(Math.min(...times)<1500,`best of 3 took ${Math.min(...times)}ms for ${text.length} chars`);
  const r=scanText(text);
  assert.equal(r.findings[0].type,'PERSON');
  assert.equal(text.slice(r.findings[0].start,r.findings[0].end),'Ayşe Yılmaz');
});
