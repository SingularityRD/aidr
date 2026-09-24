import test from 'node:test';import assert from 'node:assert/strict';
import {validTckn,validLuhn,validIban,validSsn}from '../dist/index.js';
for(const x of ['','00000000000','11111111111','10000000147','A0000000146','01000000146','100000001460'])test(`TCKN reject ${x}`,()=>assert.equal(validTckn(x),false));
for(const x of ['','0000000000000000','1111111111111111','4111111111111112','12345678','41111111111111111111'])test(`Luhn reject ${x}`,()=>assert.equal(validLuhn(x),false));
for(const x of ['TR330006100519786457841326','GB82WEST12345698765432','DE89370400440532013000','NL91ABNA0417164300','FR1420041010050500013M02606'])test(`IBAN validate ${x.slice(0,2)}`,()=>assert.ok(validIban(x)));
for(const x of ['','ZZ89370400440532013000','DE88370400440532013000','DE8937040044053201300','DE893704004405320130000','TR33ABC6100519786457841326'])test(`IBAN reject ${x.slice(0,4)}`,()=>assert.equal(validIban(x),false));
for(const x of ['000-12-1234','666-12-1234','900-12-1234','123-00-1234','123-12-0000','12-345-6789'])test(`SSN reject ${x}`,()=>assert.equal(validSsn(x),false));
test('valid SSN syntax only, no ownership claim',()=>assert.ok(validSsn('123-45-6789')));
