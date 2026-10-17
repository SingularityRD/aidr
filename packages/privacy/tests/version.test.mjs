import test from 'node:test';import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PrivacyEngine} from '../dist/index.js';
import {BrowserPrivacyEngine} from '../dist/browser/engine.js';
import {ENGINE_VERSION} from '../dist/version.js';

// audit.engineVersion said 0.5.0-rc.1 in the 0.6.0 package: every audit summary named the wrong engine.
const pkg=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8'));
const sample='TC Kimlik: 10000000146, e-posta: test.kullanici@example.com';

test('ENGINE_VERSION is the package version',()=>{assert.equal(ENGINE_VERSION,pkg.version);});
test('the engine audit names the package version',async()=>{
  const r=await new PrivacyEngine().protect(sample);
  assert.equal(r.audit.engineVersion,pkg.version);
});
test('the browser engine audit names the package version',()=>{
  const r=new BrowserPrivacyEngine().protect(sample);
  assert.equal(r.audit.engineVersion,pkg.version);
});
