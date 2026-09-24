import fs from 'node:fs';import {bundle} from '../build-extension.mjs';
fs.mkdirSync('reports/browser/test-bundles',{recursive:true});
fs.writeFileSync('reports/browser/test-bundles/content-fixture.js',bundle('tests/extension/dom-entry.ts'));
fs.writeFileSync('reports/browser/test-bundles/native-fixture.js',bundle('tests/extension/native-entry.ts'));
