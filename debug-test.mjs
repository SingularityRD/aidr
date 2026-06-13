import { mkdir, mkdtemp, writeFile, rm, readdir } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { parse as parseYaml } from 'yaml';
import { loadThreats } from './packages/core/src/threat-loader.js';
import { getFileContent } from './packages/core/src/file-utils.js';

const dir = await mkdtemp(join(tmpdir(), 'aidr-debug-'));
const threatsDir = join(dir, 'threats');
await mkdir(threatsDir);

const yaml = `
- id: CLT-TEST-001
  category: command
  severity: critical
  confidence: 0.95
  action: block
  pattern: "rm -rf /"
  match_on: [command]
  title: "Destructive filesystem deletion"

- id: CLT-TEST-002
  category: network_egress
  severity: high
  confidence: 0.90
  action: require_approval
  pattern: "malicious\\.test"
  match_on: [url]
  title: "Known malicious domain"

- id: CLT-TEST-003
  category: command
  severity: high
  confidence: 0.85
  action: block
  pattern: "curl.*\\|.*sh"
  match_on: [command]
  title: "Pipe to shell attack"
`;

await writeFile(join(threatsDir, 'test-threats.yaml'), yaml);

// Debug
const files = await readdir(threatsDir);
console.log('Files:', files);

const content = await getFileContent(join(threatsDir, 'test-threats.yaml'));
console.log('Content:', JSON.stringify(content.slice(0, 200)));

const parsed = parseYaml(content);
console.log('Parsed:', Array.isArray(parsed), parsed?.length);

const loaded = await loadThreats(threatsDir);
console.log('Loaded:', loaded.length);

await rm(dir, { recursive: true, force: true });
