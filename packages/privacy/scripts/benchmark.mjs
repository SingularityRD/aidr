/** Core-only benchmark. No inference, network, server or defense throughput is implied. */
import { PrivacyEngine } from '../dist/index.js';
import { performance } from 'node:perf_hooks';
import os from 'node:os';
import fs from 'node:fs';
const clean = 'The approved release includes documentation and operational tests. ';
const sensitive = 'Contact jane.doe@example.com. TC: 10000000146; Telefon: 0532 123 45 67; ';
function sample(target, mixed) {
  let text = mixed ? sensitive : '';
  while (Buffer.byteLength(text + clean) <= target) text += clean;
  return text + ' '.repeat(Math.max(0, target - Buffer.byteLength(text)));
}
const rows = [];
const baseline = process.memoryUsage().rss;
let peakObserved = baseline;
for (const bytes of [256, 1024, 4096, 16384]) {
  for (const mixed of [false, true]) {
    const engine = new PrivacyEngine({profile: 'strict'});
    const input = sample(bytes, mixed);
    const iterations = bytes <= 4096 ? 300 : 100;
    for (let i = 0; i < 30; i++) await engine.protect(input);
    const times = [], decisions = {};
    let findings = 0;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const at = performance.now();
      const result = await engine.protect(input);
      times.push(performance.now() - at);
      decisions[result.decision] = (decisions[result.decision] ?? 0) + 1;
      findings = result.findings.length;
      peakObserved = Math.max(peakObserved, process.memoryUsage().rss);
    }
    const elapsed = performance.now() - start;
    times.sort((a, b) => a - b);
    const p = fraction => +times[Math.ceil(times.length * fraction) - 1].toFixed(3);
    rows.push({workload: mixed ? 'mixed-pii' : 'clean', bytes: Buffer.byteLength(input),
      iterations, findingsPerRequest: findings, decisions, medianMs: p(.5), p95Ms: p(.95), p99Ms: p(.99),
      requestsPerSecond: +(iterations / elapsed * 1000).toFixed(1),
      mibPerSecond: +(Buffer.byteLength(input) * iterations / elapsed * 1000 / 1048576).toFixed(3)});
    engine.dispose();
  }
}
const adversarial = [];
for (const [name, input] of [
  ['64-KiB clean', sample(65536, false)],
  ['64-KiB long token', 'a'.repeat(65536)],
  ['64-KiB separators', ('a - '.repeat(16384)).slice(0,65536)],
  ['64-KiB marker lookalikes', ('NameX '.repeat(10923)).slice(0,65536)],
  ['oversized request', 'x'.repeat(65537)],
]) {
  const engine = new PrivacyEngine({profile:'strict'});
  const at = performance.now();
  const result = await engine.protect(input);
  adversarial.push({name, bytes:Buffer.byteLength(input), elapsedMs:+(performance.now()-at).toFixed(3),
    decision:result.decision, reasons:result.reasons});
  engine.dispose();
}
const report = {schemaVersion:1, generatedAt:new Date().toISOString(),
  scope:'Single-process, sequential, warmed-up TypeScript rules-only core. No real NER inference, HTTP/TLS, JSON, multi-tenant service load or production SLA.',
  environment:{node:process.version, platform:os.platform(), architecture:os.arch(),
    cpu:os.cpus()[0]?.model, logicalCpusVisible:os.cpus().length},
  memory:{processRssBaselineMiB:+(baseline/1048576).toFixed(2),
    processRssPeakObservedMiB:+(peakObserved/1048576).toFixed(2),
    note:'Total Node process RSS, sampled after requests; not incremental engine memory, not a true continuously sampled peak.'},
  rows, adversarial};
fs.mkdirSync('reports',{recursive:true});
fs.writeFileSync('reports/benchmark.json',JSON.stringify(report,null,2)+'\n');
console.table(rows);
console.log(JSON.stringify(report.memory));
console.table(adversarial);
