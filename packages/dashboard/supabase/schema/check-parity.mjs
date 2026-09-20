#!/usr/bin/env node
/** Deterministic dashboard-schema parity and SQL sanity check. */
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const schemaDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(schemaDir, '../../../..');
const migrationsDir = join(repoRoot, 'supabase', 'migrations');
const [canonicalNames, dashboardNames] = await Promise.all([
  readdir(migrationsDir).then((names) => names.filter((name) => name.endsWith('.sql')).sort()),
  readdir(schemaDir).then((names) => names.filter((name) => name.endsWith('.sql')).sort()),
]);
if (JSON.stringify(canonicalNames) !== JSON.stringify(dashboardNames)) {
  throw new Error(`migration filename parity failed\ncanonical: ${canonicalNames}\ndashboard: ${dashboardNames}`);
}
for (const name of canonicalNames) {
  const [canonical, dashboard] = await Promise.all([
    readFile(join(migrationsDir, name), 'utf8'),
    readFile(join(schemaDir, name), 'utf8'),
  ]);
  if (canonical !== dashboard) throw new Error(`migration content parity failed: ${name}`);
  // Catch the common copy/order corruption without attempting a live database.
  if ((dashboard.match(/\$\$/g) ?? []).length % 2 !== 0) throw new Error(`unbalanced dollar quote: ${name}`);
  if ((dashboard.match(/\(/g) ?? []).length !== (dashboard.match(/\)/g) ?? []).length) {
    throw new Error(`unbalanced parentheses: ${name}`);
  }
}
console.log(`schema parity and SQL sanity passed (${canonicalNames.length} migrations)`);
