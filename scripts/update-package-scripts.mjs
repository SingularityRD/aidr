import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const packageJsonPath = join(__dirname, '..', 'package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));

// Add new scripts
packageJson.scripts = {
  ...packageJson.scripts,
  "bundle-analyze": "pnpm -r run bundle-analyze",
  "bundlesize": "bundlesize",
  "lint:versions": "syncpack list-mismatches",
  "fix:versions": "syncpack fix-mismatches",
  "test:perf": "vitest run --reporter=verbose --reporter=json --outputFile=coverage/test-results.json"
};

// Add new dev dependencies
packageJson.devDependencies = {
  ...packageJson.devDependencies,
  "bundlesize": "^0.18.2",
  "syncpack": "^13.0.0"
};

writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, '\t') + '\n');
console.log('Updated package.json with new scripts and dependencies');
