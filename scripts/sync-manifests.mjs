#!/usr/bin/env node

/**
 * Syncs versions from package.json files (already bumped by Changesets)
 * into non-standard manifest files that Changesets doesn't know about.
 *
 *   node scripts/sync-manifests.mjs           write every drifted manifest
 *   node scripts/sync-manifests.mjs --check   exit 1 if any manifest drifted
 *
 * `pnpm run version` runs the write mode right after `changeset version`; the
 * check mode is a gate (`pnpm verify:manifests`) so a hand-edited or missed
 * manifest cannot ship a release whose pieces disagree on their version.
 *
 * Helm chart policy (deploy/helm/aidr/Chart.yaml): `appVersion` is the
 * dashboard package version, which is also the default tag of every first-party
 * image the chart deploys (values.yaml `tag: ""`). Whenever `appVersion` moves,
 * the chart `version` is bumped too, because the rendered chart changed: a
 * patch release of the product bumps the chart patch, anything larger bumps the
 * chart minor. Chart majors are reserved for breaking values changes and are
 * made by hand.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_ROOT = resolve(import.meta.dirname, "..");
const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/u;

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf-8"));
}

function jsonText(json) {
  return `${JSON.stringify(json, null, 2)}\n`;
}

function parseSemver(version, label) {
  const match = SEMVER.exec(String(version));
  if (!match) throw new Error(`${label}: "${version}" is not a plain MAJOR.MINOR.PATCH version`);
  return match.slice(1).map(Number);
}

/** Next chart version for an appVersion move from `previousApp` to `nextApp`. */
export function nextChartVersion(chartVersion, previousApp, nextApp) {
  const [major, minor, patch] = parseSemver(chartVersion, "Chart.yaml version");
  const [fromMajor, fromMinor] = parseSemver(previousApp, "Chart.yaml appVersion");
  const [toMajor, toMinor] = parseSemver(nextApp, "dashboard package version");
  if (fromMajor === toMajor && fromMinor === toMinor) return `${major}.${minor}.${patch + 1}`;
  return `${major}.${minor + 1}.0`;
}

const SCALAR_LINE = (key) => new RegExp(`^${key}:[ \\t]*"?([^"\\n#]*?)"?[ \\t]*$`, "mu");

function readChartScalar(text, key) {
  const match = SCALAR_LINE(key).exec(text);
  if (!match) throw new Error(`Chart.yaml has no top-level ${key}`);
  return match[1].trim();
}

/** Rewrite only the `version:` and `appVersion:` lines so comments and layout survive. */
export function syncChartText(text, appVersion) {
  const previousApp = readChartScalar(text, "appVersion");
  if (previousApp === appVersion) return { text, changed: false, previous: previousApp };
  const chartVersion = readChartScalar(text, "version");
  const next = nextChartVersion(chartVersion, previousApp, appVersion);
  const updated = text
    .replace(SCALAR_LINE("appVersion"), `appVersion: "${appVersion}"`)
    .replace(SCALAR_LINE("version"), `version: ${next}`);
  return { text: updated, changed: true, previous: previousApp, chartVersion: { from: chartVersion, to: next } };
}

const ENGINE_VERSION_LINE = /^export const ENGINE_VERSION = '([^'\n]*)';$/mu;

/** Rewrite the AIDR Privacy `ENGINE_VERSION` constant (reported as audit.engineVersion). */
export function syncEngineVersionText(text, version) {
  const match = ENGINE_VERSION_LINE.exec(text);
  if (!match) throw new Error("packages/privacy/src/version.ts has no ENGINE_VERSION constant");
  if (match[1] === version) return { text, changed: false, previous: match[1] };
  return {
    text: text.replace(ENGINE_VERSION_LINE, `export const ENGINE_VERSION = '${version}';`),
    changed: true,
    previous: match[1],
  };
}

const jsonSync = (sourcePackage, targetFile, apply) => ({
  source: sourcePackage,
  target: targetFile,
  sync(text, version) {
    const json = JSON.parse(text);
    const previous = json.version;
    apply(version, json);
    const next = jsonText(json);
    // A file whose content is already correct but formatted differently is not drift.
    return { text: next, changed: jsonText(JSON.parse(text)) !== next, previous };
  },
});

export const SYNCS = Object.freeze([
  jsonSync("packages/claude-code/package.json", ".claude-plugin/plugin.json", (version, json) => {
    json.version = version;
  }),
  jsonSync("packages/claude-code/package.json", ".claude-plugin/marketplace.json", (version, json) => {
    json.version = version;
    for (const plugin of json.plugins ?? []) plugin.version = version;
  }),
  jsonSync("packages/openclaw/package.json", "packages/openclaw/openclaw.plugin.json", (version, json) => {
    json.version = version;
  }),
  {
    source: "packages/privacy/package.json",
    target: "packages/privacy/src/version.ts",
    sync: syncEngineVersionText,
  },
  {
    source: "packages/dashboard/package.json",
    target: "deploy/helm/aidr/Chart.yaml",
    sync: syncChartText,
  },
]);

/**
 * @param {{root?: string, check?: boolean, log?: (line: string) => void}} options
 * @returns {{drifted: string[], written: string[]}}
 */
export function syncManifests({ root = DEFAULT_ROOT, check = false, log = console.log } = {}) {
  const drifted = [];
  const written = [];
  for (const { source, target, sync } of SYNCS) {
    const { version } = readJson(resolve(root, source));
    const targetPath = resolve(root, target);
    const result = sync(readFileSync(targetPath, "utf-8"), version);
    if (!result.changed) continue;
    const rel = relative(root, targetPath).replaceAll("\\", "/");
    drifted.push(rel);
    const chart = result.chartVersion ? ` (chart version ${result.chartVersion.from} -> ${result.chartVersion.to})` : "";
    if (check) {
      log(`${rel}: ${result.previous} != ${version} from ${source}${chart}`);
      continue;
    }
    writeFileSync(targetPath, result.text);
    written.push(rel);
    log(`${rel}  ${result.previous} -> ${version}${chart}`);
  }
  return { drifted, written };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes("--check");
  try {
    const { drifted, written } = syncManifests({ check });
    if (check && drifted.length > 0) {
      console.error(`\n${drifted.length} manifest(s) out of sync with their package version; run \`node scripts/sync-manifests.mjs\`.`);
      process.exitCode = 1;
    } else if (drifted.length === 0) {
      console.log("All manifests already in sync.");
    } else {
      console.log(`\nSynced ${written.length} manifest(s).`);
    }
  } catch (error) {
    console.error(`sync-manifests: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
