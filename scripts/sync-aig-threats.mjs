#!/usr/bin/env node
/**
 * AIG Threat Intel Sync Pipeline
 *
 * Reads the latest AIG vulnerability data from vendor/ai-infra-guard/data/
 * and recompiles the threat indices for AIDR edge agents.
 *
 * Can be run:
 *   - Manually:    node scripts/sync-aig-threats.mjs
 *   - On schedule: via cron / systemd timer / GitHub Actions
 *   - On postinstall: via package.json scripts
 *
 * Flags:
 *   --force   Force recompile and overwrite even if hashes match
 *   --watch   Watch AIG data directory for changes and recompile on-the-fly
 *   --quiet   Suppress info-level logging (warnings/errors still shown)
 *   --source-mode=pinned|worktree  Compile the pinned Git tree (default) or
 *                                  deliberately compile and verify the worktree
 *
 * Exit codes:
 *   0  Success (no changes or changes applied)
 *   1  Failure (compilation error, disk error, etc.)
 */

import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  watch,
  readdirSync,
  statSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { pinnedSourceTreeDigest, readPinnedYamlFiles, readWorktreeYamlFiles } from "./lib/aig-source-tree.mjs";

// ─── Paths ───────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const COMPILE_SCRIPT = join(__dirname, "compile-aig-data.mjs");
const AIG_DIR = join(ROOT, "vendor", "ai-infra-guard");
const AIG_DATA_DIR = join(AIG_DIR, "data");
const GENERATED_DIR = join(ROOT, "packages", "core", "src", "generated");

export const GENERATED_FILES = [
  "aig-cve-index.json",
  "aig-fingerprints.json",
  "aig-mcp-categories.json",
  "aig-data-manifest.json",
];

const SIGNING_ENVIRONMENT = new Set([
  "AIG_SIGNING_PRIVATE_KEY",
  "AIG_SIGNING_PRIVATE_KEY_PATH",
  "AIG_SIGNING_KEY_ID",
]);

// ─── Logging ──────────────────────────────────────────────────────────────────

const QUIET = process.argv.includes("--quiet");

function info(...args) {
  if (!QUIET) console.log("[sync]", ...args);
}

function warn(...args) {
  console.warn("[sync] ⚠️ ", ...args);
}

function error(...args) {
  console.error("[sync] ❌ ", ...args);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Compute SHA-256 hex digest of a file (empty string if missing). */
function fileHash(filePath) {
  try {
    return createHash("sha256").update(readFileSync(filePath)).digest("hex");
  } catch {
    return "";
  }
}

/** Read and parse a JSON file (returns null on failure). */
function readJson(filePath) {
  try {
    return JSON.parse(readFileSync(filePath, "utf-8"));
  } catch {
    return null;
  }
}

export function parseSourceMode(args) {
  const values = args
    .filter((arg) => arg.startsWith("--source-mode="))
    .map((arg) => arg.slice("--source-mode=".length));
  if (values.length > 1 || (values[0] && !new Set(["pinned", "worktree"]).has(values[0]))) {
    throw new Error("--source-mode must be exactly one of: pinned, worktree");
  }
  return values[0] ?? "pinned";
}

export function compilationEnvironment(environment = process.env) {
  return Object.fromEntries(Object.entries(environment).filter(([name]) =>
    !SIGNING_ENVIRONMENT.has(name.toUpperCase())));
}

export function validateSourceManifest(manifest, { sourceMode, aigRoot = AIG_DIR, cwd = ROOT } = {}) {
  if (!new Set(["pinned", "worktree"]).has(sourceMode)) throw new Error(`Invalid source mode: ${sourceMode}`);
  const vendored = resolve(aigRoot) === resolve(AIG_DIR) && !existsSync(join(aigRoot, ".git"));
  const release = vendored ? readJson(join(cwd, "config", "aig-release-sequence.json"))?.releases?.at(-1) : null;
  const commit = vendored ? release?.source_commit : execFileSync("git", ["-C", aigRoot, "rev-parse", "HEAD"], {
    cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
  }).trim();
  if (vendored) {
    const tree = execFileSync("git", ["-C", cwd, "rev-parse", "HEAD:vendor/ai-infra-guard"], {
      cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (tree !== release?.source_tree_oid || manifest?.source?.git_tree_oid !== tree) {
      throw new Error("compiled manifest source Git tree mismatch");
    }
  }
  const files = sourceMode === "worktree"
    ? readWorktreeYamlFiles({ aigRoot })
    : readPinnedYamlFiles({ aigRoot, cwd, ref: vendored ? "HEAD" : commit });
  const treeSha256 = pinnedSourceTreeDigest(files);
  if (manifest?.source?.commit !== commit) {
    throw new Error(`compiled manifest source commit mismatch: ${manifest?.source?.commit ?? "missing"} (expected ${commit})`);
  }
  if (manifest?.source?.tree_sha256 !== treeSha256) {
    throw new Error(`compiled manifest source tree mismatch: ${manifest?.source?.tree_sha256 ?? "missing"} (expected ${treeSha256})`);
  }
  return { commit, treeSha256, fileCount: files.length };
}

/** Format byte size for human readability. */
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** Check if a directory (shallow) contains *.yaml files. */
function hasYamlFiles(dir) {
  if (!existsSync(dir)) return false;

  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isFile() && entry.name.endsWith(".yaml")) return true;
      if (entry.isDirectory() && entry.name !== ".git") {
        try {
          const sub = readdirSync(join(dir, entry.name), { withFileTypes: true });
          for (const subEntry of sub) {
            if (subEntry.isFile() && subEntry.name.endsWith(".yaml")) return true;
          }
        } catch {
          // skip unreadable subdirectories
        }
      }
    }
  } catch {
    // directory unreadable
  }
  return false;
}

/** Diff two index objects and return a human-readable change summary. */
function summarizeChanges(oldData, newData) {
  const changes = [];

  if (!oldData && newData) return ["new file"];
  if (oldData && !newData) return ["deleted"];

  const countKeys = ["cves", "fingerprints", "categories"];
  for (const key of countKeys) {
    if (Array.isArray(oldData?.[key]) && Array.isArray(newData?.[key])) {
      const oldCount = oldData[key].length;
      const newCount = newData[key].length;
      if (oldCount !== newCount) {
        const delta = newCount - oldCount;
        changes.push(`${key}: ${oldCount} → ${newCount} (${delta > 0 ? "+" : ""}${delta})`);
      }
    }
  }

  if (oldData?.generated !== newData?.generated) {
    changes.push(
      `generated: ${oldData?.generated ?? "?"} → ${newData?.generated ?? "?"}`,
    );
  }

  if (oldData?.version !== newData?.version) {
    changes.push(`version: ${oldData?.version} → ${newData?.version}`);
  }

  return changes.length > 0
    ? changes
    : ["content changed (structure may differ)"];
}

// ─── State (captured during pipeline run) ────────────────────────────────────

let oldHashes = new Map();
let newHashes = new Map();

// ─── Core Pipeline ───────────────────────────────────────────────────────────

/**
 * Check if AIG is installed and has data files.
 * Graceful: returns false silently if not found.
 */
function checkAigInstalled() {
  if (!existsSync(AIG_DATA_DIR)) return false;
  return hasYamlFiles(AIG_DATA_DIR);
}

/** Snapshot hashes of all generated files. */
function captureHashes() {
  const hashes = new Map();
  for (const file of GENERATED_FILES) {
    hashes.set(file, fileHash(join(GENERATED_DIR, file)));
  }
  return hashes;
}

/** Snapshot parsed contents of all generated files. */
function readAllGenerated() {
  const contents = new Map();
  for (const file of GENERATED_FILES) {
    contents.set(file, readJson(join(GENERATED_DIR, file)));
  }
  return contents;
}

/** Run compile-aig-data.mjs as a child process. */
function runCompilation(sourceMode) {
  info("Running compile-aig-data.mjs ...");
  const start = performance.now();

  const result = execFileSync(process.execPath, [COMPILE_SCRIPT, `--source-mode=${sourceMode}`], {
    cwd: ROOT,
    // A reviewed worktree may be compiled explicitly, but never inherits signing
    // material merely because the caller's shell contains it.
    env: compilationEnvironment(),
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
    windowsHide: true,
  });

  const lines = result.trim().split("\n").filter(Boolean);
  for (const line of lines) {
    if (!QUIET) console.log(`  ${line}`);
  }

  const source = validateSourceManifest(readJson(join(GENERATED_DIR, "aig-data-manifest.json")), { sourceMode });
  info(`Validated ${sourceMode} source (${source.fileCount} YAML files; ${source.treeSha256.slice(0, 12)}…).`);

  const elapsed = Math.round(performance.now() - start);
  info(`Compilation finished in ${elapsed}ms`);
}

/** Print a structured diff report. */
function reportChanges(oldContents, newContents) {
  console.log("");
  console.log("  ┌─ Sync Report ──────────────────────────────────");

  let anyChange = false;

  for (const file of GENERATED_FILES) {
    const oldData = oldContents.get(file);
    const newData = newContents.get(file);
    const oldHash = oldHashes.get(file) ?? "";
    const newHash = newHashes.get(file) ?? "";

    if (oldHash !== newHash) {
      anyChange = true;
      const changes = summarizeChanges(oldData, newData);
      const oldBytes = oldData
        ? formatBytes(Buffer.byteLength(JSON.stringify(oldData)))
        : "N/A";
      const newBytes = newData
        ? formatBytes(Buffer.byteLength(JSON.stringify(newData)))
        : "N/A";
      console.log(`  │ ${file}`);
      console.log(`  │   size: ${oldBytes} → ${newBytes}`);
      for (const c of changes) {
        console.log(`  │   ● ${c}`);
      }
    } else {
      console.log(`  │ ${file}  (unchanged)`);
    }
  }

  if (!anyChange) {
    console.log("  │  No changes detected.");
  }

  console.log("  └────────────────────────────────────────────────");
  console.log("");
}

/**
 * Run the full sync pipeline.
 * Returns 0 for success, 1 for failure.
 */
function syncPipeline(force, sourceMode) {
  // 1 — Check AIG installation
  if (!checkAigInstalled()) {
    warn("AI-Infra-Guard not found or has no data at:", AIG_DATA_DIR);
    warn("  Restore the committed vendor/ai-infra-guard/ directory from the AIDR checkout.");
    warn("  Existing compiled indices will be used as-is (if any).");
    console.log("");
    info("Sync skipped — no upstream data to compile.");
    return 0;
  }

  // 2 — Snapshot current state
  info("Snapshotting current generated files...");
  oldHashes = captureHashes();
  const oldContents = readAllGenerated();

  // 3 — Compile
  try {
    runCompilation(sourceMode);
  } catch (err) {
    error("Compilation step failed:", err.message);
    if (err.stderr) {
      process.stderr.write(String(err.stderr));
    }
    return 1;
  }

  // 4 — Snapshot new state
  newHashes = captureHashes();
  const newContents = readAllGenerated();

  // 5 — Diff
  const changedFiles = [];
  const unchangedFiles = [];

  for (const file of GENERATED_FILES) {
    if ((oldHashes.get(file) ?? "") !== (newHashes.get(file) ?? "")) {
      changedFiles.push(file);
    } else {
      unchangedFiles.push(file);
    }
  }

  if (changedFiles.length === 0 && !force) {
    console.log("");
    info("✅ All generated files are up-to-date — no changes detected.");
    console.log("");
    return 0;
  }

  if (changedFiles.length > 0) {
    console.log("");
    info("📦 Changes detected in compiled indices:");
    reportChanges(oldContents, newContents);
    info("✅ Sync complete — edge agents will pick up updates on next poll or session start.");
    console.log("");
  } else if (force) {
    console.log("");
    info("🔁 Force recompile complete — files overwritten.");
    reportChanges(oldContents, newContents);
    console.log("");
  }

  return 0;
}

// ─── Watch Mode ──────────────────────────────────────────────────────────────

let watchTimer = null;
const WATCH_DEBOUNCE_MS = 2000;

function startWatch(sourceMode) {
  if (!existsSync(AIG_DATA_DIR)) {
    warn("Cannot start watch: AIG data directory missing:", AIG_DATA_DIR);
    process.exit(1);
  }

  console.log("");
  info("👀 Watching for changes in:", AIG_DATA_DIR);
  info("    Press Ctrl+C to stop.");
  console.log("");

  const debouncedRecompile = () => {
    if (watchTimer) clearTimeout(watchTimer);
    watchTimer = setTimeout(() => {
      console.log("");
      info("📡 Change detected, recompiling...");
      syncPipeline(false, sourceMode);
    }, WATCH_DEBOUNCE_MS);
  };

  let watcher;
  try {
    watcher = watch(AIG_DATA_DIR, { recursive: true }, (_eventType, filename) => {
      if (
        !filename ||
        filename.startsWith(".") ||
        filename.includes("~") ||
        filename.endsWith(".swp") ||
        filename.endsWith(".swx") ||
        filename.endsWith(".tmp")
      ) {
        return;
      }
      debouncedRecompile();
    });
  } catch (err) {
    error("Failed to start file watcher:", err.message);
    process.exit(1);
  }

  const shutdown = () => {
    if (watcher) watcher.close();
    console.log("");
    info("Watch mode terminated.");
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

function main() {
  const force = process.argv.includes("--force");
  const watch = process.argv.includes("--watch");
  let sourceMode;
  try {
    sourceMode = parseSourceMode(process.argv.slice(2));
  } catch (err) {
    error(err.message);
    process.exit(1);
  }
  if (watch && sourceMode !== "worktree") {
    error("--watch requires the deliberate --source-mode=worktree opt-in");
    process.exit(1);
  }

  console.log("");
  info("AIG Threat Intel Sync Pipeline");
  info("─".repeat(40));
  console.log("");

  if (!existsSync(GENERATED_DIR)) {
    info("Creating generated directory:", GENERATED_DIR);
    mkdirSync(GENERATED_DIR, { recursive: true });
  }

  if (watch) {
    const code = syncPipeline(force, sourceMode);
    if (code !== 0) process.exit(code);
    startWatch(sourceMode);
    return; // keep alive
  }

  const code = syncPipeline(force, sourceMode);
  process.exit(code);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
