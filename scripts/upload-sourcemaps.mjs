#!/usr/bin/env node
/**
 * Singularity AIDR Source Map Upload Script
 * Uploads source maps to Sentry for error tracking
 */

import { createReadStream } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { createInterface } from "node:readline";

const SENTRY_AUTH_TOKEN = process.env.SENTRY_AUTH_TOKEN;
const SENTRY_ORG = process.env.SENTRY_ORG || "singularityrd";
const SENTRY_PROJECT = process.env.SENTRY_PROJECT || "aidr";
const SENTRY_URL = process.env.SENTRY_URL || "https://sentry.io";
const RELEASE = process.env.SENTRY_RELEASE || process.env.npm_package_version || "dev";

const PACKAGES = ["core", "claude-code", "openclaw", "opencode", "extension"];

interface SourceMapFile {
  path: string;
  relativePath: string;
  jsPath?: string;
}

function log(message: string): void {
  console.log(`[upload-sourcemaps] ${message}`);
}

function error(message: string): void {
  console.error(`[upload-sourcemaps] ERROR: ${message}`);
}

async function findSourceMaps(packageDir: string): Promise<SourceMapFile[]> {
  const sourceMaps: SourceMapFile[] = [];
  const distDir = join(packageDir, "dist");

  try {
    await stat(distDir);
  } catch {
    return sourceMaps;
  }

  async function scanDir(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        await scanDir(fullPath);
      } else if (entry.name.endsWith(".map")) {
        const relativePath = relative(distDir, fullPath);
        // Look for corresponding JS file
        const jsPath = fullPath.slice(0, -4); // Remove .map
        sourceMaps.push({ path: fullPath, relativePath, jsPath });
      }
    }
  }

  await scanDir(distDir);
  return sourceMaps;
}

async function validateSourceMap(mapPath: string): Promise<boolean> {
  try {
    const content = await readFile(mapPath, "utf-8");
    const map = JSON.parse(content);
    return !!(map.version && map.sources && map.mappings);
  } catch {
    return false;
  }
}

async function uploadSourceMap(sourceMap: SourceMapFile, packageName: string): Promise<boolean> {
  if (!SENTRY_AUTH_TOKEN) {
    error("SENTRY_AUTH_TOKEN not set");
    return false;
  }

  const url = `${SENTRY_URL}/api/0/projects/${SENTRY_ORG}/${SENTRY_PROJECT}/releases/${RELEASE}/files/`;

  // Read source map content
  const content = await readFile(sourceMap.path, "utf-8");

  // Build form data manually
  const boundary = `----FormBoundary${Math.random().toString(36).slice(2)}`;
  const lines: string[] = [];

  // Add file field
  lines.push(`--${boundary}`);
  lines.push(`Content-Disposition: form-data; name="file"; filename="${sourceMap.relativePath}"`);
  lines.push("Content-Type: application/json");
  lines.push("");
  lines.push(content);

  // Add name field (artifact name in Sentry)
  lines.push(`--${boundary}`);
  lines.push(`Content-Disposition: form-data; name="name"`);
  lines.push("");
  lines.push(`~/${packageName}/${sourceMap.relativePath}`);

  // Add dist field
  lines.push(`--${boundary}`);
  lines.push(`Content-Disposition: form-data; name="dist"`);
  lines.push("");
  lines.push(RELEASE);

  lines.push(`--${boundary}--`);

  const body = lines.join("\r\n");

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${SENTRY_AUTH_TOKEN}`,
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
        "Accept": "application/json",
      },
      body,
    });

    if (response.ok) {
      log(`✓ Uploaded ${sourceMap.relativePath}`);
      return true;
    } else {
      const text = await response.text();
      error(`Failed to upload ${sourceMap.relativePath}: ${response.status} ${text}`);
      return false;
    }
  } catch (e) {
    error(`Network error uploading ${sourceMap.relativePath}: ${e}`);
    return false;
  }
}

async function createRelease(): Promise<boolean> {
  if (!SENTRY_AUTH_TOKEN) {
    error("SENTRY_AUTH_TOKEN not set");
    return false;
  }

  const url = `${SENTRY_URL}/api/0/projects/${SENTRY_ORG}/${SENTRY_PROJECT}/releases/`;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${SENTRY_AUTH_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        version: RELEASE,
        projects: [SENTRY_PROJECT],
      }),
    });

    if (response.ok || response.status === 409) { // 409 = release already exists
      log(`Release ${RELEASE} ready`);
      return true;
    } else {
      error(`Failed to create release: ${await response.text()}`);
      return false;
    }
  } catch (e) {
    error(`Network error creating release: ${e}`);
    return false;
  }
}

async function main(): Promise<void> {
  log(`Starting source map upload for release: ${RELEASE}`);

  if (!SENTRY_AUTH_TOKEN) {
    error("SENTRY_AUTH_TOKEN environment variable is required");
    process.exit(1);
  }

  // Create release
  const releaseOk = await createRelease();
  if (!releaseOk) {
    process.exit(1);
  }

  const rootDir = resolve(import.meta.dirname, "..");
  let totalUploaded = 0;
  let totalFailed = 0;

  for (const pkg of PACKAGES) {
    const packageDir = join(rootDir, "packages", pkg);
    const sourceMaps = await findSourceMaps(packageDir);

    if (sourceMaps.length === 0) {
      log(`No source maps found in ${pkg}`);
      continue;
    }

    log(`Found ${sourceMaps.length} source map(s) in ${pkg}`);

    for (const sourceMap of sourceMaps) {
      const valid = await validateSourceMap(sourceMap.path);
      if (!valid) {
        error(`Invalid source map: ${sourceMap.relativePath}`);
        totalFailed++;
        continue;
      }

      const uploaded = await uploadSourceMap(sourceMap, pkg);
      if (uploaded) {
        totalUploaded++;
      } else {
        totalFailed++;
      }
    }
  }

  log(`Upload complete: ${totalUploaded} succeeded, ${totalFailed} failed`);
  process.exit(totalFailed > 0 ? 1 : 0);
}

main().catch((e) => {
  error(String(e));
  process.exit(1);
});
