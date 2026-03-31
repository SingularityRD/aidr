/**
 * Generate a signed-artifact manifest for a connector/bundle directory.
 *
 * Usage:
 *   node scripts/generate-artifact-manifest.mjs --dir <artifactDir> --id <artifactId> --version <version> [--key-id <keyId>]
 *     [--watermark-id <id>] [--issued-to <name>] [--channel dev|commercial]
 *     [--build-id <id>] [--git-sha <sha>] [--ci-provider <name>] [--ci-run-id <id>] [--nonce-b64 <b64>]
 *
 * Outputs `aidr-artifact.manifest.json` in the artifact directory.
 */

import { createHash } from "node:crypto";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

const args = parseArgs(process.argv.slice(2));
const dir = path.resolve(args["--dir"] ?? ".");
// Backward-compatible aliases and defaults (keeps release pipelines stable).
const pkg = tryReadLocalPackageJson();
const artifactId = args["--id"] ?? args["--artifact-id"] ?? pkg?.name;
const artifactVersion = args["--version"] ?? pkg?.version;
const keyId = args["--key-id"];
const watermarkId = args["--watermark-id"] ?? process.env.AIDR_WATERMARK_ID;
const issuedTo = args["--issued-to"] ?? process.env.AIDR_WATERMARK_ISSUED_TO;
const channel = args["--channel"] ?? process.env.AIDR_WATERMARK_CHANNEL;
const buildId =
	args["--build-id"] ??
	process.env.AIDR_BUILD_ID ??
	process.env.GITHUB_RUN_ID ??
	process.env.CI_PIPELINE_ID;
const gitSha = args["--git-sha"] ?? process.env.GITHUB_SHA ?? process.env.CI_COMMIT_SHA;
const ciProvider =
	args["--ci-provider"] ??
	(process.env.GITHUB_ACTIONS ? "github_actions" : process.env.CI ? "ci" : undefined);
const ciRunId = args["--ci-run-id"] ?? process.env.GITHUB_RUN_ID ?? process.env.CI_JOB_ID;
const nonceB64 = args["--nonce-b64"] ?? process.env.AIDR_WATERMARK_NONCE_B64;

if (!artifactId || !artifactVersion) {
	console.error("Missing required args: --id <artifactId> --version <version>");
	process.exit(2);
}

const MANIFEST_NAME = "aidr-artifact.manifest.json";
const SIG_NAME = "aidr-artifact.manifest.sig";

const files = await listFilesRecursive(dir);
const relFiles = files
	.map((abs) => path.relative(dir, abs).replace(/\\/g, "/"))
	.filter((p) => p && !p.startsWith("../"));

const included = relFiles
	.filter((p) => p !== MANIFEST_NAME && p !== SIG_NAME)
	.filter((p) => !p.endsWith(".map"));

included.sort((a, b) => a.localeCompare(b));

const entries = [];
for (const rel of included) {
	const abs = path.join(dir, rel);
	const buf = await readFile(abs);
	const sha256 = createHash("sha256").update(buf).digest("hex");
	entries.push({ path: rel, sha256 });
}

const manifest = {
	schema_version: 1,
	artifact_id: artifactId,
	artifact_version: artifactVersion,
	created_at: new Date().toISOString(),
	...(keyId ? { key_id: keyId } : {}),
	files: entries,
	...(watermarkId
		? {
				lineage: {
					watermark_id: watermarkId,
					...(issuedTo ? { issued_to: issuedTo } : {}),
					...(channel ? { channel } : {}),
					nonce_b64: nonceB64 ?? randomBytes(16).toString("base64"),
					...(buildId ? { build_id: buildId } : {}),
					...(gitSha ? { git_sha: gitSha } : {}),
					...(ciProvider ? { ci_provider: ciProvider } : {}),
					...(ciRunId ? { ci_run_id: ciRunId } : {}),
				},
			}
		: {}),
};

await writeFile(path.join(dir, MANIFEST_NAME), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
console.log(`Wrote ${path.join(dir, MANIFEST_NAME)}`);

async function listFilesRecursive(root) {
	const out = [];
	const stack = [root];
	while (stack.length) {
		const current = stack.pop();
		let st;
		try {
			st = await stat(current);
		} catch {
			continue;
		}
		if (st.isDirectory()) {
			const ents = await readdir(current, { withFileTypes: true });
			for (const e of ents) {
				const full = path.join(current, e.name);
				if (e.isDirectory()) stack.push(full);
				else if (e.isFile()) out.push(full);
			}
			continue;
		}
	}
	return out;
}

function parseArgs(argv) {
	const m = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (!a.startsWith("--")) continue;
		const v = argv[i + 1];
		if (v && !v.startsWith("--")) {
			m[a] = v;
			i++;
		} else {
			m[a] = "true";
		}
	}
	return m;
}

function tryReadLocalPackageJson() {
	try {
		// This script is typically invoked from a package directory during build.
		// Pulling name/version from package.json avoids cross-platform shell env quirks.
		return JSON.parse(readFileSync("package.json", "utf8"));
	} catch {
		return null;
	}
}
