import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateReleaseManifest } from "../deploy/dashboard/release-manifest.mjs";
import { generateReleaseManifest, inferPlatforms } from "./generate-release-manifest.mjs";

const script = join(dirname(fileURLToPath(import.meta.url)), "generate-release-manifest.mjs");
const BASE_URL = "https://downloads.customer.example/aidr/1.4.0/";

function sha256(content) {
	return createHash("sha256").update(content).digest("hex");
}

function releaseDir(files) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-release-manifest-"));
	for (const [name, content] of Object.entries(files)) {
		mkdirSync(dirname(join(directory, name)), { recursive: true });
		writeFileSync(join(directory, name), content);
	}
	return directory;
}

test("hashes every recognized release file and binds detached signatures", async () => {
	const files = {
		"aidr-claude-plugin-1.4.0.tar.gz": "claude plugin bytes",
		"aidr-claude-plugin-1.4.0.tar.gz.sig": "signature bytes",
		"aidr-cursor.vsix": "cursor vsix",
		"aidr-vscode.vsix": "vscode vsix",
		"singularityrd-aidr-openclaw-1.4.0.tgz": "openclaw",
		"singularityrd-aidr-opencode-1.4.0.tgz": "opencode",
		"singularityrd-aidr-codex-1.4.0.tgz": "codex",
		"bin/aidr-cli-1.4.0-linux-x64": "cli linux",
		"bin/aidr-cli-1.4.0-macos-arm64": "cli mac",
		"aidr-browser-guard-chrome-1.4.0.zip": "chrome",
		"aidr-browser-guard-firefox-1.4.0.xpi": "firefox",
		"singularityrd-aidr-mcp-gateway-1.4.0.tgz": "gateway",
		"aidr-provenance.intoto.json": "{}",
	};
	const directory = releaseDir(files);
	try {
		const { manifest, skipped } = await generateReleaseManifest({
			dir: directory,
			version: "1.4.0",
			baseUrl: BASE_URL.slice(0, -1),
			env: { SOURCE_DATE_EPOCH: "1788000000" },
		});
		assert.deepEqual(skipped, ["aidr-provenance.intoto.json"]);
		assert.equal(manifest.version, "1.4.0");
		assert.equal(manifest.publishedAt, new Date(1788000000 * 1000).toISOString());
		assert.deepEqual(
			manifest.artifacts.map((artifact) => [artifact.id, artifact.platforms.join(",")]),
			[
				["claude-code", "any"],
				["cursor", "any"],
				["vscode", "any"],
				["openclaw", "any"],
				["opencode", "any"],
				["codex", "any"],
				["cli", "linux-x64"],
				["cli", "darwin-arm64"],
				["browser-guard-chrome", "chrome,edge"],
				["browser-guard-firefox", "firefox"],
				["mcp-gateway", "any"],
			],
		);
		const claude = manifest.artifacts[0];
		assert.equal(claude.url, `${BASE_URL}aidr-claude-plugin-1.4.0.tar.gz`);
		assert.equal(claude.sha256, sha256(files["aidr-claude-plugin-1.4.0.tar.gz"]));
		assert.equal(claude.size, Buffer.byteLength(files["aidr-claude-plugin-1.4.0.tar.gz"]));
		assert.equal(claude.signature, `${BASE_URL}aidr-claude-plugin-1.4.0.tar.gz.sig`);
		assert.equal(manifest.artifacts[1].signature, undefined);
		assert.equal(manifest.artifacts[6].url, `${BASE_URL}bin/aidr-cli-1.4.0-linux-x64`);
		assert.deepEqual(validateReleaseManifest(manifest), manifest);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
});

test("the CLI writes a validated manifest and supports explicit artifact mapping", () => {
	const directory = releaseDir({ "custom name.bin": "payload", "notes.txt": "not an artifact" });
	const out = join(directory, "release-manifest.json");
	try {
		const result = spawnSync(
			process.execPath,
			[
				script,
				"--dir",
				directory,
				"--version",
				"2.0.0-rc.1",
				"--base-url",
				BASE_URL,
				"--published-at",
				"2026-09-24T08:00:00Z",
				"--artifact",
				"mcp-gateway=custom name.bin@linux-x64,linux-arm64",
				"--out",
				out,
			],
			{ encoding: "utf8", timeout: 10_000 },
		);
		assert.equal(result.status, 0, result.stderr);
		assert.match(result.stderr, /skipped \(no artifact id matched\): notes\.txt/);
		const manifest = JSON.parse(readFileSync(out, "utf8"));
		assert.deepEqual(manifest, {
			version: "2.0.0-rc.1",
			publishedAt: "2026-09-24T08:00:00Z",
			artifacts: [
				{
					id: "mcp-gateway",
					version: "2.0.0-rc.1",
					url: `${BASE_URL}custom%20name.bin`,
					sha256: sha256("payload"),
					size: 7,
					platforms: ["linux-x64", "linux-arm64"],
				},
			],
		});
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
});

test("fails closed on insecure URLs, mixed versions, symlinks and empty releases", async () => {
	const directory = releaseDir({ "singularityrd-aidr-codex-1.3.9.tgz": "old codex" });
	try {
		await assert.rejects(
			generateReleaseManifest({ dir: directory, version: "1.4.0", baseUrl: "http://downloads.customer.example/" }),
			/must use https/,
		);
		await assert.rejects(
			generateReleaseManifest({ dir: directory, version: "1.4.0", baseUrl: BASE_URL }),
			/names a different version/,
		);
		await assert.rejects(
			generateReleaseManifest({ dir: directory, version: "not-semver", baseUrl: BASE_URL, artifacts: ["codex=missing.tgz"] }),
			/does not exist/,
		);
		symlinkSync(join(directory, "singularityrd-aidr-codex-1.3.9.tgz"), join(directory, "aidr-cursor.vsix"));
		await assert.rejects(generateReleaseManifest({ dir: directory, version: "1.3.9", baseUrl: BASE_URL }), /refusing symlink/);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
	const empty = releaseDir({ "README.txt": "nothing to ship" });
	try {
		const result = spawnSync(process.execPath, [script, "--dir", empty, "--version", "1.0.0", "--base-url", BASE_URL], {
			encoding: "utf8",
			timeout: 10_000,
		});
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /no release artifacts recognized/);
		const unknown = spawnSync(process.execPath, [script, "--dir", empty, "--bogus", "x"], { encoding: "utf8", timeout: 10_000 });
		assert.notEqual(unknown.status, 0);
		assert.match(unknown.stderr, /unknown argument --bogus/);
	} finally {
		rmSync(empty, { recursive: true, force: true });
	}
});

test("infers platforms from release file names", () => {
	assert.deepEqual(inferPlatforms("cli", "aidr-cli-1.0.0-windows-x64.exe"), ["win32-x64"]);
	assert.deepEqual(inferPlatforms("cli", "aidr-cli-1.0.0-darwin-arm64"), ["darwin-arm64"]);
	assert.deepEqual(inferPlatforms("codex", "singularityrd-aidr-codex-1.0.0.tgz"), ["any"]);
	assert.deepEqual(inferPlatforms("browser-guard-firefox", "anything.xpi"), ["firefox"]);
});
