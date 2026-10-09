import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { renameWithRetry } from "./lib/atomic-write.mjs";
import { stageWindowsKoffi } from "./stage-windows-koffi.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const installer = join(repository, "scripts", "endpoint-install.mjs");
const packageDir = join(repository, "packages", "claude-code");
const requireFromClaudePackage = createRequire(join(packageDir, "package.json"));
const managedMarker = "Singularity AIDR managed installation";
const customerHook = { type: "command", command: "customer-command", timeout: 9 };
let endpointPackageRoot;
const endpointPackagePromises = new Map();

after(() => {
	if (!endpointPackageRoot) return;
	const temporaryRoot = resolve(tmpdir());
	assert.equal(dirname(endpointPackageRoot), temporaryRoot);
	assert.ok(basename(endpointPackageRoot).startsWith("aidr-endpoint-package-"));
	rmSync(endpointPackageRoot, { recursive: true, force: true });
});

async function buildEndpointPackageFixture(version) {
	const sourceManifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
	const fixtureVersion = version ?? sourceManifest.version;
	if (!endpointPackagePromises.has(fixtureVersion)) {
		const temporaryRoot = resolve(tmpdir());
		endpointPackageRoot ??= mkdtempSync(join(temporaryRoot, "aidr-endpoint-package-"));
		const fixturePackage = join(endpointPackageRoot, `package-${String(fixtureVersion).replace(/[^A-Za-z0-9._-]/g, "_")}`);
		const fixturePromise = (async () => {
			const dist = join(fixturePackage, "dist");
			mkdirSync(dist, { recursive: true });
			const manifest = { ...sourceManifest, version: fixtureVersion };
			writeFileSync(join(fixturePackage, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
			cpSync(join(packageDir, "resources"), join(fixturePackage, "resources"), { recursive: true });

			const { build } = requireFromClaudePackage("esbuild");
			await build({
				absWorkingDir: packageDir,
				entryPoints: {
					"pre-tool-use": "src/pre-tool-use.ts",
					"post-tool-use": "src/post-tool-use.ts",
					"mcp-server": "src/mcp-server.ts",
					"session-start": "src/session-start.ts",
					health: "src/health.ts",
				},
				outdir: dist,
				outExtension: { ".js": ".cjs" },
				bundle: true,
				platform: "node",
				target: "node18",
				format: "cjs",
				external: ["koffi"],
				sourcemap: false,
				legalComments: "none",
				define: { __AIDR_VERSION__: JSON.stringify(manifest.version) },
				alias: { "@singularityrd/aidr-core": join(repository, "packages", "core", "src", "index.ts") },
			});

			if (process.platform === "win32") {
				stageWindowsKoffi(packageDir, { isRelease: true, vendorDir: join(dist, "vendor", "koffi") });
			}
			return fixturePackage;
		})();
		endpointPackagePromises.set(fixtureVersion, fixturePromise);
	}
	return await endpointPackagePromises.get(fixtureVersion);
}

function temporaryHome(context) {
	const temporaryRoot = resolve(tmpdir());
	const home = mkdtempSync(join(temporaryRoot, "aidr-hook-lifecycle-"));
	context.after(() => {
		assert.equal(dirname(home), temporaryRoot);
		assert.ok(basename(home).startsWith("aidr-hook-lifecycle-"));
		rmSync(home, { recursive: true, force: true });
	});
	mkdirSync(join(home, ".claude"), { recursive: true });
	return home;
}

function writeMixedSettings(home) {
	const settingsPath = join(home, ".claude", "settings.json");
	writeFileSync(settingsPath, JSON.stringify({
		hooks: {
			PreToolUse: [{ matcher: "*", customFlag: "keep", hooks: [
				{ type: "command", command: "old-managed-command", statusMessage: managedMarker },
				customerHook,
			] }],
			PostToolUse: [{ hooks: [{ type: "command", command: "old-post-managed", statusMessage: managedMarker }] }],
		},
	}));
	return settingsPath;
}

function assertCustomerHookPreserved(settingsPath, managedExpected) {
	const settings = JSON.parse(readFileSync(settingsPath, "utf8"));
	const preToolUse = settings.hooks.PreToolUse;
	assert.deepEqual(preToolUse[0], { matcher: "*", customFlag: "keep", hooks: [customerHook] });
	assert.equal(preToolUse.length, managedExpected ? 2 : 1);
	if (managedExpected) assert.equal(preToolUse[1].hooks[0].statusMessage, managedMarker);
	else assert.ok(!JSON.stringify(settings).includes(managedMarker));
}

function createSignedCommercialPackage(directory, sourcePackage, options = {}) {
	const signedPackage = join(directory, "signed-package");
	mkdirSync(signedPackage, { recursive: true });
	const packageJson = JSON.parse(readFileSync(join(sourcePackage, "package.json"), "utf8"));
	writeFileSync(join(signedPackage, "package.json"), `${JSON.stringify(packageJson, null, 2)}\n`);
	cpSync(join(sourcePackage, "dist"), join(signedPackage, "dist"), {
		recursive: true,
		filter: (path) => !path.endsWith(".map"),
	});
	cpSync(join(sourcePackage, "resources"), join(signedPackage, "resources"), { recursive: true });

	const { publicKey, privateKey } = options.keys ?? generateKeyPairSync("ed25519");
	const keyFingerprint = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
	function entries(directory, prefix = "") {
		const result = [];
		for (const name of readdirSync(directory).sort()) {
			const absolute = join(directory, name);
			const relative = prefix ? `${prefix}/${name}` : name;
			if (statSync(absolute).isDirectory()) result.push(...entries(absolute, relative));
			else result.push({ path: relative, sha256: createHash("sha256").update(readFileSync(absolute)).digest("hex") });
		}
		return result;
	}
	const dist = join(signedPackage, "dist");
	const distManifest = `${JSON.stringify({
		schema_version: 1,
		artifact_id: "claude-code/dist",
		artifact_version: packageJson.version,
		created_at: "2026-01-01T00:00:00.000Z",
		key_fingerprint: keyFingerprint,
		files: entries(dist),
	}, null, 2)}\n`;
	writeFileSync(join(dist, "aidr-artifact.manifest.json"), distManifest);
	writeFileSync(join(dist, "aidr-artifact.manifest.sig"), `${sign(null, Buffer.from(distManifest), privateKey).toString("base64")}\n`);
	const packageFiles = [
		{ path: "package.json", sha256: createHash("sha256").update(readFileSync(join(signedPackage, "package.json"))).digest("hex") },
		...entries(dist, "dist"),
		...entries(join(signedPackage, "resources"), "resources"),
	].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
	const packageManifest = `${JSON.stringify({
		schema_version: 1,
		artifact_id: "claude-code/package",
		artifact_version: packageJson.version,
		created_at: "2026-01-01T00:00:00.000Z",
		key_fingerprint: keyFingerprint,
		files: packageFiles,
	}, null, 2)}\n`;
	writeFileSync(join(signedPackage, "aidr-artifact.manifest.json"), packageManifest);
	writeFileSync(join(signedPackage, "aidr-artifact.manifest.sig"), `${sign(null, Buffer.from(packageManifest), privateKey).toString("base64")}\n`);
	return {
		packageDir: signedPackage,
		publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
		keys: { publicKey, privateKey },
	};
}

function runCommercialInstaller(sourcePackage, home, config) {
	mkdirSync(home, { recursive: true });
	const args = [installer, "--package-dir", sourcePackage, "--home", home];
	if (config) args.push("--config", config);
	return spawnSync(process.execPath, args, {
		encoding: "utf8", timeout: 120000, cwd: home,
		env: { ...process.env, HOME: home, USERPROFILE: home, AIDR_COMMERCIAL: "1", AIDR_DEVELOPMENT_MODE: "false" },
	});
}

function runWithInstallFault(sourcePackage, home, fault, config) {
	const preload = join(home, "install-fault.cjs");
	writeFileSync(preload, `
const child = require("node:child_process");
const fs = require("node:fs");
const { syncBuiltinESMExports } = require("node:module");
const spawn = child.spawnSync;
const rename = fs.renameSync;
if (process.env.AIDR_TEST_FAULT === "concurrent-edit") child.spawnSync = (...args) => {
  const result = spawn(...args);
  if (args[1]?.[0]?.endsWith("pre-tool-use.cjs")) fs.writeFileSync(process.env.AIDR_TEST_SETTINGS, process.env.AIDR_TEST_EDIT);
  return result;
};
if (process.env.AIDR_TEST_FAULT?.startsWith("receipt-failure")) fs.renameSync = (from, to) => {
  if (to.endsWith("installation.json")) {
    if (process.env.AIDR_TEST_FAULT === "receipt-failure-after-user-edit") fs.writeFileSync(process.env.AIDR_TEST_SETTINGS, process.env.AIDR_TEST_EDIT);
    throw new Error("injected receipt publication failure");
  }
  if (process.env.AIDR_TEST_FAULT === "receipt-failure-and-rollback-failure" && from.includes(".aidr-rollback-")) throw new Error("injected rollback failure");
  return rename(from, to);
};
syncBuiltinESMExports();
`);
	const args = ["--require", preload, installer, "--package-dir", sourcePackage, "--home", home];
	if (config) args.push("--config", config);
	return spawnSync(process.execPath, args, {
		encoding: "utf8", timeout: 120000, cwd: home,
		env: { ...process.env, HOME: home, USERPROFILE: home, AIDR_TEST_FAULT: fault,
			AIDR_TEST_SETTINGS: join(home, ".claude", "settings.json"), AIDR_TEST_EDIT: '{"customerChangedDuringCanary":true}\n',
			AIDR_DEVELOPMENT_MODE: "true" },
	});
}

test("atomic settings replacement retries transient EPERM", () => {
	let attempts = 0;
	const sleeps = [];
	assert.doesNotThrow(() => renameWithRetry("staged-settings", "settings.json", {
		attempts: 4,
		delayMs: 7,
		rename: () => {
			attempts++;
			if (attempts < 3) {
				const error = new Error("sharing violation");
				error.code = "EPERM";
				throw error;
			}
		},
		sleep: (delay) => sleeps.push(delay),
	}));
	assert.equal(attempts, 3);
	assert.deepEqual(sleeps, [7, 7]);
});

test("installer refuses unsupported Node runtimes before changing the endpoint", (context) => {
	const home = temporaryHome(context);
	const preload = join(home, "node-version.cjs");
	writeFileSync(preload, 'Object.defineProperty(process.versions, "node", { value: process.env.AIDR_TEST_NODE_VERSION });\n');
	for (const version of ["20.20.0", "22.11.0"]) {
		const result = spawnSync(process.execPath, ["--require", preload, installer, "--package-dir", packageDir, "--home", home], {
			encoding: "utf8", timeout: 30000,
			env: { ...process.env, AIDR_TEST_NODE_VERSION: version, AIDR_DEVELOPMENT_MODE: "false" },
		});
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /Endpoint installation requires Node\.js >=22\.12\.0/);
		assert.equal(existsSync(join(home, ".singularity-aidr")), false);
		assert.equal(existsSync(join(home, ".claude", "settings.json")), false);
	}
});

test("fleet-staged installer runs without source-checkout sibling modules", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const stagedInstaller = join(home, "endpoint-install.mjs");
	copyFileSync(installer, stagedInstaller);
	const result = spawnSync(process.execPath, [stagedInstaller, "--package-dir", sourcePackage, "--home", home], {
		encoding: "utf8", timeout: 120000, cwd: home,
		env: { ...process.env, HOME: home, USERPROFILE: home, AIDR_DEVELOPMENT_MODE: "true" },
	});
	assert.equal(result.status, 0, `staged installer failed: ${result.stderr || result.error?.message}`);
	assert.match(readFileSync(join(home, ".singularity-aidr", "installation.json"), "utf8"), /local_canary/);
});

test("commercial installer stages integrity config before its canary and rejects an empty unconfigured home", async (context) => {
	const fixture = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const signed = createSignedCommercialPackage(fixture, sourcePackage);
	const goodConfig = join(fixture, "good-config.json");
	writeFileSync(goodConfig, JSON.stringify({
		integrity: { enabled: true, verify_on_start: true, public_keys_pem: [signed.publicKeyPem] },
	}));
	const configuredHome = join(fixture, "configured-home");
	const configured = runCommercialInstaller(signed.packageDir, configuredHome, goodConfig);
	assert.equal(configured.status, 0, configured.stderr || configured.error?.message);
	assert.equal(existsSync(join(configuredHome, ".singularity-aidr", "config.json")), true);
	assert.equal(existsSync(join(configuredHome, ".claude", "settings.json")), true);
	assert.equal(
		readFileSync(join(configuredHome, ".singularity-aidr", "connectors", "claude", readdirSync(join(configuredHome, ".singularity-aidr", "connectors", "claude"))[0], "aidr-artifact.manifest.json"), "utf8"),
		readFileSync(join(signed.packageDir, "aidr-artifact.manifest.json"), "utf8"),
	);

	const badConfig = join(fixture, "bad-config.json");
	writeFileSync(badConfig, JSON.stringify({
		integrity: { enabled: true, verify_on_start: true, public_keys_pem: [] },
	}));
	const rejectedConfigHome = join(fixture, "rejected-config-home");
	const rejectedConfig = runCommercialInstaller(signed.packageDir, rejectedConfigHome, badConfig);
	assert.notEqual(rejectedConfig.status, 0);
	assert.match(rejectedConfig.stderr, /requires independently provisioned integrity keys/);
	assert.equal(existsSync(join(rejectedConfigHome, ".singularity-aidr", "config.json")), false, "failed verification left staged config behind");
	assert.equal(existsSync(join(rejectedConfigHome, ".claude", "settings.json")), false);

	const emptyHome = join(fixture, "empty-home");
	const unconfigured = runCommercialInstaller(signed.packageDir, emptyHome);
	assert.notEqual(unconfigured.status, 0);
	assert.match(unconfigured.stderr, /requires independently provisioned integrity keys/);
	assert.equal(existsSync(join(emptyHome, ".claude", "settings.json")), false);
	assert.equal(existsSync(join(emptyHome, ".singularity-aidr", "installation.json")), false);
});

test("unsigned packages are refused before any install side effect outside explicit development mode", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const result = spawnSync(process.execPath, [installer, "--package-dir", sourcePackage, "--home", home], {
		encoding: "utf8", timeout: 120000, cwd: home,
		env: { ...process.env, HOME: home, USERPROFILE: home, AIDR_DEVELOPMENT_MODE: "false" },
	});
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /Unsigned Claude package refused/);
	assert.equal(existsSync(join(home, ".claude", "settings.json")), false);
	assert.equal(existsSync(join(home, ".singularity-aidr", "connectors", "claude")), false);
	assert.equal(existsSync(join(home, ".singularity-aidr", "installation.json")), false);
});

test("commercial installer refuses package-provided trust through a directory alias", async (context) => {
	const fixture = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const signed = createSignedCommercialPackage(fixture, sourcePackage);
	const packageAlias = join(fixture, "package-alias");
	symlinkSync(signed.packageDir, packageAlias, process.platform === "win32" ? "junction" : "dir");
	writeFileSync(join(signed.packageDir, "trust.json"), JSON.stringify({
		integrity: { enabled: true, verify_on_start: true, public_keys_pem: [signed.publicKeyPem] },
	}));
	const home = join(fixture, "aliased-trust-home");
	const result = runCommercialInstaller(signed.packageDir, home, join(packageAlias, "trust.json"));
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /Integrity trust configuration must be provisioned outside the endpoint package/);
	assert.equal(existsSync(join(home, ".singularity-aidr", "connectors", "claude")), false);
	assert.equal(existsSync(join(home, ".claude", "settings.json")), false);
});

test("commercial installer refuses redirected managed directories before writing outside the home", async (context) => {
	const fixture = temporaryHome(context);
	const signed = createSignedCommercialPackage(fixture, await buildEndpointPackageFixture());
	const config = join(fixture, "trusted-config.json");
	writeFileSync(config, JSON.stringify({ integrity: { enabled: true, verify_on_start: true, public_keys_pem: [signed.publicKeyPem] } }));
	for (const managedDirectory of [".claude", ".singularity-aidr"]) {
		const home = join(fixture, `${managedDirectory}-home`);
		const redirected = join(fixture, `${managedDirectory}-redirected`);
		mkdirSync(home);
		mkdirSync(redirected);
		symlinkSync(redirected, join(home, managedDirectory), process.platform === "win32" ? "junction" : "dir");
		const result = runCommercialInstaller(signed.packageDir, home, config);
		assert.notEqual(result.status, 0, `${managedDirectory} redirected the installer`);
		assert.match(result.stderr, /Managed installation path contains a symlink/);
		assert.deepEqual(readdirSync(redirected), [], `${managedDirectory} wrote outside the target home`);
	}
});

test("commercial package tampering is refused before files are copied or hooks are registered", async (context) => {
	const fixture = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const signed = createSignedCommercialPackage(fixture, sourcePackage);
	const config = join(fixture, "trusted-config.json");
	writeFileSync(config, JSON.stringify({ integrity: { enabled: true, verify_on_start: true, public_keys_pem: [signed.publicKeyPem] } }));
	for (const [name, relative, contents] of [
		["resource-tamper", "resources/threats/commands.yaml", "# modified after signing\n"],
		["runtime-tamper", "dist/pre-tool-use.cjs", "// modified after signing\n"],
		["unexpected-file", "resources/threats/extra.yaml", "unexpected\n"],
		["metadata-tamper", "package.json", `${readFileSync(join(signed.packageDir, "package.json"), "utf8")}\n`],
		["signature-tamper", "aidr-artifact.manifest.sig", "AAAA\n"],
		["manifest-tamper", "aidr-artifact.manifest.json", `${readFileSync(join(signed.packageDir, "aidr-artifact.manifest.json"), "utf8")}\n`],
	]) {
		const candidate = join(fixture, name);
		cpSync(signed.packageDir, candidate, { recursive: true });
		writeFileSync(join(candidate, ...relative.split("/")), contents);
		const home = join(fixture, `${name}-home`);
		const result = runCommercialInstaller(candidate, home, config);
		assert.notEqual(result.status, 0, `${name} unexpectedly installed`);
		assert.doesNotMatch(result.stderr, /malicious-command canary passed/);
		assert.equal(existsSync(join(home, ".claude", "settings.json")), false, `${name} registered hooks`);
		assert.equal(existsSync(join(home, ".singularity-aidr", "connectors", "claude")), false, `${name} copied package files`);
		assert.equal(existsSync(join(home, ".singularity-aidr", "installation.json")), false, `${name} published an install receipt`);
	}
});

test("reinstall preserves a customer hook alongside a managed hook", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const settingsPath = writeMixedSettings(home);
	const configPath = join(home, ".singularity-aidr", "config.json");
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
	const originalConfig = '{"version_check":{"enabled":false}}\n';
	writeFileSync(configPath, originalConfig);

	for (let attempt = 0; attempt < 2; attempt++) {
		const result = spawnSync(process.execPath, [installer, "--package-dir", sourcePackage, "--home", home], {
			encoding: "utf8", timeout: 120000, cwd: home,
			env: { ...process.env, HOME: home, USERPROFILE: home, AIDR_DEVELOPMENT_MODE: "true" },
		});
		assert.equal(result.status, 0, `installer attempt ${attempt + 1} failed: ${result.stderr || result.error?.message}`);
		assertCustomerHookPreserved(settingsPath, true);
		assert.equal(readFileSync(configPath, "utf8"), originalConfig);
	}
	assert.equal(readdirSync(join(home, ".claude")).filter((name) => name.startsWith("settings.json.aidr-backup-")).length, 1);
});

test("signed local update switches managed hooks to the new digest and retains the old payload", async (context) => {
	const fixture = temporaryHome(context);
	const firstSourcePackage = await buildEndpointPackageFixture("0.6.0");
	const secondSourcePackage = await buildEndpointPackageFixture("0.6.1");
	const first = createSignedCommercialPackage(join(fixture, "release-1"), firstSourcePackage);
	const second = createSignedCommercialPackage(join(fixture, "release-2"), secondSourcePackage, { keys: first.keys });
	const config = join(fixture, "agent-config.json");
	const configBytes = JSON.stringify({ integrity: { enabled: true, verify_on_start: true, public_keys_pem: [first.publicKeyPem] } });
	writeFileSync(config, configBytes);
	const home = temporaryHome(context);
	const settingsPath = writeMixedSettings(home);

	const installed = runCommercialInstaller(first.packageDir, home, config);
	assert.equal(installed.status, 0, installed.stderr || installed.error?.message);
	const firstReceipt = JSON.parse(readFileSync(join(home, ".singularity-aidr", "installation.json"), "utf8"));
	const firstPayload = join(home, ".singularity-aidr", "connectors", "claude", firstReceipt.artifact_sha256);

	const updated = runCommercialInstaller(second.packageDir, home);
	assert.equal(updated.status, 0, updated.stderr || updated.error?.message);
	const secondReceipt = JSON.parse(readFileSync(join(home, ".singularity-aidr", "installation.json"), "utf8"));
	const secondPayload = join(home, ".singularity-aidr", "connectors", "claude", secondReceipt.artifact_sha256);
	assert.notEqual(firstReceipt.artifact_sha256, secondReceipt.artifact_sha256);
	assert.equal(existsSync(firstPayload), true, "update removed the prior digest payload");
	assert.equal(existsSync(secondPayload), true, "update did not install the new digest payload");
	assert.equal(readFileSync(config, "utf8"), configBytes, "update overwrote the existing trust configuration");

	const settings = JSON.parse(readFileSync(settingsPath, "utf8"));
	assert.ok(JSON.stringify(settings.hooks.PreToolUse).includes(secondPayload.replaceAll("\\", "/")));
	assert.ok(JSON.stringify(settings.hooks.PostToolUse).includes(secondPayload.replaceAll("\\", "/")));
	assertCustomerHookPreserved(settingsPath, true);
	for (const event of ["PreToolUse", "PostToolUse", "SessionStart"]) {
		const managed = settings.hooks[event].flatMap((entry) => entry.hooks ?? []).filter((hook) => hook.statusMessage === managedMarker);
		assert.equal(managed.length, 1, `${event} duplicated its managed hook on update`);
	}
});

test("installer refuses a concurrent Claude settings edit without overwriting it", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const settingsPath = join(home, ".claude", "settings.json");
	writeFileSync(settingsPath, '{"beforeCanary":true}\n');
	const result = runWithInstallFault(sourcePackage, home, "concurrent-edit");
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /settings changed during installation/);
	assert.equal(readFileSync(settingsPath, "utf8"), '{"customerChangedDuringCanary":true}\n');
	assert.equal(existsSync(join(home, ".singularity-aidr", "installation.json")), false);
});

test("installer rejects hooks arrays rather than claiming a hookless success", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const settingsPath = join(home, ".claude", "settings.json");
	const original = '{"hooks":[]}\n';
	writeFileSync(settingsPath, original);
	const result = spawnSync(process.execPath, [installer, "--package-dir", sourcePackage, "--home", home], {
		encoding: "utf8", timeout: 120000, cwd: home,
		env: { ...process.env, HOME: home, USERPROFILE: home, AIDR_DEVELOPMENT_MODE: "true" },
	});
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /Invalid Claude hooks configuration/);
	assert.equal(readFileSync(settingsPath, "utf8"), original);
	assert.equal(existsSync(join(home, ".singularity-aidr", "installation.json")), false);
});

test("receipt publication failure rolls back only this install and preserves the old receipt", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const settingsPath = join(home, ".claude", "settings.json");
	const receiptPath = join(home, ".singularity-aidr", "installation.json");
	const originalSettings = '{"customerSetting":"keep"}\n';
	const originalReceipt = '{"previous":"receipt"}\n';
	writeFileSync(settingsPath, originalSettings);
	mkdirSync(dirname(receiptPath), { recursive: true });
	writeFileSync(receiptPath, originalReceipt);
	const result = runWithInstallFault(sourcePackage, home, "receipt-failure");
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /injected receipt publication failure/);
	assert.equal(readFileSync(settingsPath, "utf8"), originalSettings);
	assert.equal(readFileSync(receiptPath, "utf8"), originalReceipt);
	assert.equal(readdirSync(dirname(receiptPath)).filter((name) => name.startsWith("installation.json.aidr-")).length, 0);
});

test("receipt failure removes newly created settings without touching another file", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const customerFile = join(home, ".claude", "customer.json");
	writeFileSync(customerFile, "customer-owned\n");
	const result = runWithInstallFault(sourcePackage, home, "receipt-failure");
	assert.notEqual(result.status, 0);
	assert.equal(existsSync(join(home, ".claude", "settings.json")), false);
	assert.equal(readFileSync(customerFile, "utf8"), "customer-owned\n");
	assert.equal(existsSync(join(home, ".singularity-aidr", "installation.json")), false);
});

test("receipt failure preserves a customer edit made after settings replacement", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const settingsPath = join(home, ".claude", "settings.json");
	writeFileSync(settingsPath, '{"original":"customer"}\n');
	const result = runWithInstallFault(sourcePackage, home, "receipt-failure-after-user-edit");
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /settings changed afterward/);
	assert.equal(readFileSync(settingsPath, "utf8"), '{"customerChangedDuringCanary":true}\n');
	assert.equal(existsSync(join(home, ".singularity-aidr", "installation.json")), false);
});

test("rollback failure leaves an exact settings backup and a recovery path", async (context) => {
	const home = temporaryHome(context);
	const sourcePackage = await buildEndpointPackageFixture();
	const settingsPath = join(home, ".claude", "settings.json");
	const originalSettings = '{"original":"customer"}\n';
	writeFileSync(settingsPath, originalSettings);
	const result = runWithInstallFault(sourcePackage, home, "receipt-failure-and-rollback-failure");
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /settings rollback failed; recover the original settings from/);
	const backups = readdirSync(dirname(settingsPath)).filter((name) => name.startsWith("settings.json.aidr-backup-"));
	assert.equal(backups.length, 1);
	assert.equal(readFileSync(join(dirname(settingsPath), backups[0]), "utf8"), originalSettings);
	assert.ok(readFileSync(settingsPath, "utf8").includes(managedMarker));
	assert.equal(existsSync(join(home, ".singularity-aidr", "installation.json")), false);
});

test("Unix uninstall removes only managed nested hooks", (context) => {
	const home = temporaryHome(context);
	const settingsPath = writeMixedSettings(home);
	const remover = join(repository, "deploy", "fleet", "unix", "remove-managed-hooks.mjs");
	const result = spawnSync(process.execPath, [remover, "--home", home], { encoding: "utf8", timeout: 30000 });
	assert.equal(result.status, 0, result.stderr || result.error?.message);
	assertCustomerHookPreserved(settingsPath, false);
	assert.equal(readdirSync(join(home, ".claude")).filter((name) => name.startsWith("settings.json.aidr-backup-")).length, 1);
});

test("Unix uninstall refuses a concurrent settings edit without overwriting it", (context) => {
	const home = temporaryHome(context);
	const settingsPath = writeMixedSettings(home);
	const remover = join(repository, "deploy", "fleet", "unix", "remove-managed-hooks.mjs");
	const customerEdit = '{"customerChangedDuringUninstall":true}\n';
	const preload = join(home, "uninstall-fault.cjs");
	writeFileSync(preload, `
const fs = require("node:fs");
const { syncBuiltinESMExports } = require("node:module");
const originalWrite = fs.writeFileSync;
fs.writeFileSync = (path, data, options) => {
  const result = originalWrite(path, data, options);
  if (String(path).endsWith(".tmp") && String(path).includes("settings.json.aidr-")) {
    originalWrite(process.env.AIDR_TEST_SETTINGS, ${JSON.stringify(customerEdit)});
  }
  return result;
};
syncBuiltinESMExports();
`);
	const result = spawnSync(process.execPath, ["--require", preload, remover, "--home", home], {
		encoding: "utf8", timeout: 30000, env: { ...process.env, AIDR_TEST_SETTINGS: settingsPath },
	});
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /settings changed during uninstall/);
	assert.equal(readFileSync(settingsPath, "utf8"), customerEdit);
	assert.equal(existsSync(`${settingsPath}.aidr-${result.pid}.tmp`), false);
});

test("Windows uninstall removes only managed nested hooks", (context) => {
	const powershell = process.platform === "win32" ? "powershell.exe" : "pwsh";
	const available = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0"], { encoding: "utf8" });
	if (available.error?.code === "ENOENT") return context.skip("PowerShell is unavailable on this host");
	assert.equal(available.status, 0, available.stderr || available.error?.message);
	const home = temporaryHome(context);
	const settingsPath = writeMixedSettings(home);
	const remover = join(repository, "deploy", "fleet", "windows", "Uninstall-Aidr.ps1");
	const result = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", remover, "-TargetHome", home, "-StateRoot", join(home, "fleet-state")], {
		encoding: "utf8", timeout: 30000, windowsHide: true,
	});
	assert.equal(result.status, 0, result.stderr || result.error?.message);
	assertCustomerHookPreserved(settingsPath, false);
	assert.equal(readdirSync(join(home, ".claude")).filter((name) => name.startsWith("settings.json.aidr-uninstall-backup-")).length, 1);
});
