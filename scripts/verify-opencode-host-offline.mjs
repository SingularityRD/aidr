#!/usr/bin/env node
/** Real OpenCode host dispatch, with a deterministic localhost model and no cloud. */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const binary = process.argv[2];
const output = process.argv[3] && resolve(process.argv[3]);
if (!binary || !isAbsolute(binary) || !existsSync(binary) || !/opencode\.exe$/i.test(binary)) {
	throw new Error("Pass the absolute path to the installed opencode.exe as the only argument.");
}
if (!existsSync(join(root, "packages/opencode/dist/index.js")) || !existsSync(join(root, "packages/core/dist/index.js"))) {
	throw new Error("Existing OpenCode/Core dist files are required; this test never builds them.");
}

const scratch = mkdtempSync(join(tmpdir(), "aidr-opencode-offline-"));
function cleanupScratch() {
	if (!existsSync(scratch)) return;
	const canonicalScratch = realpathSync(scratch);
	assert.equal(dirname(canonicalScratch), realpathSync(tmpdir()));
	assert.ok(basename(canonicalScratch).startsWith("aidr-opencode-offline-"));
	rmSync(canonicalScratch, { recursive: true, force: true });
}
process.on("exit", cleanupScratch);
const home = join(scratch, "home");
const workspace = join(scratch, "workspace");
const configDir = join(home, ".config", "opencode");
const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const sourcePackages = ["core", "opencode"].map((name) => join(root, "packages", name));
function artifactSnapshot() {
	return Object.fromEntries(sourcePackages.map((packageRoot) => {
		const dist = join(packageRoot, "dist");
		const manifestPath = join(dist, "aidr-artifact.manifest.json");
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
		assert.equal(manifest.artifact_id, `${basename(packageRoot)}/dist`);
		const files = Object.fromEntries(manifest.files.map((entry) => {
			const file = resolve(dist, entry.path);
			const local = relative(dist, file);
			assert.ok(local && local !== ".." && !local.startsWith(`..${sep}`) && !isAbsolute(local));
			assert.equal(hash(file), entry.sha256, `Release manifest mismatch: ${entry.path}`);
			return [entry.path, entry.sha256];
		}));
		return [manifest.artifact_id, { manifest: hash(manifestPath), package_json: hash(join(packageRoot, "package.json")), files }];
	}));
}
const before = { executable: hash(binary), artifacts: artifactSnapshot() };
assert.match(readFileSync(join(sourcePackages[0], "dist/build-flavor.js"), "utf8"), /EMBEDDED_BUILD_FLAVOR\s*=\s*"commercial"/, "The native verifier requires actual commercial release bytes");
const { publicKey: artifactPublicKey, privateKey: artifactPrivateKey } = generateKeyPairSync("ed25519");
const integrity = { enabled: true, verify_on_start: true, public_keys_pem: [artifactPublicKey.export({ type: "spki", format: "pem" }).toString()] };
const copiedCore = join(scratch, "packages/core");
for (const packageRoot of sourcePackages) {
	const copy = join(scratch, "packages", basename(packageRoot));
	mkdirSync(copy, { recursive: true });
	cpSync(join(packageRoot, "package.json"), join(copy, "package.json"));
	cpSync(join(packageRoot, "dist"), join(copy, "dist"), { recursive: true });
	const manifestBytes = readFileSync(join(copy, "dist/aidr-artifact.manifest.json"));
	writeFileSync(join(copy, "dist/aidr-artifact.manifest.sig"), `${sign(null, manifestBytes, artifactPrivateKey).toString("base64")}\n`);
	// Existing installed third-party dependencies remain read-only. The workspace
	// core reference points at the copied, signed package, never the source dist.
	const dependencies = JSON.parse(readFileSync(join(copy, "package.json"), "utf8")).dependencies ?? {};
	for (const name of Object.keys(dependencies)) {
		const destination = join(copy, "node_modules", name);
		mkdirSync(dirname(destination), { recursive: true });
		const dependency = name === "@singularityrd/aidr-core" ? copiedCore : realpathSync(join(packageRoot, "node_modules", name));
		symlinkSync(dependency, destination, process.platform === "win32" ? "junction" : "dir");
	}
}
const scenarios = [
	{ id: "env-path", path: join(workspace, ".env"), content: "AIDR_DEMO_SENTINEL=synthetic-only\n", blocked: true },
	{ id: "credential-content", path: join(workspace, "synthetic-secrets.txt"), content: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=synthetic-only\n", blocked: true },
	{ id: "benign", path: join(workspace, "safe-note.txt"), content: "AIDR offline benign fixture\n", blocked: false },
];
const tenant = "22222222-2222-4222-8222-222222222222";
const tenantMarker = "AIDR-TENANT-SYNTHETIC-RESTRICTED";
const localPluginPackage = realpathSync(join(root, "packages/opencode/node_modules/@opencode-ai/plugin"));
const localPluginVersion = JSON.parse(readFileSync(join(localPluginPackage, "package.json"), "utf8")).version;
function seedOfflineDependencies(dir) {
	const packageName = "@opencode-ai/plugin";
	mkdirSync(join(dir, "node_modules", "@opencode-ai"), { recursive: true });
	cpSync(localPluginPackage, join(dir, "node_modules", "@opencode-ai", "plugin"), { recursive: true });
	writeFileSync(join(dir, "package.json"), JSON.stringify({ private: true, dependencies: { [packageName]: localPluginVersion } }));
	writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { [packageName]: localPluginVersion } } } }));
}
mkdirSync(configDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
seedOfflineDependencies(configDir);
seedOfflineDependencies(join(home, ".opencode"));
const pluginDir = join(configDir, "plugins");
mkdirSync(pluginDir);
// Observe the real signed handler invocation, including errors before a verdict.
// This fixture relay forwards the exact host arguments and never writes sentinels.
writeFileSync(join(pluginDir, "aidr.js"), `import actual from ${JSON.stringify(pathToFileURL(join(scratch, "packages/opencode/dist/index.js")).href)};
import {appendFileSync} from 'node:fs';
export default async function(context){const handlers=await actual(context);const before=handlers['tool.execute.before'];
if(typeof before!=='function')throw new Error('Actual signed plugin has no pre-tool handler');
return {...handlers,'tool.execute.before':async (...args)=>{
appendFileSync(process.env.AIDR_NATIVE_TEST_RECEIPT,JSON.stringify({nonce:process.env.AIDR_NATIVE_TEST_CASE_NONCE,connector:'opencode-fixture-relay',event:'tool.execute.before',toolName:args[0]?.tool,phase:'invoke_actual_signed_plugin'})+'\\n');
return before(...args);}};}
`);
writeFileSync(join(home, ".singularity-aidr", "config.json"), JSON.stringify({
	mode: "local",
	integrity,
	control_plane: { enabled: false },
	logging: { enabled: true, path: join(home, ".singularity-aidr", "audit.jsonl") },
}));

let scenario = scenarios[0];
let requestedTool = false;
let providerCalls = 0;
const model = "aidr-fixture";
const provider = createServer(async (request, response) => {
	if (request.method === "GET" && request.url === "/v1/models") {
		response.writeHead(200, { "content-type": "application/json" });
		response.end(JSON.stringify({ object: "list", data: [{ id: model, object: "model" }] }));
		return;
	}
	if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
		response.writeHead(404).end();
		return;
	}
	let raw = "";
	for await (const chunk of request) {
		raw += chunk;
		if (raw.length > 1_000_000) { response.writeHead(413).end(); return; }
	}
	const body = JSON.parse(raw);
	providerCalls++;
	if (body.model !== model || body.stream !== true) {
		response.writeHead(400, { "content-type": "application/json" });
		response.end(JSON.stringify({ error: { message: "offline fixture expected the configured streaming model" } }));
		return;
	}
	const hasWriteTool = body.tools?.some((entry) => entry.function?.name === "write") ?? false;
	if (hasWriteTool) requestedTool = true;
	const priorToolCall = body.messages?.some((entry) => entry.role === "tool");
	const call = !hasWriteTool || priorToolCall ? null : {
		index: 0,
		id: `call_aidr_${scenario.id}`,
		type: "function",
		function: {
			name: "write",
			arguments: JSON.stringify({ filePath: scenario.path, content: scenario.content }),
		},
	};
	const envelope = (delta, finish_reason) => JSON.stringify({
		id: `chatcmpl-aidr-${scenario.id}`,
		object: "chat.completion.chunk",
		created: 1,
		model,
		choices: [{ index: 0, delta, finish_reason }],
	});
	response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
	response.write(`data: ${envelope(call ? { role: "assistant", tool_calls: [call] } : { role: "assistant", content: "Fixture complete." }, null)}\n\n`);
	response.write(`data: ${envelope({}, call ? "tool_calls" : "stop")}\n\n`);
	response.end("data: [DONE]\n\n");
});

function isolatedEnvironment() {
	const env = Object.fromEntries(["SystemRoot", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP"].filter((key) =>
		process.env[key] !== undefined).map((key) => [key, process.env[key]]));
	return {
		...env,
		HOME: home, USERPROFILE: home,
		APPDATA: join(home, "AppData", "Roaming"), LOCALAPPDATA: join(home, "AppData", "Local"),
		XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local", "share"),
		XDG_CACHE_HOME: join(home, ".cache"), XDG_STATE_HOME: join(home, ".local", "state"),
		OPENCODE_CONFIG: join(configDir, "opencode.json"),
		OPENCODE_CONFIG_DIR: join(home, ".opencode"),
		OPENCODE_DISABLE_AUTOUPDATE: "1", OPENCODE_DISABLE_MODELS_FETCH: "1",
		DO_NOT_TRACK: "1", CI: "1", NO_COLOR: "1",
		HTTP_PROXY: "http://127.0.0.1:1", HTTPS_PROXY: "http://127.0.0.1:1",
		ALL_PROXY: "http://127.0.0.1:1", NO_PROXY: "127.0.0.1,localhost",
	};
}

async function runHost(label) {
	const nonce = randomUUID();
	const receipt = join(workspace, `hook-${nonce}.jsonl`);
	const child = spawn(binary, ["--print-logs", "--log-level", "DEBUG", "run", "--model", "aidr-local/aidr-fixture", "--format", "json", `AIDR offline ${label} fixture`], {
		cwd: workspace, env: { ...isolatedEnvironment(), AIDR_NATIVE_TEST_WORKSPACE: workspace, AIDR_NATIVE_TEST_RECEIPT: receipt, AIDR_NATIVE_TEST_CASE_NONCE: nonce }, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
	});
	let stdout = "";
	let stderr = "";
	child.stdout.setEncoding("utf8");
	child.stderr.setEncoding("utf8");
	child.stdout.on("data", (chunk) => { stdout = (stdout + chunk).slice(-1_000_000); });
	child.stderr.on("data", (chunk) => { stderr = (stderr + chunk).slice(-100_000); });
	const timer = setTimeout(() => child.kill(), 30_000);
	const [code] = await new Promise((resolveExit, reject) => {
		child.once("error", reject);
		child.once("exit", (...args) => resolveExit(args));
	});
	clearTimeout(timer);
	const events = stdout.split(/\r?\n/).flatMap((line) => {
		try { return [JSON.parse(line)]; } catch { return []; }
	});
	const observations = existsSync(receipt) ? readFileSync(receipt, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line)) : [];
	return { code, nonce, observations, events, stderr: stderr.slice(-2000), stdoutTail: stdout.slice(-2000) };
}

const results = [];
async function verifyScenario(item) {
	scenario = item;
	requestedTool = false;
	providerCalls = 0;
	const result = await runHost(item.id);
	const record = { id: item.id, expected_block: item.blocked, provider_calls: providerCalls, ...result, status: "FAIL" };
	results.push(record);
	const writes = result.events.filter((event) => event.type === "tool_use" && event.part?.tool === "write");
	assert.equal(result.code, 0, `${item.id}: OpenCode failed (${result.stderr}; ${result.stdoutTail})`);
	assert.ok(requestedTool && providerCalls >= 1, `${item.id}: OpenCode did not request the local fake model with write (calls=${providerCalls}; ${result.stderr})`);
	assert.ok(writes.length > 0, `${item.id}: real OpenCode did not dispatch write (${result.stderr})`);
	assert.ok(result.observations.some((entry) => entry.nonce === result.nonce && entry.connector === "opencode-fixture-relay" && entry.toolName === "write" && entry.phase === "invoke_actual_signed_plugin"), `${item.id}: no nonce-bound actual signed AIDR handler invocation`);
	if (item.id !== "signed-dlp-no-entitlement") {
		assert.ok(result.observations.some((entry) => entry.nonce === result.nonce && entry.connector === "opencode"), `${item.id}: no evaluated AIDR verdict observation`);
	}
	if (item.blocked) {
		assert.equal(existsSync(item.path), false, `${item.id}: synthetic write unexpectedly reached disk; host shape=${JSON.stringify(writes.map((event) => ({ status: event.part?.state?.status, keys: Object.keys(event.part?.state?.input ?? {}), contentLength: typeof event.part?.state?.input?.content === "string" ? event.part.state.input.content.length : null })))}`);
		assert.ok(writes.some((event) => event.part?.state?.status === "error" && /Singularity AIDR/i.test(JSON.stringify(event.part?.state))), `${item.id}: blocked write was not attributed to the AIDR hook (${JSON.stringify(writes.map((event) => event.part?.state))})`);
		if (item.reason) assert.match(JSON.stringify(writes.map((event) => event.part?.state)), item.reason);
	} else {
		assert.ok(writes.some((event) => event.part?.state?.status === "completed"), `${item.id}: benign host write was not completed`);
		assert.equal(readFileSync(item.path, "utf8"), item.content, "Benign write did not execute in the real host");
	}
	record.status = "PASS";
	console.log(`PASS ${item.id}: real OpenCode host dispatched write; ${item.blocked ? "AIDR blocked and file absent" : "benign file contents match"}`);
}

let failure;
let versionProbe;
try {
	versionProbe = spawnSync(binary, ["--version"], { env: isolatedEnvironment(), encoding: "utf8", timeout: 10_000, windowsHide: true });
	assert.equal(versionProbe.status, 0, "Native host version probe failed");
	await new Promise((resolveListen) => provider.listen(0, "127.0.0.1", resolveListen));
	const port = provider.address().port;
	writeFileSync(join(configDir, "opencode.json"), JSON.stringify({
		$schema: "https://opencode.ai/config.json",
		autoupdate: false,
		model: `aidr-local/${model}`,
		small_model: `aidr-local/${model}`,
		enabled_providers: ["aidr-local"],
		permission: { edit: "allow", bash: "deny", webfetch: "deny", external_directory: "deny" },
		provider: { "aidr-local": {
			npm: "@ai-sdk/openai-compatible", name: "AIDR offline fixture",
			options: { baseURL: `http://127.0.0.1:${port}/v1`, apiKey: "fixture-only" },
			models: { [model]: { name: "AIDR fixture", limit: { context: 8192, output: 1024 } } },
		} },
	}));
	for (const item of scenarios) await verifyScenario(item);

	const { canonicalDetectorPolicyPayload } = await import(pathToFileURL(join(copiedCore, "dist/index.js")).href);
	const { installSignedDlpBundle, signSavedDlpRevision } = await import("./provision-dlp-detector.mjs");
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const now = Date.now();
	const aidrStateDir = join(home, ".singularity-aidr");
	writeFileSync(join(aidrStateDir, "config.json"), JSON.stringify({
		mode: "managed", control_plane: { enabled: false },
		integrity,
		licensing: { public_keys_pem: [publicKey.export({ type: "spki", format: "pem" }).toString()], require_signed_entitlements: true },
		logging: { enabled: true, path: join(aidrStateDir, "audit.jsonl") },
	}));
	const policy = {
		version: 7, tenantId: tenant, maxContentBytes: 4096,
		supportedFormats: ["application/json"], unavailableAction: "block",
		labels: [{ id: "restricted", tenantId: tenant, name: "Restricted", sensitivity: "restricted" }],
		rules: [{ id: "marker", tenantId: tenant, labelId: "restricted", name: "Synthetic marker",
			action: "block", directions: ["input"], matchers: [{ type: "keyword", values: [tenantMarker], wholeWord: false }] }],
		exceptions: [],
	};
	await installSignedDlpBundle(join(aidrStateDir, "detectors"), "opencode",
		signSavedDlpRevision({ policy, tenant, expiresAt: new Date(now + 300_000).toISOString(), privateKey }));
	await verifyScenario({ id: "signed-dlp-no-entitlement", path: join(workspace, "unlicensed-note.txt"),
		content: "ordinary harmless text\n", blocked: true, reason: /could not evaluate/i });
	const entitlement = { schema_version: 2, tenant_id: tenant, subscription_tier: "enterprise",
		included_agents: 1, extra_agents: 0, allowed_agents: 1, premium_modules: ["runtime_detectors"],
		issued_at: new Date(now - 60_000).toISOString(), expires_at: new Date(now + 600_000).toISOString(),
		grace_until: new Date(now + 900_000).toISOString(), serial: "synthetic-host-entitlement", revocation_epoch: 1 };
	writeFileSync(join(aidrStateDir, "managed.json"), JSON.stringify({ entitlement, entitlement_alg: "ed25519",
		entitlement_key_id: "synthetic-host", entitlement_sig: sign(null,
			Buffer.from(canonicalDetectorPolicyPayload(entitlement)), privateKey).toString("base64") }));
	await verifyScenario({ id: "signed-tenant-dlp-deny", path: join(workspace, "tenant-marker.txt"),
		content: `${tenantMarker}\n`, blocked: true, reason: /DLP policy requires block/i });
	await verifyScenario({ id: "signed-tenant-dlp-benign", path: join(workspace, "tenant-safe.txt"),
		content: "ordinary harmless text\n", blocked: false });
} catch (error) {
	failure = error.message; process.exitCode = 1; console.error(failure);
} finally {
	provider.closeAllConnections(); provider.close();
	try { assert.deepEqual({ executable: hash(binary), artifacts: artifactSnapshot() }, before, "Source release/host bytes changed during native acceptance"); }
	catch (error) { failure = error.message; process.exitCode = 1; console.error(failure); }
	if (output) {
		mkdirSync(dirname(output), { recursive: true });
		writeFileSync(output, `${JSON.stringify({ schema_version: 1, kind: "aidr-opencode-offline-native", measured_at: new Date().toISOString(),
			host_version: versionProbe?.stdout?.trim(), host_path: binary, source_sha256: hash(fileURLToPath(import.meta.url)), inputs: before,
			source_commit: spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).stdout.trim(),
			workspace_dirty: Boolean(spawnSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).stdout.trim()),
			status: failure ? "FAIL" : "PASS", failure: failure ?? null, expected: 6, passed: results.filter((entry) => entry.status === "PASS").length, results,
			limitations: ["Deterministic loopback peer tests actual CLI tool dispatch; no model intelligence or remote inference was tested.", "Copied release artifacts use an ephemeral fixture signing key; production signing and independent deployment acceptance remain open.", "Installed third-party dependencies are linked read-only into scratch; the tested core and plugin release packages are private copies.", "One Windows/version run is not the supported host/OS matrix."],
		}, null, 2)}\n`);
		console.log(`Report: ${output}`);
	}
	cleanupScratch();
}
