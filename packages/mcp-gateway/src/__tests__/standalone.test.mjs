import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { after, before, test } from "node:test";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { coreSourcePlugin, gatewayBundleOptions, readRuleSets } from "../../scripts/bundle-options.mjs";

const packageRoot = resolve(import.meta.dirname, "../..");
let root;
let runtime;
let gatewayConfig;
let home;
let installedConfig;
let preload;
const token = "a".repeat(48);

before(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-mcp-standalone-"));
	home = join(root, "home");
	installedConfig = join(home, ".singularity-aidr", "config.json");
	await mkdir(join(home, ".singularity-aidr"), { recursive: true });
	const entry = join(root, "runtime-entry.mjs");
	await writeFile(entry, [
		`export * from ${JSON.stringify(join(packageRoot, "src", "standalone.mjs"))};`,
		`export * from ${JSON.stringify(join(packageRoot, "src", "gateway.mjs"))};`,
		`export * from ${JSON.stringify(join(packageRoot, "src", "stdio.mjs"))};`,
		`export * from ${JSON.stringify(resolve(packageRoot, "../core/src/mcp-attestation.ts"))};`,
	].join("\n"));
	const bundleOptions = gatewayBundleOptions({ ruleSets: await readRuleSets() });
	for (const name of ["cli.mjs", "stdio-cli.mjs", "runtime.mjs"]) {
		await build({ ...bundleOptions, entryPoints: [name === "runtime.mjs" ? entry : join(packageRoot, "src", name)],
			outfile: join(root, name), plugins: [...bundleOptions.plugins, coreSourcePlugin()], logLevel: "silent" });
	}
	runtime = await import(pathToFileURL(join(root, "runtime.mjs")));
	gatewayConfig = join(root, "gateway.json");
	await writeFile(gatewayConfig, JSON.stringify(fixtureConfig()));
	preload = join(root, "observe.cjs");
	await writeFile(preload, `
const fs = require("node:fs"), http = require("node:http"), https = require("node:https"), dns = require("node:dns");
const mark = (name) => fs.appendFileSync(process.env.AIDR_TEST_OBSERVER, name + "\\n");
const originalRead = fs.promises.readFile;
fs.promises.readFile = async function(path, ...args) {
 if (String(path) === process.env.AIDR_TEST_GATEWAY_CONFIG) {
  mark("gateway-config");
  if (process.env.AIDR_TEST_CHANGE_ON_CONFIG) fs.writeFileSync(process.env.AIDR_TEST_INSTALLED_CONFIG, '{"privacy":{"required":true}}');
 }
 return originalRead.call(this, path, ...args);
};
const originalListen = http.Server.prototype.listen;
http.Server.prototype.listen = function(...args) { mark("listen"); return originalListen.apply(this, args); };
const originalBodyIterator = http.IncomingMessage.prototype[Symbol.asyncIterator];
http.IncomingMessage.prototype[Symbol.asyncIterator] = function(...args) { mark("body-read"); return originalBodyIterator.apply(this, args); };
for (const [object, name] of [[dns,"lookup"],[dns.promises,"lookup"],[https,"request"],[http,"request"]]) {
 const original = object[name];
 object[name] = function(...args) {
  if (name === "lookup" && args[0] === "127.0.0.1") return original.apply(this,args);
  mark("network"); throw new Error("test_outbound_refused");
 };
}
globalThis.fetch = async function() { mark("network"); throw new Error("test_outbound_refused"); };
const originalInputRead = process.stdin.read;
process.stdin.read = function(...args) { mark("stdin"); return originalInputRead.apply(this,args); };
require("node:module").syncBuiltinESMExports();
`);
});
after(async () => { await rm(root, { recursive: true, force: true }); });

function fixtureConfig(overrides = {}) {
	const keys = generateKeyPairSync("ed25519");
	const tools = [{ name: "search", description: "Search", input_schema: { type: "object" } }];
	return { stateDir: join(root, "state"), port: 0,
		clients: [{ id: "client", tenantId: "tenant", tokenSha256: createHash("sha256").update(token).digest("hex"), allowedTools: { server: ["search"] } }],
		servers: [{ id: "server", tenantId: "tenant", url: "https://mcp.example.test/mcp", transport: "json", sessionMode: "stateless",
			signedManifest: runtime.signMcpToolManifest({ keyId: "publisher", privateKey: keys.privateKey, manifest: {
				schema_version: 1, server_id: "server", sequence: 1, issued_at: new Date(Date.now() - 60000).toISOString(),
				expires_at: new Date(Date.now() + 3600000).toISOString(), tools,
			} }), trustedSigners: { publisher: keys.publicKey.export({ type: "spki", format: "pem" }).toString() }, ...overrides }],
	};
}

async function profile(raw) {
	await rm(installedConfig, { recursive: true, force: true });
	if (raw !== undefined) await writeFile(installedConfig, raw);
}
function childOptions(name, extraEnv = {}) {
	const observer = join(root, `${name}-observer.log`);
	const args = ["--require", preload, join(root, name), gatewayConfig,
		...(name === "stdio-cli.mjs" ? ["tenant", "client", "server", "TEST_MCP_TOKEN"] : [])];
	return { args, observer, options: { env: { ...process.env, HOME: home, AIDR_COMMERCIAL: "0", TEST_MCP_TOKEN: token,
		AIDR_TEST_OBSERVER: observer, AIDR_TEST_GATEWAY_CONFIG: gatewayConfig, AIDR_TEST_INSTALLED_CONFIG: installedConfig,
		...extraEnv }, encoding: "utf8", timeout: 10000 } };
}
function observed(path) { return existsSync(path) ? readFileSync(path, "utf8").trim().split("\n") : []; }
async function startChild(name, extraEnv) {
	const prepared = childOptions(name, extraEnv);
	await rm(prepared.observer, { force: true });
	const child = spawn(process.execPath, prepared.args, prepared.options);
	let stdout = "", stderr = "";
	child.stderr.on("data", (value) => { stderr += value; });
	child.stdout.on("data", (value) => { stdout += value; });
	const closed = new Promise((resolve) => child.once("close", (code) => resolve({ code, stdout, stderr })));
	await new Promise((resolve, reject) => {
		const timer = setTimeout(() => { child.kill(); reject(new Error(`startup timeout: ${stderr}`)); }, 8000);
		const poll = setInterval(() => {
			if (observed(prepared.observer).includes("listen")) { clearTimeout(timer); clearInterval(poll); resolve(); }
		}, 10);
		child.once("exit", (code) => { clearTimeout(timer); clearInterval(poll); if (code !== null) reject(new Error(`startup exit ${code}: ${stderr}`)); });
	});
	return { child, closed, observer: prepared.observer, stdout: () => stdout };
}

for (const name of ["cli.mjs", "stdio-cli.mjs"]) {
	for (const [label, raw] of [["required", '{"privacy":{"required":true}}'], ["invalid JSON", "{"],
		["invalid required type", '{"privacy":{"required":"true"}}'], ["unknown privacy setting", '{"privacy":{"unknown":true}}']]) {
		test(`${name} refuses ${label} before gateway config, listen, network or stdin`, async () => {
			await profile(raw);
			const prepared = childOptions(name);
			await rm(prepared.observer, { force: true });
			const result = spawnSync(process.execPath, prepared.args, prepared.options);
			assert.equal(result.status, 1, result.stderr);
			assert.deepEqual(observed(prepared.observer), []);
		});
	}
	test(`${name} refuses unreadable installed configuration before startup`, async () => {
		await profile(); await mkdir(installedConfig);
		const prepared = childOptions(name); await rm(prepared.observer, { force: true });
		const result = spawnSync(process.execPath, prepared.args, prepared.options);
		assert.equal(result.status, 1, result.stderr); assert.deepEqual(observed(prepared.observer), []);
	});
	test(`${name} rechecks after awaited gateway configuration read`, async () => {
		await profile("{}");
		const prepared = childOptions(name, { AIDR_TEST_CHANGE_ON_CONFIG: "1" });
		await rm(prepared.observer, { force: true });
		const result = spawnSync(process.execPath, prepared.args, prepared.options);
		assert.equal(result.status, 1, result.stderr); assert.deepEqual(observed(prepared.observer), ["gateway-config"]);
	});
	for (const [label, raw] of [["fresh install", undefined], ["ordinary local defaults", "{}"], ["optional privacy", '{"privacy":{"required":false}}']]) {
		test(`${name} preserves ${label} startup`, async () => {
			await profile(raw);
			if (name === "stdio-cli.mjs") {
				const prepared = childOptions(name); await rm(prepared.observer, { force: true });
				const result = spawnSync(process.execPath, prepared.args, { ...prepared.options, input: "" });
				assert.equal(result.status, 0, result.stderr); assert.ok(observed(prepared.observer).includes("listen"));
				assert.equal(observed(prepared.observer).includes("network"), false);
			} else {
				const running = await startChild(name);
				running.child.kill(); await running.closed;
				assert.equal(observed(running.observer).includes("network"), false);
			}
		});
	}
}

for (const [label, raw] of [["required", '{"privacy":{"required":true}}'], ["invalid", "{"]])
test(`running public CLI rejects a newly ${label} profile before request body or upstream I/O`, async () => {
	await profile("{}");
	const running = await startChild("cli.mjs");
	try {
		for (let count = 0; !running.stdout().includes("listening") && count < 100; count++) await new Promise((resolve) => setTimeout(resolve, 10));
		const port = Number(running.stdout().match(/127\.0\.0\.1:(\d+)/)?.[1]);
		assert.ok(port);
		await profile(raw);
		const response = await fetch(`http://127.0.0.1:${port}/mcp/server`, { method: "POST", headers: {
			authorization: `Bearer ${token}`, "content-type": "application/json",
		}, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });
		assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: "gateway_unavailable" });
		assert.equal(observed(running.observer).includes("body-read"), false);
		assert.equal(observed(running.observer).includes("network"), false);
	} finally { running.child.kill(); await running.closed; }
});

test("running public stdio CLI rechecks its profile before parsing and releasing another frame", async () => {
	await profile("{}");
	const running = await startChild("stdio-cli.mjs");
	try {
		await profile('{"privacy":{"required":true}}');
		running.child.stdin.end("{\n");
		const result = await running.closed;
		assert.equal(result.code, 1, result.stderr); assert.equal(result.stdout, "");
		assert.equal(observed(running.observer).includes("network"), false);
	} finally { running.child.kill(); await running.closed; }
});

async function withRuntime(action) {
	const previousHome = process.env.HOME;
	process.env.HOME = home;
	await profile("{}");
	const config = fixtureConfig();
	let calls = 0;
	const dependencies = { assertInstalledPrivacySupported: runtime.requireStandaloneProfile,
		toolGuard: runtime.standalonePayloadGuard, outputGuard: runtime.standalonePayloadGuard,
		lookup: async () => ["8.8.8.8"], storeFactory: () => new runtime.MemoryMcpAttestationStore(),
		pinnedFetch: async ({ init }) => {
			calls++; const rpc = JSON.parse(init.body);
			const result = rpc.method === "tools/list" ? { tools: [{ name: "search", description: "Search", inputSchema: { type: "object" } }] }
				: { content: [{ type: "text", text: "controlled result" }] };
			return new Response(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }), { headers: { "content-type": "application/json" } });
		} };
	let gateway;
	try { await action({ config, dependencies, create: () => (gateway = runtime.createMcpGateway(config, dependencies)), calls: () => calls }); }
	finally { if (gateway) await gateway.close(); if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome; }
}
async function request(gateway, rpc) {
	const response = await fetch(`http://127.0.0.1:${gateway.address.port}/mcp/server`, { method: "POST", headers: {
		authorization: `Bearer ${token}`, "content-type": "application/json",
	}, body: JSON.stringify(rpc) });
	return response.json();
}
async function ready(gateway) {
	gateway.address = await gateway.listen();
	await request(gateway, { jsonrpc: "2.0", id: 0, method: "ping" });
	const state = await gateway.storeFor("tenant").read("server");
	await gateway.approve({ tenantId: "tenant", serverId: "server", toolsetHash: runtime.mcpToolsetHash(gateway.config.servers[0].signedManifest.manifest.tools),
		bindingSha256: state.quarantine.bindingSha256, approvedBy: "test operator", reason: "synthetic controlled test" });
}
test("source-alias standalone guards preserve a complete normal local tool request and result", async () => withRuntime(async (f) => {
	const gateway = f.create(); await ready(gateway);
	const reply = await request(gateway, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search", arguments: {} } });
	assert.deepEqual(reply.result, { content: [{ type: "text", text: "controlled result" }] });
	assert.equal(f.calls(), 2);
}));
test("source-alias gateway rechecks immediately before transport after its input guard awaited", async () => withRuntime(async (f) => {
	f.dependencies.toolGuard = async () => { await profile('{"privacy":{"required":true}}'); return { allowed: true, coverage: "full" }; };
	const gateway = f.create(); await ready(gateway);
	const reply = await request(gateway, { jsonrpc: "2.0", id: 1, method: "tools/list" });
	assert.ok(reply.error); assert.equal(f.calls(), 0);
}));
test("source-alias startup rechecks between negative routing probes without a payload guard", async () => withRuntime(async (f) => {
	f.config.routingRequired = true;
	f.config.servers[0].upstreamAuthEnv = "TEST_STANDALONE_UPSTREAM";
	f.config.servers[0].pinnedAddresses = ["8.8.8.8"];
	f.config.clients[0].probeTokenEnv = "TEST_STANDALONE_CLIENT";
	const previousUpstream = process.env.TEST_STANDALONE_UPSTREAM, previousClient = process.env.TEST_STANDALONE_CLIENT;
	process.env.TEST_STANDALONE_UPSTREAM = "u".repeat(48); process.env.TEST_STANDALONE_CLIENT = token;
	let probes = 0;
	f.dependencies.pinnedFetch = async () => { probes++; await profile('{"privacy":{"required":true}}'); return new Response(null, { status: 401 }); };
	try { await assert.rejects(f.create().listen(), /standalone_privacy_unavailable/); assert.equal(probes, 1); }
	finally {
		if (previousUpstream === undefined) delete process.env.TEST_STANDALONE_UPSTREAM; else process.env.TEST_STANDALONE_UPSTREAM = previousUpstream;
		if (previousClient === undefined) delete process.env.TEST_STANDALONE_CLIENT; else process.env.TEST_STANDALONE_CLIENT = previousClient;
	}
}));
test("source-alias gateway does not send raw session cleanup after an upstream await changes the profile", async () => withRuntime(async (f) => {
	const methods = [];
	f.dependencies.pinnedFetch = async ({ init }) => {
		methods.push(init.method); const rpc = JSON.parse(init.body);
		await profile('{"privacy":{"required":true}}');
		return new Response(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { protocolVersion: "2025-03-26", capabilities: {}, serverInfo: { name: "test", version: "1" } } }),
			{ headers: { "content-type": "application/json", "mcp-session-id": "session-12345678" } });
	};
	const gateway = f.create(); await ready(gateway);
	const reply = await request(gateway, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "test", version: "1" } } });
	assert.ok(reply.error); assert.deepEqual(methods, ["POST"]);
}));
test("source-alias gateway withholds successful result after the final awaited audit changes the profile", async () => withRuntime(async (f) => {
	let change = false;
	f.dependencies.onEvent = async (event) => { if (change && event.decision === "allow") await profile('{"privacy":{"required":true}}'); };
	const gateway = f.create(); await ready(gateway); change = true;
	const reply = await request(gateway, { jsonrpc: "2.0", id: 1, method: "tools/list" });
	assert.ok(reply.error); assert.equal(Object.hasOwn(reply, "result"), false); assert.equal(f.calls(), 1);
}));
test("private library host remains usable with required profile and its own full guards", async () => withRuntime(async (f) => {
	await profile('{"privacy":{"required":true}}');
	delete f.dependencies.assertInstalledPrivacySupported;
	f.dependencies.toolGuard = f.dependencies.outputGuard = async () => ({ allowed: true, coverage: "full", opaqueInspected: false });
	const gateway = f.create(); await ready(gateway);
	const reply = await request(gateway, { jsonrpc: "2.0", id: 1, method: "tools/list" });
	assert.ok(reply.result); assert.equal(f.calls(), 1);
}));

test("stdio source bridge withholds a loopback reply if profile changes while it awaits", async () => withRuntime(async (f) => {
	const chunks = [];
	const gateway = { config: { ...f.config, maxBodyBytes: 4096 }, listen: async () => ({ port: 12345 }), close: async () => {} };
	await assert.rejects(runtime.runStdioBridge({ gateway, tenantId: "tenant", clientId: "client", serverId: "server", tokenEnv: "TEST_MCP_TOKEN",
		environment: { TEST_MCP_TOKEN: token }, assertInstalledPrivacySupported: runtime.requireStandaloneProfile,
		input: Readable.from(['{"jsonrpc":"2.0","id":1,"method":"ping"}\n']),
		output: new Writable({ write(chunk, _encoding, callback) { chunks.push(String(chunk)); callback(); } }),
		fetchImpl: async () => { await profile('{"privacy":{"required":true}}'); return new Response('{"jsonrpc":"2.0","id":1,"result":{}}'); },
	}), /standalone_privacy_unavailable/);
	assert.deepEqual(chunks, []);
}));

async function runWithConfig(name, config, extraEnv = {}) {
	const path = join(root, `${name}-variant.json`);
	await writeFile(path, JSON.stringify(config));
	const prepared = childOptions(name, extraEnv);
	prepared.args[prepared.args.indexOf(gatewayConfig)] = path;
	return spawnSync(process.execPath, prepared.args, { ...prepared.options, input: "" });
}

test("public gateway CLI refuses an expired signed manifest with a precise reason and never reports listening", async () => {
	await profile("{}");
	const config = fixtureConfig();
	const keys = generateKeyPairSync("ed25519");
	config.servers[0].signedManifest = runtime.signMcpToolManifest({ keyId: "publisher", privateKey: keys.privateKey, manifest: {
		...config.servers[0].signedManifest.manifest, issued_at: new Date(Date.now() - 2 * 86400000).toISOString(),
		expires_at: new Date(Date.now() - 86400000).toISOString() } });
	config.servers[0].trustedSigners = { publisher: keys.publicKey.export({ type: "spki", format: "pem" }).toString() };
	const result = await runWithConfig("cli.mjs", config);
	assert.equal(result.status, 1, result.stderr);
	assert.match(result.stderr, /AIDR MCP gateway failed: startup_failed:manifest_expired\n/);
	assert.doesNotMatch(result.stdout, /listening/);
});

test("public stdio CLI warns about its isolation limits and can refuse an upstream credential", async () => {
	await profile("{}");
	const upstream = "u".repeat(48);
	const warned = await runWithConfig("stdio-cli.mjs", fixtureConfig({ upstreamAuthEnv: "TEST_STDIO_UPSTREAM" }),
		{ TEST_STDIO_UPSTREAM: upstream });
	assert.equal(warned.status, 0, warned.stderr);
	assert.match(warned.stderr, /not a credential-isolation or approval boundary/);
	assert.match(warned.stderr, /upstreamAuthEnv is set/);
	assert.equal(warned.stderr.includes(upstream), false);

	const refused = await runWithConfig("stdio-cli.mjs",
		{ ...fixtureConfig({ upstreamAuthEnv: "TEST_STDIO_UPSTREAM" }), stdioUpstreamCredentials: "refuse" },
		{ TEST_STDIO_UPSTREAM: upstream });
	assert.equal(refused.status, 1, refused.stderr);
	assert.match(refused.stderr, /AIDR MCP stdio bridge failed: stdio_isolation_refused:stdio_upstream_credential_refused\n/);
});
