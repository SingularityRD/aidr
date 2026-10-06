#!/usr/bin/env node
/** Real Codex tool dispatch against a deterministic loopback peer; no cloud model. */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const binary = process.argv[2];
const output = process.argv[3] && resolve(process.argv[3]);
assert.ok(binary && isAbsolute(binary) && existsSync(binary) && /codex\.exe$/i.test(binary), "Pass the installed absolute codex.exe path, optionally followed by a report JSON path.");
const sourceDist = join(root, "packages/codex/dist");
const sourceManifest = join(sourceDist, "aidr-artifact.manifest.json");
assert.ok(existsSync(sourceManifest), "Existing release Codex dist is required; this verifier never builds.");
const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const manifest = JSON.parse(readFileSync(sourceManifest, "utf8"));
assert.equal(manifest.artifact_id, "codex/dist");
assert.ok(Array.isArray(manifest.files) && manifest.files.some((entry) => entry.path === "pre-tool-use.cjs"));
function artifactSnapshot() {
	return Object.fromEntries(manifest.files.map((entry) => {
		const path = resolve(sourceDist, entry.path);
		const local = relative(sourceDist, path);
		assert.ok(local && local !== ".." && !local.startsWith(`..${sep}`) && !isAbsolute(local), "Manifest path escaped dist");
		const sha256 = hash(path);
		assert.equal(sha256, entry.sha256, `Release manifest mismatch: ${entry.path}`);
		return [entry.path, sha256];
	}));
}
const before = { executable: hash(binary), manifest: hash(sourceManifest), files: artifactSnapshot() };
const scratch = mkdtempSync(join(tmpdir(), "aidr-codex-offline-"));
function cleanupScratch() {
	if (!existsSync(scratch)) return;
	const canonical = realpathSync(scratch);
	assert.equal(dirname(canonical), realpathSync(tmpdir()));
	assert.ok(basename(canonical).startsWith("aidr-codex-offline-"));
	rmSync(canonical, { recursive: true, force: true });
}
process.on("exit", cleanupScratch);
const home = join(scratch, "home");
const codexHome = join(home, ".codex");
const workspace = join(scratch, "workspace");
const testDist = join(scratch, "dist");
for (const path of [codexHome, join(workspace, ".codex"), join(home, ".singularity-aidr")]) mkdirSync(path, { recursive: true });
cpSync(sourceDist, testDist, { recursive: true });
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
writeFileSync(join(testDist, "aidr-artifact.manifest.sig"), `${sign(null, readFileSync(sourceManifest), privateKey).toString("base64")}\n`);
writeFileSync(join(home, ".singularity-aidr", "config.json"), JSON.stringify({
	mode: "local", control_plane: { enabled: false },
	integrity: { enabled: true, verify_on_start: true, public_keys_pem: [publicKey.export({ type: "spki", format: "pem" }).toString()] },
	logging: { enabled: true, path: join(home, ".singularity-aidr", "audit.jsonl") },
}));
const hook = join(testDist, "pre-tool-use.cjs");
// This fixture relay records the real host payload and exact hook wire response.
// It never creates the tested sentinel and forwards the hook bytes unchanged.
const relay = join(scratch, "capture-hook.cjs");
writeFileSync(relay, `const {spawnSync}=require('node:child_process');const {readFileSync,appendFileSync}=require('node:fs');
const input=readFileSync(0,'utf8');const result=spawnSync(${JSON.stringify(process.execPath)},[${JSON.stringify(hook)}],{input,encoding:'utf8',env:process.env,timeout:8000,windowsHide:true});
appendFileSync(process.env.AIDR_NATIVE_WIRE_RECEIPT,JSON.stringify({nonce:process.env.AIDR_NATIVE_TEST_CASE_NONCE,input:JSON.parse(input),stdout:result.stdout,stderr:result.stderr,status:result.status,error:result.error?.code})+'\\n');
process.stdout.write(result.stdout||'');process.stderr.write(result.stderr||'');process.exit(result.status??1);
`);
// This is the documented project registration and Windows command override.
// PowerShell needs '&' when the executable's absolute path is quoted.
const hookCommand = `"${process.execPath}" "${relay}"`;
writeFileSync(join(workspace, ".codex", "hooks.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "^apply_patch$", hooks: [{
	type: "command", command: hookCommand, commandWindows: `& ${hookCommand}`, timeout: 10,
}] }] } }));
function environment() {
	const env = Object.fromEntries(["SystemRoot", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP"].filter((key) => process.env[key] !== undefined).map((key) => [key, process.env[key]]));
	return { ...env, HOME: home, USERPROFILE: home, CODEX_HOME: codexHome,
		APPDATA: join(home, "AppData/Roaming"), LOCALAPPDATA: join(home, "AppData/Local"),
		XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local/share"), XDG_CACHE_HOME: join(home, ".cache"), XDG_STATE_HOME: join(home, ".local/state"),
		HTTP_PROXY: "http://127.0.0.1:1", HTTPS_PROXY: "http://127.0.0.1:1", ALL_PROXY: "http://127.0.0.1:1", NO_PROXY: "127.0.0.1,localhost",
		DO_NOT_TRACK: "1", CI: "1", NO_COLOR: "1",
	};
}
const versionProbe = spawnSync(binary, ["--version"], { env: environment(), encoding: "utf8", windowsHide: true, timeout: 10_000 });
assert.equal(versionProbe.status, 0, "Installed Codex version probe failed");
const scenarios = [
	{ id: "env-path", file: ".env", content: "AIDR_DEMO_SENTINEL=synthetic-only\n", blocked: true },
	{ id: "benign", file: "safe-note.txt", content: "AIDR offline benign fixture\n", blocked: false },
];
let scenario;
let providerCalls = 0;
let dispatchedCall;
let dispatchedPatch;
let providerToolResult;
const provider = createServer(async (request, response) => {
	try {
		if (request.method !== "POST" || request.url !== "/v1/responses") { response.writeHead(404).end(); return; }
		let raw = "";
		for await (const chunk of request) { raw += chunk; if (raw.length > 2_000_000) { response.writeHead(413).end(); return; } }
		const body = JSON.parse(raw);
		assert.equal(request.headers.authorization, undefined, "Offline peer must receive no authentication credential");
		assert.equal(body.model, "gpt-5.5");
		assert.equal(body.stream, true);
		providerCalls++;
		assert.ok(providerCalls <= 2, "Fixture refused unexpected model retries");
		const prior = body.input?.find((item) => ["function_call_output", "custom_tool_call_output"].includes(item.type) && item.call_id === dispatchedCall);
		assert.ok(providerCalls === 1 || prior, "Fixture refused to dispatch more than one patch per case");
		if (prior) providerToolResult = prior.output;
		const tool = body.tools?.find((item) => item.name === "apply_patch");
		assert.ok(tool, "Actual Codex did not advertise apply_patch");
		const patch = `*** Begin Patch\n*** Add File: ${scenario.file}\n${scenario.content.trimEnd().split("\n").map((line) => `+${line}`).join("\n")}\n*** End Patch`;
		const callId = `call_aidr_${scenario.id}`;
		const item = prior ? { id: `msg_${scenario.id}`, type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: "Fixture complete.", annotations: [] }] } :
			tool.type === "custom" ? { id: `ctc_${scenario.id}`, type: "custom_tool_call", call_id: callId, name: "apply_patch", input: patch, status: "completed" } :
				{ id: `fc_${scenario.id}`, type: "function_call", call_id: callId, name: "apply_patch", arguments: JSON.stringify({ command: patch }), status: "completed" };
		if (!prior) { dispatchedCall = callId; dispatchedPatch = patch; }
		response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
		const emit = (type, data) => response.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
		const envelope = { id: `resp_${scenario.id}_${providerCalls}`, object: "response", created_at: 1, status: "in_progress", output: [] };
		emit("response.created", { response: envelope });
		emit("response.output_item.added", { output_index: 0, item: { ...item, status: "in_progress" } });
		emit("response.output_item.done", { output_index: 0, item });
		emit("response.completed", { response: { ...envelope, status: "completed", output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } });
		response.end();
	} catch (error) { response.writeHead(400).end(JSON.stringify({ error: { message: error.message } })); }
});
async function runHost(item) {
	const nonce = randomUUID();
	const receipt = join(workspace, `hook-${nonce}.jsonl`);
	const wireReceipt = join(workspace, `wire-${nonce}.jsonl`);
	// Windows' unconfigured sandbox rejects writes before hooks. This isolated,
	// hardcoded single-patch peer deliberately tests the hook, not that sandbox.
	const child = spawn(binary, ["exec", "--sandbox", "danger-full-access", "--dangerously-bypass-hook-trust", "--skip-git-repo-check", "--ephemeral", "--ignore-rules", "--json", "--color", "never", "-C", workspace, `AIDR offline ${item.id} fixture`], {
		cwd: workspace, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], env: { ...environment(), AIDR_NATIVE_TEST_WORKSPACE: workspace, AIDR_NATIVE_TEST_RECEIPT: receipt, AIDR_NATIVE_TEST_CASE_NONCE: nonce, AIDR_NATIVE_WIRE_RECEIPT: wireReceipt },
	});
	let stdout = "", stderr = "", timedOut = false;
	child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
	child.stdout.on("data", (chunk) => { stdout = (stdout + chunk).slice(-1_000_000); });
	child.stderr.on("data", (chunk) => { stderr = (stderr + chunk).slice(-100_000); });
	const timer = setTimeout(() => { timedOut = true; child.kill(); }, 30_000);
	let code;
	try { code = await new Promise((done, reject) => { child.once("error", reject); child.once("close", done); }); } finally { clearTimeout(timer); }
	const lines = (path) => existsSync(path) ? readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line)) : [];
	return { code, timedOut, stdout, stderr, nonce, hookObservations: lines(receipt), wireObservations: lines(wireReceipt) };
}
const results = [];
let failure;
let featureProbe;
try {
	await new Promise((done) => provider.listen(0, "127.0.0.1", done));
	writeFileSync(join(codexHome, "config.toml"), `model = "gpt-5.5"\nmodel_provider = "aidr-local"\ncli_auth_credentials_store = "file"\ncheck_for_update_on_startup = false\nweb_search = "disabled"\n[features]\nhooks = true\n[sandbox_workspace_write]\nnetwork_access = false\n[model_providers.aidr-local]\nname = "AIDR offline fixture"\nbase_url = "http://127.0.0.1:${provider.address().port}/v1"\nwire_api = "responses"\nrequires_openai_auth = false\nsupports_websockets = false\nrequest_max_retries = 0\nstream_max_retries = 0\n[projects.${JSON.stringify(workspace)}]\ntrust_level = "trusted"\n`);
	featureProbe = spawnSync(binary, ["features", "list"], { cwd: workspace, env: environment(), encoding: "utf8", timeout: 10_000, windowsHide: true });
	for (const item of scenarios) {
		scenario = item; providerCalls = 0; dispatchedCall = null; providerToolResult = null;
		const result = await runHost(item);
		const record = { id: item.id, expected_block: item.blocked, provider_calls: providerCalls, provider_tool_result: providerToolResult, ...result, status: "FAIL" };
		results.push(record);
		assert.equal(result.timedOut, false, `${item.id}: native host timed out`);
		assert.equal(result.code, 0, `${item.id}: native host failed: ${result.stderr}`);
		assert.ok(providerCalls >= 2 && providerToolResult !== null, `${item.id}: no native tool result returned to loopback peer (${result.stdout}; ${result.stderr})`);
		const observed = result.hookObservations.find((entry) => entry.nonce === result.nonce && entry.connector === "codex" && entry.event === "PreToolUse" && entry.toolName === "apply_patch");
		const wire = result.wireObservations.find((entry) => entry.nonce === result.nonce && entry.input.tool_name === "apply_patch");
		assert.ok(observed && wire, `${item.id}: current AIDR hook not observed for real native apply_patch`);
		assert.equal(wire.input.tool_use_id, dispatchedCall, "Hook payload did not bind to the requested native tool");
		assert.equal(wire.input.tool_input?.command, dispatchedPatch, "Native hook did not receive the exact controlled patch");
		assert.equal(wire.status, 0, `${item.id}: hook failed rather than returning an explicit decision`);
		if (item.blocked) {
			assert.ok(["deny", "ask"].includes(observed.decision));
			assert.equal(JSON.parse(wire.stdout).hookSpecificOutput?.permissionDecision, "deny");
			assert.match(String(providerToolResult), /Singularity AIDR/i);
			assert.equal(existsSync(join(workspace, item.file)), false, "Blocked native patch reached disk");
		} else {
			assert.equal(observed.decision, "allow"); assert.equal(wire.stdout, "");
			assert.equal(readFileSync(join(workspace, item.file), "utf8"), item.content, "Benign native patch did not execute");
		}
		record.status = "PASS";
		console.log(`PASS ${item.id}: real Codex apply_patch; ${item.blocked ? "AIDR denial and absent file" : "exact benign file"}`);
	}
} catch (error) { failure = error.message; process.exitCode = 1; console.error(failure); }
finally {
	provider.closeAllConnections(); provider.close();
	try { assert.deepEqual({ executable: hash(binary), manifest: hash(sourceManifest), files: artifactSnapshot() }, before, "Source release/host bytes changed during acceptance"); } catch (error) { failure = error.message; process.exitCode = 1; console.error(failure); }
	const report = { schema_version: 1, kind: "aidr-codex-offline-native", measured_at: new Date().toISOString(), host_version: versionProbe.stdout.trim(), host_path: binary,
		hook_registration: "Documented trusted project .codex/hooks.json in a fresh disposable workspace, commandWindows override",
		feature_probe: { status: featureProbe?.status, stdout: featureProbe?.stdout, stderr: featureProbe?.stderr },
		source_commit: spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).stdout.trim(), source_sha256: hash(fileURLToPath(import.meta.url)), inputs: before,
		workspace_dirty: Boolean(spawnSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).stdout.trim()),
		status: failure ? "FAIL" : "PASS", failure: failure ?? null, expected: scenarios.length, passed: results.filter((item) => item.status === "PASS").length,
		results, limitations: ["Deterministic loopback peer exercises the real CLI tool dispatcher; no model intelligence or remote inference was tested.", "Temporary artifact signing key and explicit hook-trust/sandbox bypass apply only to the isolated single-patch fixture; production signature/trust/sandbox acceptance remains open.", "These two apply_patch cases do not cover host hook crash/timeout behavior or the supported host/version/OS matrix."] };
	if (output) { mkdirSync(dirname(output), { recursive: true }); writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`); console.log(`Report: ${output}`); }
	cleanupScratch();
}
