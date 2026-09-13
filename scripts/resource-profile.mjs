#!/usr/bin/env node
// Isolated local resource snapshot; no credentials, raw payloads or host paths are emitted.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { availableParallelism, cpus, tmpdir, totalmem } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { performance } from "node:perf_hooks";

function fail(message) { throw new Error(message); }
function args(argv) {
	const result = { samples: 3, hookIterations: 10, edgeIterations: 5, skipImageSize: false, imageInventoryOnly: false };
	for (let i = 0; i < argv.length; i += 1) {
		const token = argv[i];
		if (token === "--deployment") result.deployment = argv[++i];
		else if (token === "--output") result.output = argv[++i];
		else if (token === "--connector-package") result.connectorPackage = argv[++i];
		else if (token === "--samples") result.samples = Number(argv[++i]);
		else if (token === "--hook-iterations") result.hookIterations = Number(argv[++i]);
		else if (token === "--edge-iterations") result.edgeIterations = Number(argv[++i]);
		else if (token === "--skip-image-size") result.skipImageSize = true;
		else if (token === "--image-inventory-only") result.imageInventoryOnly = true;
		else if (token === "--help" || token === "-h") result.help = true;
		else fail(`Unknown argument: ${token}`);
	}
	if (result.help) return result;
	if (!result.deployment || !result.output) fail("--deployment and --output are required");
	for (const [key, max] of [["samples", 20], ["hookIterations", 100], ["edgeIterations", 50]]) {
		if (!Number.isInteger(result[key]) || result[key] < 1 || result[key] > max) fail(`Invalid ${key}`);
	}
	return result;
}
function docker(...argv) {
	const result = spawnSync("docker", argv, { encoding: "utf8", timeout: 90000, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
	if (result.error || result.status !== 0) fail(`Docker command failed: ${argv[0]} (${result.error?.code ?? result.status})`);
	return result.stdout.trim();
}
function sha(path) { return createHash("sha256").update(readFileSync(path)).digest("hex"); }
function q(values, fraction) {
	const sorted = [...values].sort((a, b) => a - b);
	return sorted.length ? sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] : null;
}
function size(input) {
	const match = /^([0-9.]+)\s*([kKmMgGtT]?i?[bB])$/.exec(input.trim());
	if (!match) fail("Unsupported Docker size unit");
	const power = { B: 0, kB: 1, KB: 1, KiB: 1, MB: 2, MiB: 2, GB: 3, GiB: 3, TB: 4, TiB: 4 }[match[2]];
	if (power === undefined) fail("Unsupported Docker size unit");
	return Math.round(Number(match[1]) * (match[2].includes("i") ? 1024 : 1000) ** power);
}
function treeBytes(path) {
	let total = 0;
	for (const entry of readdirSync(path, { withFileTypes: true })) {
		const child = join(path, entry.name);
		if (entry.isSymbolicLink()) fail("Connector artifact contains a symlink");
		total += entry.isDirectory() ? treeBytes(child) : statSync(child).size;
	}
	return total;
}
function volumeKiB(container, path) {
	const raw = docker("exec", container, "du", "-sk", path);
	const match = /^(\d+)\s/.exec(raw);
	if (!match) fail("Unexpected volume size output");
	return Number(match[1]);
}
function parseStat(raw, project) {
	const stat = JSON.parse(raw);
	if (!stat.Name?.startsWith(`${project}-`) || !stat.Name.endsWith("-1")) fail("Unexpected Docker project in stats");
	const service = stat.Name.slice(project.length + 1, -2);
	const [memoryUsed] = stat.MemUsage.split("/");
	const [networkRx, networkTx] = stat.NetIO.split("/");
	const [blockRead, blockWrite] = stat.BlockIO.split("/");
	return { service, cpu_percent_of_one_core: Number.parseFloat(stat.CPUPerc), memory_bytes: size(memoryUsed), network_rx_bytes_cumulative: size(networkRx), network_tx_bytes_cumulative: size(networkTx), block_read_bytes_cumulative: size(blockRead), block_write_bytes_cumulative: size(blockWrite), pids: Number(stat.PIDs) };
}
function imageSizes(project, names) {
	const running = docker("ps", "--filter", `label=com.docker.compose.project=${project}`, "--format", "{{.Names}}|{{.Image}}").split(/\r?\n/).filter(Boolean).map((line) => line.split("|"));
	if (running.length !== names.length || running.some(([name, image]) => !names.includes(name) || !image)) fail("Image inventory does not match project containers");
	const imageByContainer = new Map(running);
	const imageNames = names.map((name) => imageByContainer.get(name));
	const rawSizes = docker("image", "inspect", "--format", "{{.Size}}", ...imageNames).split(/\r?\n/);
	if (rawSizes.length !== names.length) fail("Image sizes missing");
	const sizes = names.map((name, index) => {
		const bytes = Number(rawSizes[index]);
		if (!Number.isSafeInteger(bytes) || bytes < 0) fail("Invalid image size");
		return { service: name.slice(project.length + 1, -2), image_uncompressed_virtual_bytes: bytes };
	});
	return { by_service: sizes.sort((a, b) => a.service.localeCompare(b.service)), sum_virtual_bytes_upper_bound: sizes.reduce((sum, row) => sum + row.image_uncompressed_virtual_bytes, 0), note: "Uncompressed virtual image sizes double count shared layers; actual local image storage is lower or equal and includes Docker metadata" };
}
function snapshot(project, names) {
	const raw = docker("stats", "--no-stream", "--format", "{{json .}}");
	const services = raw.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line)).filter((row) => names.includes(row.Name)).map((row) => parseStat(JSON.stringify(row), project)).sort((a, b) => a.service.localeCompare(b.service));
	if (services.length !== names.length) fail("Missing Docker stats row");
	return { at: new Date().toISOString(), services, total_memory_bytes: services.reduce((sum, row) => sum + row.memory_bytes, 0), total_cpu_percent_of_one_core: services.reduce((sum, row) => sum + row.cpu_percent_of_one_core, 0) };
}
function percentiles(values) { return { min: Math.min(...values), p50: q(values, 0.5), p95: q(values, 0.95), max: Math.max(...values) }; }
function benchHook(iterations, tempRoot, connectorPackage) {
	const hook = join(connectorPackage, "dist/pre-tool-use.cjs");
	const preload = resolve("scripts/resource-profile-preload.cjs");
	if (!existsSync(hook) || !existsSync(preload)) fail("Built Claude hook or preload is missing");
	const payload = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "resource-profile-local", tool_name: "Bash", tool_input: { command: "ls -la" } });
	const baseEnv = { ...process.env, HOME: tempRoot, USERPROFILE: tempRoot, AIDR_THREATS_DIR: join(connectorPackage, "resources/threats"), AIDR_ALLOWLISTS_DIR: join(connectorPackage, "resources/allowlists") };
	const wall = [];
	let responseBytes = null;
	for (let i = 0; i < iterations; i += 1) {
		const started = performance.now();
		const result = spawnSync(process.execPath, [hook], { input: payload, encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024, windowsHide: true, env: baseEnv });
		wall.push(Math.round((performance.now() - started) * 1000) / 1000);
		if (result.error || result.status !== 0 || JSON.stringify(JSON.parse(result.stdout.trim())) !== "{}") fail("Local benign hook benchmark failed");
		responseBytes = Buffer.byteLength(result.stdout);
	}
	const rss = [];
	for (let i = 0; i < Math.min(iterations, 5); i += 1) {
		const output = join(tempRoot, `rss-${i}.txt`);
		const result = spawnSync(process.execPath, ["--require", preload, hook], { input: payload, encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024, windowsHide: true, env: { ...baseEnv, AIDR_RESOURCE_RSS_OUTPUT: output } });
		if (result.error || result.status !== 0 || !existsSync(output)) fail("Instrumented hook benchmark failed");
		rss.push(Number(readFileSync(output, "utf8")));
	}
	return { scope: "fresh Node process, benign local Bash evaluation, no control-plane request", input_bytes: Buffer.byteLength(payload), output_bytes: responseBytes, first_process_wall_ms: wall[0], subsequent_process_wall_ms: iterations > 1 ? percentiles(wall.slice(1)) : null, wall_ms: percentiles(wall), diagnostic_peak_rss_bytes: percentiles(rss), diagnostic_note: "RSS includes the diagnostic preload; this is per active hook process, not idle resident memory", connector_installed_files_bytes: treeBytes(join(connectorPackage, "resources")) + treeBytes(join(connectorPackage, "dist")) + statSync(join(connectorPackage, "package.json")).size, hook_sha256: sha(hook), runs: iterations };
}
function readAnonKey(envPath) {
	const raw = readFileSync(envPath, "utf8");
	const match = /^ANON_KEY=(.+)$/m.exec(raw);
	if (!match) fail("Deployment ANON_KEY missing");
	return match[1].trim();
}
async function benchHttp(base, path, iterations, options = {}) {
	const durations = [];
	const statuses = {};
	const responses = [];
	let transportErrors = 0;
	for (let i = 0; i < iterations; i += 1) {
		const started = performance.now();
		try {
			const response = await fetch(new URL(path, base), { method: options.method ?? "GET", headers: options.headers ?? {}, body: options.body, signal: AbortSignal.timeout(5000) });
			const body = await response.arrayBuffer();
			durations.push(Math.round((performance.now() - started) * 1000) / 1000);
			statuses[response.status] = (statuses[response.status] ?? 0) + 1;
			responses.push(body.byteLength);
		} catch {
			transportErrors += 1;
		}
	}
	return { requests: iterations, completed: durations.length, transport_errors: transportErrors, request_timeout_ms: 5000, method: options.method ?? "GET", request_body_bytes: Buffer.byteLength(options.body ?? ""), response_body_bytes: responses.length ? percentiles(responses) : null, status_counts: statuses, wall_ms: durations.length ? percentiles(durations) : null, excluded_from_bytes: "HTTP headers, TLS framing, retries and transport overhead" };
}
function scenarioModel() {
	const eventBytes = 2048, policyBytes = 4096, optimizedIngestBatch = 20, dbMultiplier = 3, retentionDays = 90, peakFactor = 10;
	return { assumptions: { event_payload_bytes: eventBytes, policy_exchange_bytes: policyBytes, optimized_ingest_batch_events: optimizedIngestBatch, indexed_db_and_wal_multiplier: dbMultiplier, retention_days: retentionDays, peak_to_average_factor: peakFactor, policy_cache_seconds: 30, notes: "Planning assumptions; event size and DB multiplier must be replaced by field measurements. Clean verdicts are disabled by default. Current per-verdict flush often sends one event per ingest call; optimized batching is only a lower bound." }, scenarios: [
		{ label: "pilot", endpoints: 10, tool_calls_per_endpoint_day: 100, active_minutes_per_endpoint_day: 30, recorded_events_per_endpoint_day: 10 },
		{ label: "department", endpoints: 100, tool_calls_per_endpoint_day: 200, active_minutes_per_endpoint_day: 60, recorded_events_per_endpoint_day: 20 },
		{ label: "enterprise", endpoints: 1000, tool_calls_per_endpoint_day: 400, active_minutes_per_endpoint_day: 180, recorded_events_per_endpoint_day: 40 },
	].map((x) => {
		const policyRequests = x.endpoints * Math.min(x.tool_calls_per_endpoint_day, x.active_minutes_per_endpoint_day * 60 / 30);
		const events = x.endpoints * x.recorded_events_per_endpoint_day;
		const ingestRequestsLowerBound = Math.ceil(events / optimizedIngestBatch);
		const ingestRequestsTypical = events;
		const dailyAppBytes = events * eventBytes + policyRequests * policyBytes;
		return { ...x, policy_requests_day_upper_bound: policyRequests, recorded_events_day_assumed: events, ingest_requests_day_lower_bound_if_batched: ingestRequestsLowerBound, ingest_requests_day_typical_unbatched: ingestRequestsTypical, edge_invocations_day_lower_bound_for_these_routes: policyRequests + ingestRequestsLowerBound, edge_invocations_day_typical_for_these_routes: policyRequests + ingestRequestsTypical, edge_average_rps_typical: Math.round((policyRequests + ingestRequestsTypical) / 86400 * 100) / 100, edge_planning_peak_rps_typical: Math.ceil((policyRequests + ingestRequestsTypical) / 86400 * peakFactor), app_payload_bytes_day_estimate: dailyAppBytes, app_payload_gib_day_estimate: Math.round(dailyAppBytes / 1024 ** 3 * 100) / 100, database_live_bytes_estimate: events * eventBytes * dbMultiplier * retentionDays, database_live_gib_estimate: Math.round(events * eventBytes * dbMultiplier * retentionDays / 1024 ** 3 * 100) / 100 };
	}) };
}
async function main() {
	const a = args(process.argv.slice(2));
	if (a.help) { console.log("node scripts/resource-profile.mjs --deployment .release-evidence/aidr-install-v4 --output .release-evidence/resource-profile-local-20260912.json [--connector-package .release-evidence/aidr-customer-kit-20260912-v4/packages/claude-code] [--samples 3 --hook-iterations 10 --edge-iterations 5 --skip-image-size | --image-inventory-only]"); return; }
	const deployment = resolve(a.deployment), output = resolve(a.output);
	if (existsSync(output)) fail("Output exists; choose a fresh evidence path");
	const manifest = JSON.parse(readFileSync(join(deployment, "deployment.json"), "utf8"));
	const api = new URL(manifest.supabase_url), dashboard = new URL(manifest.dashboard_url);
	if (!manifest.development || manifest.mode !== "self-hosted" || !["localhost", "127.0.0.1", "::1"].includes(api.hostname) || !["localhost", "127.0.0.1", "::1"].includes(dashboard.hostname)) fail("Only isolated loopback self-hosted development installations may be profiled");
	if (!/^[a-z0-9][a-z0-9-]{2,80}$/.test(manifest.project_name)) fail("Invalid Compose project name");
	const project = manifest.project_name;
	const names = docker("ps", "--filter", `label=com.docker.compose.project=${project}`, "--format", "{{.Names}}").split(/\r?\n/).filter(Boolean).sort();
	if (names.length !== 11 || names.some((name) => !name.startsWith(`${project}-`) || !name.endsWith("-1"))) fail("Expected 11 running project containers");
	if (a.imageInventoryOnly) {
		const doc = { schema_version: 1, kind: "aidr_local_image_inventory", measured_at: new Date().toISOString(), project_services: names.length, compose_sha256: sha(join(deployment, "compose.yml")), images: imageSizes(project, names), limitations: ["Uncompressed virtual image sizes double count shared layers", "Docker Desktop image store includes other projects and was not attributed to this one", "This is not a production disk requirement"] };
		writeFileSync(output, `${JSON.stringify(doc, null, 2)}\n`, { flag: "wx", mode: 0o600 });
		console.log(`Image inventory written: ${basename(output)}; ${names.length} services.`);
		return;
	}
	const allRunning = docker("ps", "--format", "{{.Names}}").split(/\r?\n/).filter(Boolean).length;
	const snapshots = [];
	for (let i = 0; i < a.samples; i += 1) snapshots.push(snapshot(project, names));
	const containerFor = (service) => {
		const name = `${project}-${service}-1`;
		if (!names.includes(name)) fail(`Missing ${service}`);
		return name;
	};
	const volumes = { postgres_data_bytes: volumeKiB(containerFor("db"), "/var/lib/postgresql/data") * 1024, storage_data_bytes: volumeKiB(containerFor("storage"), "/var/lib/storage") * 1024, deno_cache_bytes: volumeKiB(containerFor("functions"), "/root/.cache/deno") * 1024, postgres_config_bytes: volumeKiB(containerFor("db"), "/etc/postgresql-custom") * 1024 };
	const images = a.skipImageSize ? { skipped: true, reason: "Run image sizing separately after service profile" } : imageSizes(project, names);
	const root = mkdtempSync(join(tmpdir(), "aidr-resource-profile-"));
	let hook;
	try { hook = benchHook(a.hookIterations, root, resolve(a.connectorPackage ?? "packages/claude-code")); }
	finally {
		const relativeToTemp = relative(resolve(tmpdir()), root);
		if (!relativeToTemp || relativeToTemp === ".." || relativeToTemp.startsWith(`..${sep}`) || resolve(root) === resolve(tmpdir())) fail("Refusing unsafe temporary directory deletion");
		rmSync(root, { recursive: true, force: true });
	}
	const anon = readAnonKey(join(deployment, ".env"));
	const edge = await benchHttp(api, "/functions/v1/url-check", a.edgeIterations, { method: "POST", headers: { apikey: anon, "content-type": "application/json" }, body: JSON.stringify({ queries: [{ key: { "url-like": "https://example.test/" } }] }) });
	const health = await benchHttp(dashboard, "/healthz", a.edgeIterations);
	const doc = { schema_version: 1, kind: "aidr_local_resource_profile", measured_at: new Date().toISOString(), scope: "single Windows Docker Desktop development host; shared with other containers and test agents; no customer workload or TLS", platform: process.platform, node: process.version, host_hardware: { logical_cpus: cpus().length, available_parallelism: availableParallelism(), physical_ram_bytes: totalmem() }, project_services: names.length, other_running_containers: Math.max(0, allRunning - names.length), deployment_manifest_sha256: sha(join(deployment, "deployment.json")), compose_sha256: sha(join(deployment, "compose.yml")), docker_snapshots: snapshots, docker_idle_memory_bytes: percentiles(snapshots.map((s) => s.total_memory_bytes)), docker_idle_cpu_percent_of_one_core: percentiles(snapshots.map((s) => s.total_cpu_percent_of_one_core)), volume_sizes: volumes, images, endpoint_hook: hook, http: { edge_unauthenticated_url_check: { ...edge, scope: "public anon gateway key and no endpoint bearer credential; auth rejection only, not an authenticated reputation lookup" }, dashboard_health: { ...health, scope: "loopback healthz, no UI rendering or database query" } }, planning_model: scenarioModel(), limitations: ["Docker memory is container current usage, not reservation or peak; Desktop VM/kernel/cache and reverse proxy are excluded", "Docker CPU samples reflect a shared developer host and cannot prove throughput", "Volume sizes are fresh fixture data; backups, logs, free-space headroom and migration growth are excluded", "The Edge HTTP sample is an unauthenticated rejection, not business-path cost", "No managed-cloud provider CPU, memory, invocation or pricing limits are inferred", "No native host, fleet, soak, failover or customer acceptance was measured"] };
	writeFileSync(output, `${JSON.stringify(doc, null, 2)}\n`, { flag: "wx", mode: 0o600 });
	console.log(`Resource profile written: ${basename(output)}; ${names.length} services; ${(doc.docker_idle_memory_bytes.p50 / 1024 ** 2).toFixed(1)} MiB median container memory. Scope: isolated loopback development only.`);
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
