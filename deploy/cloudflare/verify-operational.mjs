#!/usr/bin/env node
import { pathToFileURL } from "node:url";

const MAX_RESPONSE_BYTES = 2048;
const TIMEOUT_MS = 5000;

function origin(value) {
	const url = new URL(value);
	if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
		throw new Error("--base-url must be an HTTPS origin");
	}
	return url.origin;
}

async function jsonProbe(base, path, fetchImpl) {
	const url = `${base}${path}`;
	const response = await fetchImpl(url, {
		redirect: "manual",
		headers: { "cache-control": "no-cache" },
		signal: AbortSignal.timeout(TIMEOUT_MS),
	});
	if (response.url && response.url !== url) throw new Error(`${path} redirected`);
	if (!response.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new Error(`${path} did not return JSON`);
	if (!response.headers.get("cache-control")?.toLowerCase().includes("no-store")) throw new Error(`${path} may be cached`);
	const declared = response.headers.get("content-length");
	if (declared && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) throw new Error(`${path} response is oversized`);
	if (!response.body) throw new Error(`${path} returned no body`);
	let size = 0;
	const chunks = [];
	for await (const chunk of response.body) {
		size += chunk.byteLength;
		if (size > MAX_RESPONSE_BYTES) throw new Error(`${path} response is oversized`);
		chunks.push(chunk);
	}
	let body;
	try { body = JSON.parse(Buffer.concat(chunks, size).toString("utf8")); }
	catch { throw new Error(`${path} returned invalid JSON`); }
	return { status: response.status, body };
}

function exactBody(actual, expected) {
	return actual && !Array.isArray(actual) && typeof actual === "object" &&
		Object.keys(actual).length === Object.keys(expected).length &&
		Object.entries(expected).every(([key, value]) => actual[key] === value);
}

function readinessBody(actual) {
	const names = ["auth", "database", "storage", "functions", "signing", "backup", "queue", "certificate"];
	return actual && !Array.isArray(actual) && typeof actual === "object" && Object.keys(actual).length === 3 &&
		actual.status === "not_ready" && actual.component === "cloud-control-plane" &&
		actual.checks && !Array.isArray(actual.checks) && typeof actual.checks === "object" &&
		Object.keys(actual.checks).length === names.length && names.every((name) =>
			["auth", "database", "storage", "functions"].includes(name)
				? ["reachable", "failed"].includes(actual.checks[name])
				: actual.checks[name] === "unverified");
}

export async function verifyCloudflareOperational({ baseUrl, expectedVersion, expectedSha, pilot = false, fetchImpl = fetch }) {
	const base = origin(baseUrl);
	if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(expectedVersion ?? "")) throw new Error("Invalid expected release version");
	if (!/^[0-9a-f]{40}$/.test(expectedSha ?? "")) throw new Error("Invalid expected release SHA");
	const expectations = [
		["/livez", 200, { status: "alive" }],
		["/healthz", 200, { status: "alive" }],
		["/version", 200, { version: expectedVersion, git_sha: expectedSha }],
		["/metrics", 501, { error: "metrics_not_supported" }],
	];
	await Promise.all(expectations.map(async ([path, status, body]) => {
		const actual = await jsonProbe(base, path, fetchImpl);
		if (actual.status !== status || !exactBody(actual.body, body)) throw new Error(`${path} did not match the expected Worker contract`);
	}));
	const ready = await jsonProbe(base, "/readyz", fetchImpl);
	if (ready.status !== 503 || !readinessBody(ready.body)) throw new Error("/readyz did not match the expected fail-closed Worker contract");
	if (!pilot) throw new Error("Cloudflare production evidence and metrics are unsupported; production acceptance is blocked");
	return { status: "pilot_only", production_ready: false, version: expectedVersion, git_sha: expectedSha, origin: base };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	try {
		const args = process.argv.slice(2);
		const values = {};
		for (let i = 0; i < args.length; i++) {
			if (args[i] === "--pilot") { values.pilot = true; continue; }
			if (!["--base-url", "--expected-version", "--expected-sha"].includes(args[i]) || !args[i + 1]) throw new Error(`Unknown or incomplete option: ${args[i]}`);
			values[args[i].slice(2).replaceAll("-", "_")] = args[++i];
		}
		if (!values.base_url || !values.expected_version || !values.expected_sha) throw new Error("--base-url, --expected-version and --expected-sha are required");
		console.log(JSON.stringify(await verifyCloudflareOperational({ baseUrl: values.base_url, expectedVersion: values.expected_version, expectedSha: values.expected_sha, pilot: values.pilot })));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
