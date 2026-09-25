#!/usr/bin/env node
// Runs the alert outbox dispatcher once for a prepared Compose installation.
//
// Invoked every minute by aidr-notification-dispatch.timer. It reads the
// public API origin from deployment.json and the dedicated dispatcher token
// from the owner-only .env.functions, POSTs to the `notification-dispatch`
// Edge Function, and prints the delivery counts. It never prints the token,
// a destination or a payload. A non-2xx answer or an unusable configuration
// exits non-zero so systemd records the failed run.
//
// Usage: node notification-dispatch.mjs [deployment-dir]   (default /srv/aidr)
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const MIN_TOKEN_LENGTH = 32;
const COUNT_FIELDS = ["claimed", "delivered", "retrying", "dead", "lease_lost"];

export function readEnvFile(path) {
	const values = {};
	for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
		const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
		if (match) values[match[1]] = match[2].trim();
	}
	return values;
}

/** Resolve the dispatcher URL and token for an installation directory. */
export function dispatchTarget(deploymentDir) {
	const manifest = JSON.parse(readFileSync(join(deploymentDir, "deployment.json"), "utf8"));
	const base = new URL(manifest.supabase_url);
	const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname);
	if (base.protocol !== "https:" && !(manifest.development === true && loopback)) {
		throw new Error("notification dispatch requires an HTTPS API origin (or a loopback development deployment)");
	}
	const token = readEnvFile(join(deploymentDir, ".env.functions")).AIDR_NOTIFICATION_DISPATCH_TOKEN ?? "";
	if (token.length < MIN_TOKEN_LENGTH) {
		throw new Error("AIDR_NOTIFICATION_DISPATCH_TOKEN is missing or shorter than 32 characters in .env.functions");
	}
	return { url: new URL("/functions/v1/notification-dispatch", base), token };
}

export async function runDispatch(deploymentDir, { fetchImpl = fetch, timeoutMs = 55_000 } = {}) {
	const { url, token } = dispatchTarget(deploymentDir);
	const response = await fetchImpl(url, {
		method: "POST",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: "{}",
		redirect: "error",
		signal: AbortSignal.timeout(timeoutMs),
	});
	let body = null;
	try {
		body = await response.json();
	} catch {
		body = null;
	}
	if (!response.ok || body?.ok !== true || !COUNT_FIELDS.every((field) => Number.isSafeInteger(body[field]))) {
		const code = typeof body?.error === "string" && /^[a-z_]{1,64}$/.test(body.error) ? `, ${body.error}` : "";
		throw new Error(`notification dispatch failed (HTTP ${response.status}${code})`);
	}
	return Object.fromEntries([...COUNT_FIELDS, "pruned"].map((field) => [field, body[field] ?? null]));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
	const deploymentDir = resolve(process.argv[2] ?? process.env.AIDR_DEPLOYMENT_DIR ?? "/srv/aidr");
	try {
		console.log(JSON.stringify({ checked_at: new Date().toISOString(), ...(await runDispatch(deploymentDir)) }));
	} catch (error) {
		console.error(error instanceof Error ? error.message : "notification dispatch failed");
		process.exitCode = 1;
	}
}
