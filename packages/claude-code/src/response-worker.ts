#!/usr/bin/env node

import { join } from "node:path";
import {
	initializeInstalledWindowsResponseWorker,
	loadInstalledWindowsResponseWorker,
	runInstalledWindowsResponseWorker,
	validateInstalledWindowsResponseRemoval,
} from "@singularityrd/aidr-core";

async function bootstrapInput(optional = false): Promise<unknown> {
	if (optional && process.stdin.isTTY) return undefined;
	const chunks: Buffer[] = [];
	let bytes = 0;
	for await (const chunk of process.stdin) {
		const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		bytes += buffer.length;
		if (bytes > 32_768) throw new Error("windows_response_bootstrap_input_too_large");
		chunks.push(buffer);
	}
	if (optional && bytes === 0) return undefined;
	try {
		return JSON.parse(
			new TextDecoder("utf8", { fatal: true }).decode(Buffer.concat(chunks)).replace(/^\uFEFF/, ""),
		);
	} catch {
		throw new Error("windows_response_bootstrap_input_invalid");
	}
}

async function main(): Promise<void> {
	const args = process.argv.slice(2);
	if (
		args.length > 1 ||
		(args.length === 1 &&
			!["--initialize", "--validate", "--validate-safe-removal", "--once"].includes(
				args[0] as string,
			))
	)
		throw new Error("windows_response_invalid_arguments");
	const adapterPath = join(__dirname, "native", "Invoke-AidrResponseAction.ps1");
	if (args[0] === "--initialize") {
		await initializeInstalledWindowsResponseWorker(adapterPath, await bootstrapInput());
		process.stdout.write(`${JSON.stringify({ ok: true, status: "initialized" })}\n`);
		return;
	}
	if (args[0] === "--validate") {
		await loadInstalledWindowsResponseWorker(adapterPath, await bootstrapInput(true));
		process.stdout.write(`${JSON.stringify({ ok: true, status: "validated" })}\n`);
		return;
	}
	if (args[0] === "--validate-safe-removal") {
		await validateInstalledWindowsResponseRemoval(adapterPath);
		process.stdout.write(`${JSON.stringify({ ok: true, status: "removable" })}\n`);
		return;
	}
	const controller = new AbortController();
	const stop = () => controller.abort();
	process.once("SIGINT", stop);
	process.once("SIGTERM", stop);
	try {
		const result = await runInstalledWindowsResponseWorker(adapterPath, {
			once: args[0] === "--once",
			signal: controller.signal,
		});
		if (result) {
			process.stdout.write(`${JSON.stringify(result)}\n`);
			if (result.status !== "idle" && result.status !== "succeeded") process.exitCode = 1;
		}
	} finally {
		process.removeListener("SIGINT", stop);
		process.removeListener("SIGTERM", stop);
	}
}

main().catch((error: unknown) => {
	const code =
		error instanceof Error &&
		/^(?:windows_response_|fleet_response_worker_)[a-z0-9_]{1,64}$/.test(error.message)
			? error.message
			: "windows_response_worker_unavailable";
	process.stderr.write(`${JSON.stringify({ ok: false, code })}\n`);
	process.exitCode = 1;
});
