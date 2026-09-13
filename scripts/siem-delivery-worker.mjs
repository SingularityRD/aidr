#!/usr/bin/env node
/** Run from a scheduler (one-shot) to retry due SIEM deliveries without new incidents. */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HELP = `Usage: node scripts/siem-delivery-worker.mjs [--max-items N] [--status]

Requires SINGULARITY_AIDR_SIEM_CONFIG_PATH pointing to a protected JSON config.
Run periodically from Task Scheduler, cron, or a systemd timer. Exit 0 means
healthy/empty; exit 2 means queued, retrying, dead-lettered, or locked state;
exit 3 means configuration or worker failure. --status reports lock age and PID.

If a .lock directory remains after a crash, verify its owner PID is gone and
no AIDR process is using the queue before manually removing that directory.
Never delete the SIEM state file to clear a lock or a delivery failure.
`;

function parseArgs(argv) {
	let maxItems = 25;
	let statusOnly = false;
	for (let index = 0; index < argv.length; index++) {
		const arg = argv[index];
		if (arg === "--help" || arg === "-h") return { help: true };
		if (arg === "--status") {
			statusOnly = true;
			continue;
		}
		if (arg === "--max-items") {
			const value = Number(argv[++index]);
			if (!Number.isSafeInteger(value) || value < 1 || value > 100)
				throw new Error("invalid_siem_drain_limit");
			maxItems = value;
			continue;
		}
		throw new Error("invalid_siem_worker_argument");
	}
	return { maxItems, statusOnly };
}

function safeErrorCode(error) {
	const candidate = error?.code ?? error?.message;
	return typeof candidate === "string" && /^[a-z0-9_]+$/.test(candidate)
		? candidate
		: "siem_worker_unavailable";
}

export async function runSiemDeliveryWorker(
	argv,
	loadProducer = () => import("../packages/core/dist/siem-incident-producer.js"),
	io = { out: (value) => process.stdout.write(value), err: (value) => process.stderr.write(value) },
) {
	let parsed;
	try {
		parsed = parseArgs(argv);
	} catch (error) {
		io.err(`${safeErrorCode(error)}\n`);
		return 3;
	}
	if (parsed.help) {
		io.out(HELP);
		return 0;
	}
	try {
		const producer = await loadProducer();
		if (parsed.statusOnly) {
			const lock = await producer.inspectConfiguredSiemLock();
			io.out(`${JSON.stringify({ type: "aidr_siem_lock", ...lock })}\n`);
			return lock.locked && (lock.ageMs ?? 0) >= 30_000 ? 2 : 0;
		}
		const result = await producer.drainConfiguredSiemDelivery(parsed.maxItems);
		io.out(`${JSON.stringify({ type: "aidr_siem_delivery", ...result })}\n`);
		return result.status === "healthy" ? 0 : 2;
	} catch (error) {
		io.err(`${safeErrorCode(error)}\n`);
		return 3;
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = await runSiemDeliveryWorker(process.argv.slice(2));
}
