#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const argv = process.argv.slice(2);
const deploymentDir = resolve(argv[0] || ".aidr-deploy");

function option(name, fallback) {
	const index = argv.indexOf(name);
	return index < 0 ? fallback : argv[index + 1];
}

function boundedInteger(name, fallback, minimum, maximum) {
	const raw = option(name, String(fallback));
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
		throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
	}
	return value;
}

const tenantId = option("--tenant")?.toLowerCase();
const requestedBy = option("--requested-by");
const apply = argv.includes("--apply");
const batchSize = boundedInteger("--batch-size", 100, 1, 1000);
const maxBatches = boundedInteger("--max-batches", 100, 1, 10000);
if (!tenantId || !UUID.test(tenantId)) throw new Error("--tenant must be a UUID");
if (apply && (!requestedBy || !UUID.test(requestedBy))) {
	throw new Error("--requested-by must identify the accountable operator when --apply is used");
}

async function main() {
const manifest = JSON.parse(readFileSync(join(deploymentDir, "deployment.json"), "utf8"));
const env = Object.fromEntries(
	readFileSync(join(deploymentDir, ".env"), "utf8")
		.split(/\r?\n/)
		.filter((line) => line.includes("="))
		.map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
);
if (!env.SERVICE_ROLE_KEY) throw new Error("Deployment service credential missing");
const base = new URL(manifest.supabase_url);
if (
	base.protocol !== "https:" &&
	!(manifest.development && base.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname))
) {
	throw new Error("Offboarding requires HTTPS or an explicitly marked loopback development deployment");
}

async function request(path, method = "GET", body) {
	const response = await fetch(new URL(path, base), {
		method,
		headers: {
			apikey: env.SERVICE_ROLE_KEY,
			Authorization: `Bearer ${env.SERVICE_ROLE_KEY}`,
			"Content-Type": "application/json",
		},
		body: body === undefined ? undefined : JSON.stringify(body),
		signal: AbortSignal.timeout(30_000),
	});
	const responseText = await response.text();
	let data = null;
	if (responseText) {
		try {
			data = JSON.parse(responseText);
		} catch {
			throw new Error(`Offboarding endpoint returned invalid JSON (${response.status})`);
		}
	}
	if (!response.ok) {
		const code = typeof data?.code === "string" ? ` ${data.code}` : "";
		throw new Error(`Offboarding request failed (${response.status}${code}); durable receipts remain resumable`);
	}
	return data;
}

// Even an exact bulk response requires an absence check before ACK. Neither
// ambiguous deletion nor failed ACK may cause this worker to replay Storage HTTP.
async function verifyStorageObjectsAbsent(bucket, paths) {
	for (let offset = 0; offset < paths.length; offset += 20) {
		await Promise.all(paths.slice(offset, offset + 20).map(async (path) => {
			const encodedPath = path.split("/").map(encodeURIComponent).join("/");
			const response = await fetch(new URL(`/storage/v1/object/info/${bucket}/${encodedPath}`, base), {
				headers: {
					apikey: env.SERVICE_ROLE_KEY,
					Authorization: `Bearer ${env.SERVICE_ROLE_KEY}`,
				},
				signal: AbortSignal.timeout(30_000),
			});
			if (response.status === 404) return;
			if (response.status === 400) {
				let failure;
				try { failure = await response.json(); } catch { /* Not a provider absence response. */ }
				if (failure?.statusCode === "404" && failure?.error === "not_found" && failure?.code === "NoSuchKey") return;
			}
			if (response.ok) throw new Error(`Storage object remains after deletion: ${path}`);
			throw new Error(`Storage absence check failed (${response.status}); durable receipts remain resumable`);
		}));
	}
}

const backupException =
	"Backup copies are excluded from this live-data receipt and require separate expiry or key-destruction evidence.";
const evidencePath = join(deploymentDir, `offboarding-evidence-${tenantId}.json`);
const checkedAt = new Date().toISOString();

if (!apply) {
	const [tenantRows, policies, holds, runs] = await Promise.all([
		request(`/rest/v1/tenants?id=eq.${tenantId}&select=id,status,retention_days`),
		request(
			`/rest/v1/tenant_data_retention_policies?tenant_id=eq.${tenantId}&select=data_class,retention_days,covers_backups&order=data_class.asc`,
		),
		request(`/rest/v1/tenant_legal_holds?tenant_id=eq.${tenantId}&released_at=is.null&select=id,hold_reference`),
		request(
			`/rest/v1/tenant_offboarding_runs?tenant_id=eq.${tenantId}&select=id,status,requested_at,completed_at,backup_scope&order=requested_at.desc&limit=1`,
		),
	]);
	if (!Array.isArray(tenantRows) || tenantRows.length !== 1) throw new Error("Tenant not found");
	if (!Array.isArray(holds) || !Array.isArray(runs)) {
		throw new Error("Legal hold or offboarding run state is unreadable; refusing to plan deletion");
	}
	if (!Array.isArray(policies) || policies.length !== 10) {
		throw new Error("Tenant retention policy is incomplete; refusing to plan deletion");
	}
	if (policies.some((policy) => policy.covers_backups !== false)) {
		throw new Error("Invalid retention policy: live-data offboarding must not claim backup deletion");
	}
	const evidence = {
		checked_at: checkedAt,
		action: "tenant-offboarding",
		applied: false,
		tenant_id: tenantId,
		tenant_status: tenantRows[0].status,
		active_legal_hold: holds.length > 0,
		retention_policy: policies,
		latest_run: runs[0] ?? null,
		complete: false,
		backup_scope: "excluded_external_retention",
		backup_exception: backupException,
	};
	writeFileSync(evidencePath, JSON.stringify(evidence, null, 2), { mode: 0o600 });
	console.log(JSON.stringify(evidence));
	return;
} else {
// Replace prior success BEFORE authorization/HTTP; crashes must not leave stale
// completion evidence. Durable DB state, not this file, governs reconciliation.
writeFileSync(evidencePath, JSON.stringify({
	checked_at: checkedAt, action: "tenant-offboarding", applied: true,
	tenant_id: tenantId, status: "incomplete", complete: false,
	backup_scope: "excluded_external_retention", backup_exception: backupException,
}, null, 2), { mode: 0o600 });
const run = await request("/rest/v1/rpc/request_tenant_offboarding", "POST", {
	p_tenant_id: tenantId,
	p_requested_by: requestedBy,
});
if (!run || !UUID.test(run.run_id) || run.tenant_id !== tenantId) {
	throw new Error("Offboarding request returned an invalid run binding");
}
if (run.backup_scope !== "excluded_external_retention") {
	throw new Error("Offboarding run does not explicitly exclude backup copies");
}

let state = run;
let batches = 0;
let storageBatches = 0;
let cacheInvalidationRequired = false;
while (batches < maxBatches && state.status !== "completed") {
	state = await request("/rest/v1/rpc/run_tenant_offboarding_batch", "POST", {
		p_run_id: run.run_id,
		p_batch_size: batchSize,
	});
	batches += 1;
	if (state.action === "delete_storage_objects") {
		const bucket = state.phase === "audit_export_objects" ? "aidr-audit-exports"
			: state.phase === "pack_versions" ? "aidr-packs" : null;
		if (!bucket) throw new Error("Offboarding returned an unknown storage deletion phase");
		if (!Array.isArray(state.paths) || state.paths.length < 1 || state.paths.length > batchSize) {
			throw new Error("Offboarding returned an invalid storage deletion batch");
		}
		const prefix = `${tenantId}/`;
		if (state.paths.some((path) => typeof path !== "string" || !path.startsWith(prefix) ||
			path.split("/").some((segment) => !segment || segment === "." || segment === ".."))) {
			throw new Error("Offboarding returned a storage path outside the tenant prefix");
		}
		// Tokens were committed under the SAME tenant lock as hold placement.
		// Pending tokens prevent activation of a hold and are never reissued.
		if (!Array.isArray(state.objects) || state.objects.length !== state.paths.length ||
			new Set(state.paths).size !== state.paths.length ||
			state.objects.some((object, index) => object?.path !== state.paths[index] || typeof object?.authorization_id !== "string" || !UUID.test(object.authorization_id)) ||
			new Set(state.objects.map((object) => object.authorization_id)).size !== state.objects.length) {
			throw new Error("Offboarding returned invalid storage deletion authorizations; refusing Storage DELETE");
		}
		const deleted = await request(`/storage/v1/object/${bucket}`, "DELETE", { prefixes: state.paths });
		const deletedPaths = Array.isArray(deleted) ? deleted.map((object) => object?.name) : [];
		if (deletedPaths.length !== state.paths.length || new Set(deletedPaths).size !== state.paths.length ||
			state.paths.some((path) => !deletedPaths.includes(path))) {
			throw new Error("Storage deletion returned an inexact result; fence worker and reconcile pending authorizations, do not retry deletion");
		}
		await verifyStorageObjectsAbsent(bucket, state.paths);
		state = await request(bucket === "aidr-packs"
			? "/rest/v1/rpc/ack_tenant_offboarding_packs"
			: "/rest/v1/rpc/ack_tenant_offboarding_objects", "POST", {
			p_run_id: run.run_id,
			p_paths: state.paths,
			p_authorization_ids: state.objects.map((object) => object.authorization_id),
		});
		storageBatches += 1;
	}
	if (state.action === "invalidate_cache") {
		// The cache layer is external to this deployment's database, so this
		// driver cannot purge it and must not claim that it did. It records the
		// required scope and stops: the run stays incomplete until an operator
		// purges the cache and records the receipt through
		// `ack_tenant_offboarding_cache`.
		if (typeof state.cache_scope !== "string" || state.cache_scope.toLowerCase() !== tenantId.toLowerCase()) {
			throw new Error("Offboarding returned a cache scope outside the tenant");
		}
		cacheInvalidationRequired = true;
		break;
	}
	if (state.action === "reconcile_storage_authorizations") break;
	if (["blocked_legal_hold", "waiting_retention"].includes(state.status)) break;
}

const receipts = await request(
	`/rest/v1/tenant_offboarding_phase_receipts?run_id=eq.${run.run_id}&select=phase,data_class,status,retention_days,eligible_at,rows_deleted,attempts,cache_invalidation_receipt&order=phase_order.asc`,
);
const cachePhase = Array.isArray(receipts)
	? receipts.find((receipt) => receipt?.phase === "tenant_cache")
	: undefined;
const packObjectReceipts = Array.isArray(receipts) && receipts.some((receipt) => receipt?.phase === "pack_versions")
	? await request(`/rest/v1/tenant_pack_deletion_receipts?offboarding_run_id=eq.${run.run_id}&select=storage_path,authorization_id,observed_absent_at&order=storage_path.asc`)
	: [];
const complete = state.status === "completed";
if (complete && (!Array.isArray(receipts) || receipts.length === 0 ||
	receipts.some((receipt) => receipt?.status !== "completed") ||
	cachePhase?.cache_invalidation_receipt?.tenant_id !== tenantId ||
	!Array.isArray(packObjectReceipts))) {
	throw new Error("Completed offboarding lacks complete phase and tenant-bound cache receipts");
}
const evidence = {
	checked_at: checkedAt,
	action: "tenant-offboarding",
	applied: true,
	tenant_id: tenantId,
	run_id: run.run_id,
	status: state.status,
	complete,
	batches,
	storage_batches: storageBatches,
	storage_reconciliation_required: state.action === "reconcile_storage_authorizations",
	phase_receipts: receipts,
	pack_object_receipts: packObjectReceipts,
	cache_invalidation: {
		phase: "tenant_cache",
		required_for_completion: true,
		action_returned: cacheInvalidationRequired,
		acknowledged: cachePhase?.status === "completed",
		acknowledged_by: "ack_tenant_offboarding_cache",
		cache_scope: tenantId,
		receipt: cachePhase?.cache_invalidation_receipt ?? null,
	},
	backup_scope: "excluded_external_retention",
	backup_exception: run.backup_exception || backupException,
};
writeFileSync(evidencePath, JSON.stringify(evidence, null, 2), { mode: 0o600 });
console.log(JSON.stringify(evidence));
if (!complete) process.exitCode = 2;
}
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : String(error));
	process.exitCode = 1;
});
