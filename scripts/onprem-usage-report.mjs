#!/usr/bin/env node
/**
 * On-prem / air-gapped usage report (`aidr-usage-report-v1`).
 *
 *   node scripts/onprem-usage-report.mjs <deployment-dir> [--tenant ID]
 *        [--license-file PATH] [--public-keys PATH] [--deployment-version V] [--out FILE]
 *       Compose/systemd installs: reads <dir>/deployment.json and <dir>/.env
 *       (service credential) like scripts/deployment-maintenance.mjs.
 *   node scripts/onprem-usage-report.mjs <dir> --from-env [...]
 *       Kubernetes: AIDR_MAINTENANCE_API_URL and SERVICE_ROLE_KEY.
 *   node scripts/onprem-usage-report.mjs --verify <report.json>
 *       Recompute report_sha256 (exit 0 when it matches, 1 otherwise).
 *
 * The report carries counts only (no device names, users, iids or events):
 *
 *   { format, customer_id, license_id, generated_at, seats_licensed,
 *     devices_enrolled, devices_active_30d, license_state, updates_until,
 *     deployment_version, report_sha256 }
 *
 * `report_sha256` is the SHA-256 of the canonical JSON (keys sorted, no
 * whitespace) of every other field. It detects accidental edits and transport
 * corruption. It is NOT a signature: the customer runs this script on hosts and
 * a database they control, so the report is CUSTOMER-ATTESTED, not
 * tamper-proof. Commercial true-up rests on it together with the contract's
 * audit rights (docs/operations/licensing.md, "Usage reports").
 *
 * The same report can be downloaded by a tenant owner/admin from the dashboard
 * (Settings -> License); both producers use this canonical form.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { canonicalJson, DEFAULT_PUBLIC_KEYS_PATH, verifyLicenseFile } from "./license-verify.mjs";

export const USAGE_REPORT_FORMAT = "aidr-usage-report-v1";
const LICENSE_STATES = ["valid", "grace", "expired", "not_yet_valid", "unverified", "unlicensed"];
const REPORT_FIELDS = [
	"format",
	"customer_id",
	"license_id",
	"generated_at",
	"seats_licensed",
	"devices_enrolled",
	"devices_active_30d",
	"license_state",
	"updates_until",
	"deployment_version",
];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const isCount = (value) => Number.isSafeInteger(value) && value >= 0;
const isoOrNull = (value) => (typeof value === "string" && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null);

export function reportDigest(fields) {
	return createHash("sha256").update(canonicalJson(fields), "utf8").digest("hex");
}

/** Lifecycle state of applied license terms on the reporting clock. */
export function licenseStateAt(terms, now) {
	if (!terms) return null;
	const notBefore = Date.parse(terms.not_before);
	const expires = Date.parse(terms.expires_at);
	const graceEnds = Date.parse(terms.grace_ends_at);
	if (![notBefore, expires, graceEnds].every(Number.isFinite)) return null;
	if (now < notBefore) return "not_yet_valid";
	if (now < expires) return "valid";
	if (now < graceEnds) return "grace";
	return "expired";
}

/**
 * Build the report from database facts (`usage_report_facts`) and, optionally,
 * a license verified locally with license-verify.mjs (`verifiedLicense`), which
 * wins over the stored terms.
 */
export function buildUsageReport(facts, { verifiedLicense = null, now = Date.now(), deploymentVersion } = {}) {
	if (!facts || typeof facts !== "object") throw new Error("usage facts are missing");
	for (const key of ["seats_licensed", "devices_enrolled", "devices_active_30d"]) {
		if (!isCount(facts[key])) throw new Error(`usage facts field ${key} is invalid`);
	}
	if (typeof deploymentVersion !== "string" || !deploymentVersion.trim() || deploymentVersion.length > 128) {
		throw new Error("deployment_version is required");
	}
	let customerId = null;
	let licenseId = null;
	let state;
	let updatesUntil = null;
	if (verifiedLicense) {
		customerId = verifiedLicense.payload.customer_id ?? null;
		licenseId = verifiedLicense.payload.license_id;
		state = verifiedLicense.status;
		updatesUntil = isoOrNull(verifiedLicense.grace_ends_at);
	} else if (facts.license) {
		customerId = facts.license.customer_id ?? null;
		licenseId = facts.license.license_id ?? null;
		state = licenseStateAt(facts.license, now);
		updatesUntil = isoOrNull(facts.license.grace_ends_at);
		if (!state || !licenseId) throw new Error("stored license terms are invalid");
	} else if (facts.admission && facts.admission.kind === "licensed") {
		// Terms written by the bootstrap or an admission operator, with no signed
		// file stored in the database: report the reference, but not as verified.
		licenseId = typeof facts.admission.reference === "string" ? facts.admission.reference : null;
		state = "unverified";
	} else {
		state = "unlicensed";
	}
	const fields = {
		format: USAGE_REPORT_FORMAT,
		customer_id: customerId,
		license_id: licenseId,
		generated_at: new Date(now).toISOString(),
		seats_licensed: facts.seats_licensed,
		devices_enrolled: facts.devices_enrolled,
		devices_active_30d: facts.devices_active_30d,
		license_state: state,
		updates_until: updatesUntil,
		deployment_version: deploymentVersion.trim(),
	};
	return { ...fields, report_sha256: reportDigest(fields) };
}

/** Structural check plus digest recomputation. Returns a list of problems. */
export function verifyUsageReport(report) {
	const problems = [];
	if (!report || typeof report !== "object" || Array.isArray(report)) return ["report must be a JSON object"];
	const keys = Object.keys(report).sort();
	const expected = [...REPORT_FIELDS, "report_sha256"].sort();
	if (keys.join(",") !== expected.join(",")) problems.push(`fields must be exactly: ${expected.join(", ")}`);
	if (report.format !== USAGE_REPORT_FORMAT) problems.push(`format must be ${USAGE_REPORT_FORMAT}`);
	for (const key of ["seats_licensed", "devices_enrolled", "devices_active_30d"]) {
		if (!isCount(report[key])) problems.push(`${key} must be a non-negative integer`);
	}
	if (!LICENSE_STATES.includes(report.license_state)) problems.push("license_state is not a known state");
	if (isoOrNull(report.generated_at) === null) problems.push("generated_at must be a timestamp");
	const fields = Object.fromEntries(REPORT_FIELDS.map((key) => [key, report[key]]));
	if (report.report_sha256 !== reportDigest(fields)) problems.push("report_sha256 does not match the report fields");
	return problems;
}

function loadTarget(dir, fromEnv) {
	if (fromEnv) {
		const url = (process.env.AIDR_MAINTENANCE_API_URL ?? "").trim();
		if (!url) throw new Error("AIDR_MAINTENANCE_API_URL is required with --from-env");
		const base = new URL(url);
		if (base.protocol !== "https:" && !(base.protocol === "http:" && /^[a-z0-9-]+(\.svc(\.cluster\.local)?)?$/.test(base.hostname))) {
			throw new Error("The usage report requires HTTPS or an in-cluster Service URL");
		}
		return { base, serviceRoleKey: (process.env.SERVICE_ROLE_KEY ?? "").trim(), manifest: null };
	}
	const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
	const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/)
		.filter((line) => line.includes("=")).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
	const base = new URL(manifest.supabase_url);
	if (base.protocol !== "https:" && !(manifest.development && base.protocol === "http:"
		&& ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname))) {
		throw new Error("The usage report requires HTTPS or a loopback development deployment");
	}
	return { base, serviceRoleKey: env.SERVICE_ROLE_KEY, manifest };
}

/** Product version of this kit plus the prepared source commit, when known. */
function defaultDeploymentVersion(manifest) {
	const version = JSON.parse(readFileSync(join(root, "packages/core/package.json"), "utf8")).version;
	const commit = typeof manifest?.source_commit === "string" && /^[0-9a-f]{7,40}$/.test(manifest.source_commit)
		? `+${manifest.source_commit.slice(0, 12)}` : "";
	return `${version}${commit}`;
}

async function fetchFacts(base, serviceRoleKey, tenantId) {
	const response = await fetch(new URL("/rest/v1/rpc/usage_report_facts", base), {
		method: "POST",
		headers: { apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}`, "Content-Type": "application/json" },
		body: JSON.stringify({ p_tenant_id: tenantId ?? null }),
		signal: AbortSignal.timeout(30_000),
	});
	const text = await response.text();
	if (!response.ok) {
		let message = "";
		try { message = JSON.parse(text)?.message ?? ""; } catch { /* not JSON */ }
		if (message === "tenant_required") throw new Error("Several licensed tenants exist; pass --tenant <id>");
		if (message === "no_licensed_tenant") throw new Error("No licensed tenant exists in this deployment");
		throw new Error(`usage_report_facts failed (HTTP ${response.status})`);
	}
	return JSON.parse(text);
}

const USAGE = `Usage: node scripts/onprem-usage-report.mjs <deployment-dir> [--from-env] [--tenant ID] [--license-file PATH] [--public-keys PATH] [--deployment-version V] [--out FILE]
       node scripts/onprem-usage-report.mjs --verify <report.json>`;

async function main(argv) {
	const { values, positionals } = parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			"from-env": { type: "boolean", default: false },
			tenant: { type: "string" },
			"license-file": { type: "string" },
			"public-keys": { type: "string" },
			"deployment-version": { type: "string" },
			out: { type: "string" },
			verify: { type: "string" },
			help: { type: "boolean", short: "h", default: false },
		},
	});
	if (values.help) {
		console.log(USAGE);
		return 0;
	}
	if (values.verify) {
		const problems = verifyUsageReport(JSON.parse(readFileSync(resolve(values.verify), "utf8")));
		if (problems.length) {
			for (const problem of problems) console.error(`INVALID: ${problem}`);
			return 1;
		}
		console.log("Usage report digest and structure verified (customer-attested; not a signature).");
		return 0;
	}
	if (values.tenant !== undefined && !UUID.test(values.tenant)) throw new Error("--tenant must be a UUID");
	const dir = resolve(positionals[0] ?? ".aidr-deploy");
	const { base, serviceRoleKey, manifest } = loadTarget(dir, values["from-env"]);
	if (!serviceRoleKey) throw new Error("Deployment service credential missing");
	const now = Date.now();
	const verifiedLicense = values["license-file"]
		? verifyLicenseFile(values["license-file"], {
			publicKeysPath: values["public-keys"] ? resolve(values["public-keys"]) : DEFAULT_PUBLIC_KEYS_PATH,
			now,
		})
		: null;
	const facts = await fetchFacts(base, serviceRoleKey, values.tenant?.toLowerCase());
	const report = buildUsageReport(facts, {
		verifiedLicense,
		now,
		deploymentVersion: values["deployment-version"] ?? defaultDeploymentVersion(manifest),
	});
	const outFile = resolve(values.out ?? join(dir, `aidr-usage-report-${report.generated_at.slice(0, 10)}.json`));
	mkdirSync(dirname(outFile), { recursive: true, mode: 0o700 });
	writeFileSync(outFile, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
	console.log(JSON.stringify(report, null, 2));
	console.error(`Usage report written to ${outFile}. It is customer-attested: report_sha256 detects edits, it is not a signature.`);
	return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	main(process.argv.slice(2)).then((code) => { process.exitCode = code; }).catch((error) => {
		console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	});
}
