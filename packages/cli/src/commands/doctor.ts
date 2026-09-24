import { existsSync } from "node:fs";
import {
	type AgentRuntime,
	type Config,
	describeOperatorApprovalKey,
	isInvalidConfig,
	listPendingAsks,
	loadConfig,
	loadProvisionedDetectorContext,
	type OperatorApprovalStoreOptions,
	operatorApprovalStorePath,
	resolvePath,
	VERSION,
} from "@singularityrd/aidr-core";
import { type ConnectorStatus, detectConnectorStatuses } from "../utils/connector-status.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";
import { auditLogFiles, readAuditEntries, redactAuditEntry } from "./audit.js";

export type CheckStatus = "ok" | "warn" | "fail";

export interface DoctorCheck {
	id: string;
	status: CheckStatus;
	summary: string;
	detail?: Record<string, unknown>;
}

export interface DoctorReport {
	schema_version: 1;
	checked_at: string;
	core_version: string;
	ok: boolean;
	checks: DoctorCheck[];
}

/** Test seams; production callers pass nothing. */
export interface DoctorDeps {
	configPath?: string;
	home?: string;
	operatorApprovals?: OperatorApprovalStoreOptions;
	connectors?: () => ConnectorStatus[];
	/** Per-runtime detector policy loader (DLP status). */
	loadDetectors?: typeof loadProvisionedDetectorContext;
}

function message(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

async function checkConfiguration(
	deps: DoctorDeps,
): Promise<{ check: DoctorCheck; config: Config }> {
	const path = deps.configPath ?? resolvePath("~/.singularity-aidr/config.json");
	const config = await loadConfig(deps.configPath);
	const present = existsSync(path);
	if (isInvalidConfig(config)) {
		return {
			config,
			check: {
				id: "configuration",
				status: "fail",
				summary: `Configuration at ${path} is invalid; AIDR is enforcing a restrictive fallback.`,
				detail: { path, state: "invalid" },
			},
		};
	}
	const managedIncomplete =
		config.mode === "managed" && !(config.control_plane.enabled && config.control_plane.endpoint);
	return {
		config,
		check: {
			id: "configuration",
			status: managedIncomplete ? "fail" : "ok",
			summary: managedIncomplete
				? `Mode is managed but the control plane is not enabled with an endpoint (${path}).`
				: `Mode: ${config.mode}; ${present ? `configuration ${path}` : "no configuration file, local defaults"}.`,
			detail: { path, state: present ? "valid" : "defaults", mode: config.mode },
		},
	};
}

async function checkRules(): Promise<DoctorCheck> {
	try {
		const rules = await loadBundledThreatCount();
		const selfTest = await verifyDetection();
		const ok = selfTest.ok && rules > 0;
		return {
			id: "detection",
			status: ok ? "ok" : "fail",
			summary: ok
				? `${rules} threat rules loaded; detection self-test passed.`
				: `Detection self-test failed: ${selfTest.reason || "no rules"} (${rules} rules).`,
			detail: { rules, self_test: ok ? "passed" : "failed" },
		};
	} catch (error) {
		return {
			id: "detection",
			status: "fail",
			summary: `Detection self-test crashed: ${message(error)}`,
		};
	}
}

function checkConnectors(connectors: ConnectorStatus[]): DoctorCheck {
	const installed = connectors.filter((c) => c.state === "installed");
	const broken = connectors.filter(
		(c) => c.state === "installed_but_degraded" || c.state === "unavailable",
	);
	const hostsDetected = connectors.filter((c) => c.state !== "not_detected");
	let status: CheckStatus = "ok";
	let summary = `Hooks registered for: ${installed.map((c) => c.label).join(", ")}.`;
	if (broken.length > 0) {
		status = "fail";
		summary = `Connector problems: ${broken.map((c) => `${c.label} (${c.detail})`).join("; ")}.`;
	} else if (installed.length === 0) {
		status = "fail";
		summary =
			hostsDetected.length > 0
				? `Agent hosts detected (${hostsDetected.map((c) => c.label).join(", ")}) but no AIDR hook is registered. Run \`aidr setup\`.`
				: "No supported agent host or AIDR hook was detected.";
	}
	return {
		id: "connectors",
		status,
		summary,
		detail: {
			hosts: connectors.map((c) => ({
				id: c.id,
				state: c.state,
				detail: c.detail,
				remedy: c.remedy,
			})),
		},
	};
}

async function checkDlp(connectors: ConnectorStatus[], deps: DoctorDeps): Promise<DoctorCheck> {
	const load = deps.loadDetectors ?? loadProvisionedDetectorContext;
	const runtimes = connectors
		.filter((c) => c.state === "installed")
		.map((c) => c.id as AgentRuntime);
	const results: Record<string, string> = {};
	const failures: string[] = [];
	for (const runtime of runtimes) {
		try {
			const context = await load(runtime);
			const dlp = context.runtimeDetectors?.dlp;
			results[runtime] = dlp?.enabled
				? "enabled"
				: context.runtimeDetectors
					? "policy present, DLP disabled"
					: "not provisioned";
		} catch (error) {
			results[runtime] = `invalid: ${message(error)}`;
			failures.push(runtime);
		}
	}
	if (failures.length > 0) {
		return {
			id: "dlp",
			status: "fail",
			summary: `Detector (DLP) policy invalid for ${failures.join(", ")}; those connectors block every call.`,
			detail: { runtimes: results },
		};
	}
	const enabled = Object.entries(results).filter(([, state]) => state === "enabled");
	return {
		id: "dlp",
		status: enabled.length > 0 ? "ok" : "warn",
		summary:
			enabled.length > 0
				? `DLP enabled for ${enabled.map(([runtime]) => runtime).join(", ")}.`
				: "DLP is not active: it requires a signed managed detector policy (local mode has no DLP).",
		detail: { runtimes: results },
	};
}

async function checkApprovals(deps: DoctorDeps): Promise<DoctorCheck> {
	const store = deps.operatorApprovals;
	try {
		const pending = await listPendingAsks(store);
		const key = describeOperatorApprovalKey(store ?? {});
		const unverified = pending.filter((p) => !p.verified).length;
		return {
			id: "operator_approvals",
			status: unverified > 0 ? "warn" : "ok",
			summary:
				`${pending.length} ask(s) pending operator approval` +
				(unverified > 0 ? `, ${unverified} failing integrity verification` : "") +
				`; approval key ${key.present ? `in ${key.location === "os-vault" ? `OS vault (${key.store})` : "owner-only key file"}` : "not created yet"}.`,
			detail: {
				store: operatorApprovalStorePath(store),
				pending: pending.length,
				unverified,
				key,
			},
		};
	} catch (error) {
		return {
			id: "operator_approvals",
			status: "fail",
			summary: `Approval store unusable: ${message(error)}. Asks cannot be approved until it is repaired.`,
			detail: { store: operatorApprovalStorePath(store) },
		};
	}
}

async function checkLastVerdict(config: Config): Promise<DoctorCheck> {
	if (!config.logging.enabled) {
		return {
			id: "last_verdict",
			status: "warn",
			summary: "Audit logging is disabled in the configuration.",
		};
	}
	try {
		const { entries } = await readAuditEntries(auditLogFiles(config.logging));
		const last = [...entries].reverse().find((entry) => entry.type === "runtime_verdict");
		if (!last) {
			return {
				id: "last_verdict",
				status: "warn",
				summary:
					"No verdict has been recorded yet; run an agent-host canary to confirm enforcement.",
			};
		}
		const redacted = redactAuditEntry(last);
		return {
			id: "last_verdict",
			status: "ok",
			summary: `Last verdict: ${String(redacted.verdict)} for ${String(redacted.tool_name)} at ${String(redacted.timestamp)}.`,
			detail: {
				timestamp: redacted.timestamp,
				verdict: redacted.verdict,
				tool_name: redacted.tool_name,
				matched_threat_id: redacted.matched_threat_id,
			},
		};
	} catch (error) {
		return {
			id: "last_verdict",
			status: "warn",
			summary: `Audit log unreadable: ${message(error)}`,
		};
	}
}

export async function runDoctor(deps: DoctorDeps = {}): Promise<DoctorReport> {
	const checks: DoctorCheck[] = [
		{ id: "core_version", status: "ok", summary: `Singularity AIDR core ${VERSION}.` },
	];
	const { check: configCheck, config } = await checkConfiguration(deps);
	checks.push(configCheck);
	checks.push(await checkRules());
	const connectors = deps.connectors
		? deps.connectors()
		: detectConnectorStatuses(deps.home ?? resolvePath("~"));
	checks.push(checkConnectors(connectors));
	checks.push(await checkDlp(connectors, deps));
	checks.push(await checkApprovals(deps));
	checks.push(await checkLastVerdict(config));
	return {
		schema_version: 1,
		checked_at: new Date().toISOString(),
		core_version: VERSION,
		ok: checks.every((c) => c.status !== "fail"),
		checks,
	};
}

const MARK: Record<CheckStatus, string> = { ok: "✓", warn: "!", fail: "✗" };

/** `aidr doctor` — exits non-zero when any check fails. */
export default async function doctorCommand(
	options: { json?: boolean } = {},
	deps: DoctorDeps = {},
): Promise<void> {
	const report = await runDoctor(deps);
	if (options.json) {
		console.log(JSON.stringify(report, null, 2));
	} else {
		console.log("Singularity AIDR doctor");
		for (const check of report.checks) console.log(`  ${MARK[check.status]} ${check.summary}`);
		console.log(
			report.ok
				? "No blocking problems found. A registered hook is not proof the host runs it; confirm with a canary."
				: "Problems found (✗). Fix them and re-run `aidr doctor`.",
		);
	}
	if (!report.ok) process.exitCode = 1;
}
