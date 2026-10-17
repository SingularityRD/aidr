import { existsSync } from "node:fs";
import {
	getAuditLogLossState,
	getEffectiveManagedApiKey,
	isCommercialBuild,
	isInvalidConfig,
	loadConfig,
	loadManagedState,
	managedStatePath,
	readPersistedAuditLossState,
	readTelemetryLossSummary,
	resolvePath,
	type UnprotectedAiTool,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { type ConnectorStatus, detectConnectorStatuses } from "../utils/connector-status.js";
import {
	type CustomerPacketDiscovery,
	type CustomerPacketOptions,
	customerReport,
	describeCustomer,
	discoverCustomerPacket,
} from "../utils/customer-packet.js";
import { describeReleaseKey, releaseKeySeverity, releaseKeyState } from "../utils/release-key.js";
import { readSetupLedger } from "../utils/setup-ledger.js";
import { standaloneBundleRoot } from "../utils/standalone.js";
import { buildStatusVerdict, type StatusVerdict } from "../utils/status-verdict.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";
import { unprotectedAiTools } from "../utils/unprotected-tools.js";
import { modeLabel } from "./doctor.js";

const CONFIG_STATE_KEY = {
	valid: "status.configValid",
	defaults: "status.configDefaults",
	invalid: "status.configInvalid",
} as const;

/** A measured connector state in words (English keeps the state ids scripts already match). */
const CONNECTOR_STATE_KEY = {
	installed: "status.registrationDetected",
	unavailable: "conn.state.unavailable",
	runtime_present_not_installed: "conn.state.runtime_present_not_installed",
	not_detected: "conn.state.not_detected",
	installed_but_degraded: "conn.state.installed_but_degraded",
} as const satisfies Record<ConnectorStatus["state"], string>;

/** Registration, local evaluation and live host enforcement are separate facts. */
/** The verdict as one line in the current locale. */
export function formatStatusVerdict(verdict: StatusVerdict): string {
	const parts: string[] = [];
	if (verdict.protected.length > 0) {
		parts.push(ct("status.verdictProtected", { hosts: verdict.protected.join(", ") }));
	}
	if (verdict.restart.length > 0) {
		parts.push(
			ct("status.verdictRestart", {
				since: verdict.restart[0].since,
				hosts: verdict.restart.map((entry) => entry.label).join(", "),
			}),
		);
	}
	if (verdict.manual.length > 0) {
		parts.push(
			ct("status.verdictManual", {
				steps: verdict.manual.map((entry) => `${entry.label} → ${entry.command}`).join("; "),
			}),
		);
	}
	// "Install a supported tool" only when none was found: with a manual step
	// listed, the tools are there and that step is the next action.
	const registered = verdict.protected.length + verdict.restart.length;
	if (registered > 0) parts.push(ct("status.verdictVerify"));
	else if (verdict.manual.length === 0) parts.push(ct("status.verdictNone"));
	return `${ct("status.verdictPrefix")} ${parts.join(" | ")}`;
}

export function statusVerdictFor(
	connectors: ConnectorStatus[],
	home = resolvePath("~"),
): StatusVerdict {
	return buildStatusVerdict(connectors, readSetupLedger(home), {
		standalone: standaloneBundleRoot() !== null,
	});
}

/** The customer line, when the installer placed a customer packet. */
function printCustomer(discovery: CustomerPacketDiscovery): void {
	const described = describeCustomer(discovery);
	if (described) console.log(`${described.severity === "warn" ? "! " : ""}${described.line}`);
}

/** Test seams; production callers pass nothing. */
export interface StatusDeps {
	/** Customer packet discovery: candidate files, key registry, clock. */
	customerPacket?: CustomerPacketOptions;
	/** AI tools without an AIDR connector; detected from the home directory and PATH by default. */
	unprotectedTools?: UnprotectedAiTool[];
}

export default async function statusCommand(
	options: { json?: boolean } = {},
	deps: StatusDeps = {},
): Promise<void> {
	let ruleCount = 0;
	let detectionOk = false;
	let detail = "";
	try {
		ruleCount = await loadBundledThreatCount();
		const result = await verifyDetection();
		detectionOk = result.ok && ruleCount > 0;
		detail = result.ok ? result.detail : result.reason;
	} catch (error) {
		detail = error instanceof Error ? error.message : String(error);
	}
	const connectors = detectConnectorStatuses();
	// Never part of "ready": AIDR cannot fix another product. But it is never silent.
	const unprotected = unprotectedAiTools(deps);
	// Informational only: a refused packet or an ended license never makes the
	// installation "not ready", because local detection does not depend on it.
	const customer = discoverCustomerPacket(standaloneBundleRoot(), deps.customerPacket);
	const path = resolvePath("~/.singularity-aidr/config.json");
	// The same loader the hooks use: a release build is always managed, and
	// `aidr doctor` reads it the same way, so the two never disagree on mode.
	const config = await loadConfig();
	const configState = isInvalidConfig(config) ? "invalid" : existsSync(path) ? "valid" : "defaults";
	const releaseKey = releaseKeyState(config);
	const releaseKeyFailed = releaseKeySeverity(releaseKey) === "fail";
	const registered = connectors.filter((c) => c.state === "installed");
	const verdict = statusVerdictFor(connectors);
	// Rotations happen in short-lived hook processes, so the persisted counter
	// is the one that reflects them; an unreadable counter is not zero.
	const persistedAuditLoss = await readPersistedAuditLossState(config.logging);
	const auditLoss = {
		...getAuditLogLossState(),
		...(persistedAuditLoss
			? {
					rotationDrops: persistedAuditLoss.rotationDrops,
					lastRotationDropAt: persistedAuditLoss.lastDropAt,
				}
			: { rotationDropsState: "unavailable" as const }),
	};
	let telemetryLoss: Awaited<ReturnType<typeof readTelemetryLossSummary>>;
	try {
		telemetryLoss = await readTelemetryLossSummary(resolvePath("~/.singularity-aidr/telemetry"));
	} catch {
		// An unreadable queue is not an empty one.
		telemetryLoss = {
			queues: 0,
			pendingEvents: 0,
			oldestAgeSeconds: 0,
			lostTotal: 0,
			state: "unavailable",
			namespaces: [],
		};
	}
	const configurationReady =
		configState !== "invalid" &&
		!releaseKeyFailed &&
		detectionOk &&
		registered.length > 0 &&
		!connectors.some((c) => c.state === "installed_but_degraded") &&
		!connectors.some((c) => c.state === "unavailable") &&
		(config.mode !== "managed" ||
			(config.control_plane.enabled && !!config.control_plane.endpoint));
	// control_plane.enabled defaults to true, but managed features only run in
	// managed mode; a local-mode install must not be reported as managed.
	const managedActive = config.mode === "managed" && config.control_plane.enabled;
	// Enrolled = a usable control-plane credential exists. Without it the device
	// still enforces locally, but receives no policy and reports nothing.
	let enrolled = false;
	if (managedActive) {
		try {
			const state = await loadManagedState(managedStatePath());
			enrolled = getEffectiveManagedApiKey(config.auth.api_key, state) !== "";
		} catch {
			enrolled = false;
		}
	}
	const report = {
		schema_version: 1,
		checked_at: new Date().toISOString(),
		detection: { ok: detectionOk, rules: ruleCount, detail },
		configuration: {
			state: configState,
			path,
			mode: config.mode,
			release_build: isCommercialBuild(),
		},
		integrity: releaseKey,
		customer: customerReport(customer),
		managed: {
			active: managedActive,
			enabled: managedActive,
			control_plane_enabled: config.control_plane.enabled,
			endpoint_configured: !!config.control_plane.endpoint,
			enrolled,
			connectivity: "not_checked",
			fleet_adoption: "not_checked",
		},
		// Data loss is reported, never assumed away: an audit append that failed
		// and a telemetry event that was dropped are both visible here.
		data_loss: {
			audit: auditLoss,
			telemetry: telemetryLoss,
		},
		connectors,
		// AI coding tools found here that AIDR has no connector for: not inspected.
		unprotected_ai_tools: unprotected.map((tool) => ({ id: tool.id, label: tool.label })),
		configuration_ready: configurationReady,
		host_enforcement: "unverified",
		verdict,
	};
	if (options.json) console.log(JSON.stringify(report, null, 2));
	else {
		console.log(ct("status.title"));
		console.log(
			ct("status.detection", {
				result: detectionOk ? ct("status.passed") : ct("status.failed"),
				rules: ruleCount,
				// The probe detail repeats the rule count; only a failure needs it.
				detail: detectionOk ? "" : ` — ${detail}`,
			}),
		);
		console.log(
			ct("status.configuration", {
				state: ct(CONFIG_STATE_KEY[configState]),
				mode: modeLabel(config.mode),
				note: isCommercialBuild() ? ` (${ct("mode.releaseBuildNote")})` : "",
			}),
		);
		console.log(`${releaseKeyFailed ? "✗ " : ""}${describeReleaseKey(releaseKey)}`);
		printCustomer(customer);
		for (const connector of connectors)
			console.log(
				`  ${connector.label}: ${ct(CONNECTOR_STATE_KEY[connector.state])} — ${connector.detail}`,
			);
		// Supported tools found without (working) AIDR are as unprotected as
		// tools AIDR has no connector for.
		const openTools = [
			...connectors
				.filter(
					(c) =>
						c.state === "runtime_present_not_installed" || c.state === "installed_but_degraded",
				)
				.map((c) => c.label),
			...unprotected.map((tool) => tool.label),
		];
		console.log(
			openTools.length > 0
				? ct("status.unprotected", { tools: openTools.join(", ") })
				: ct("status.unprotectedNone"),
		);
		if (config.mode !== "managed") {
			console.log(ct("status.managedInactive", { mode: modeLabel(config.mode) }));
		} else {
			console.log(
				ct("status.managed", {
					state: managedActive ? ct("status.managedEnabled") : ct("status.managedDisabled"),
					endpoint: config.control_plane.endpoint
						? ct("status.endpointConfigured")
						: ct("status.endpointMissing"),
				}),
			);
			if (managedActive && !enrolled) console.log(ct("status.notEnrolled"));
		}
		const unreadableTelemetryQueue =
			telemetryLoss.state === "unavailable" ||
			telemetryLoss.namespaces.some((entry: { state: string }) => entry.state === "unavailable");
		console.log(
			ct("status.telemetry", {
				state: telemetryLoss.state,
				pending: telemetryLoss.pendingEvents,
				lost: telemetryLoss.lostTotal,
				oldest:
					telemetryLoss.pendingEvents > 0
						? ct("status.telemetryOldest", { seconds: telemetryLoss.oldestAgeSeconds })
						: "",
				suffix: unreadableTelemetryQueue
					? ct("status.telemetryUnreadable")
					: ct("status.telemetryEnd"),
			}),
		);
		const auditSummary =
			ct("status.audit", {
				failures: auditLoss.writeFailures,
				drops: persistedAuditLoss ? auditLoss.rotationDrops : ct("status.auditUnknownDrops"),
			}) + (auditLoss.lastError ? ct("status.auditLastError", { error: auditLoss.lastError }) : "");
		console.log(auditSummary);
		console.log(configurationReady ? ct("status.ready") : ct("status.attention"));
		console.log(ct("status.disclaimer"));
		console.log(formatStatusVerdict(verdict));
	}
	if (!configurationReady) process.exitCode = 1;
}
