import { existsSync, readFileSync } from "node:fs";
import {
	ConfigSchema,
	getAuditLogLossState,
	readPersistedAuditLossState,
	readTelemetryLossSummary,
	resolvePath,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { type ConnectorStatus, detectConnectorStatuses } from "../utils/connector-status.js";
import { readSetupLedger } from "../utils/setup-ledger.js";
import { standaloneBundleRoot } from "../utils/standalone.js";
import { buildStatusVerdict, type StatusVerdict } from "../utils/status-verdict.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";

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
	if (verdict.protected.length + verdict.restart.length === 0) parts.push(ct("status.verdictNone"));
	else parts.push(ct("status.verdictVerify"));
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

export default async function statusCommand(options: { json?: boolean } = {}): Promise<void> {
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
	const path = resolvePath("~/.singularity-aidr/config.json");
	let configState = "defaults";
	let config = ConfigSchema.parse({});
	try {
		if (existsSync(path)) {
			config = ConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
			configState = "valid";
		}
	} catch {
		configState = "invalid";
	}
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
		detectionOk &&
		registered.length > 0 &&
		!connectors.some((c) => c.state === "installed_but_degraded") &&
		!connectors.some((c) => c.state === "unavailable") &&
		(config.mode !== "managed" ||
			(config.control_plane.enabled && !!config.control_plane.endpoint));
	// control_plane.enabled defaults to true, but managed features only run in
	// managed mode; a local-mode install must not be reported as managed.
	const managedActive = config.mode === "managed" && config.control_plane.enabled;
	const report = {
		schema_version: 1,
		checked_at: new Date().toISOString(),
		detection: { ok: detectionOk, rules: ruleCount, detail },
		configuration: { state: configState, path, mode: config.mode },
		managed: {
			active: managedActive,
			enabled: managedActive,
			control_plane_enabled: config.control_plane.enabled,
			endpoint_configured: !!config.control_plane.endpoint,
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
				detail,
			}),
		);
		console.log(ct("status.configuration", { state: configState, mode: config.mode }));
		for (const connector of connectors)
			console.log(
				`  ${connector.label}: ${connector.state === "installed" ? ct("status.registrationDetected") : connector.state} — ${connector.detail}`,
			);
		if (config.mode !== "managed") {
			console.log(ct("status.managedInactive", { mode: config.mode }));
		} else {
			console.log(
				ct("status.managed", {
					state: managedActive ? ct("status.managedEnabled") : ct("status.managedDisabled"),
					endpoint: config.control_plane.endpoint
						? ct("status.endpointConfigured")
						: ct("status.endpointMissing"),
				}),
			);
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
