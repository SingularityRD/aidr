import { existsSync, readFileSync } from "node:fs";
import {
	ConfigSchema,
	getAuditLogLossState,
	readPersistedAuditLossState,
	readTelemetryLossSummary,
	resolvePath,
} from "@singularityrd/aidr-core";
import { detectConnectorStatuses } from "../utils/connector-status.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";

/** Registration, local evaluation and live host enforcement are separate facts. */
export default async function statusCommand(options: { json?: boolean } = {}): Promise<void> {
	let ruleCount = 0;
	let detectionOk = false;
	let detail = "";
	try {
		ruleCount = await loadBundledThreatCount();
		const result = await verifyDetection();
		detectionOk = result.ok && ruleCount > 0;
		detail = result.ok ? result.detail : result.reason;
	} catch (error) { detail = error instanceof Error ? error.message : String(error); }
	const connectors = detectConnectorStatuses();
	const path = resolvePath("~/.singularity-aidr/config.json");
	let configState = "defaults";
	let config = ConfigSchema.parse({});
	try {
		if (existsSync(path)) {
			config = ConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
			configState = "valid";
		}
	} catch { configState = "invalid"; }
	const registered = connectors.filter((c) => c.state === "installed");
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
	const configurationReady = configState !== "invalid" && detectionOk && registered.length > 0
		&& !connectors.some((c) => c.state === "installed_but_degraded")
		&& !connectors.some((c) => c.state === "unavailable")
		&& (config.mode !== "managed" || (config.control_plane.enabled && !!config.control_plane.endpoint));
	// control_plane.enabled defaults to true, but managed features only run in
	// managed mode; a local-mode install must not be reported as managed.
	const managedActive = config.mode === "managed" && config.control_plane.enabled;
	const report = {
		schema_version: 1, checked_at: new Date().toISOString(),
		detection: { ok: detectionOk, rules: ruleCount, detail },
		configuration: { state: configState, path, mode: config.mode },
		managed: { active: managedActive, enabled: managedActive, control_plane_enabled: config.control_plane.enabled, endpoint_configured: !!config.control_plane.endpoint, connectivity: "not_checked", fleet_adoption: "not_checked" },
		// Data loss is reported, never assumed away: an audit append that failed
		// and a telemetry event that was dropped are both visible here.
		data_loss: {
			audit: auditLoss,
			telemetry: telemetryLoss,
		},
		connectors, configuration_ready: configurationReady, host_enforcement: "unverified",
	};
	if (options.json) console.log(JSON.stringify(report, null, 2));
	else {
		console.log("Singularity AIDR — installation diagnostics");
		console.log(`Detection self-test: ${detectionOk ? "passed" : "FAILED"}; ${ruleCount} rules. ${detail}`);
		console.log(`Configuration: ${configState}; mode: ${config.mode}`);
		for (const connector of connectors) console.log(`  ${connector.label}: ${connector.state === "installed" ? "registration/package detected" : connector.state} — ${connector.detail}`);
		if (config.mode !== "managed") {
			console.log(`Managed: inactive (mode: ${config.mode}); enforcement is local and no control plane is used.`);
		} else {
			console.log(`Managed: ${managedActive ? "enabled" : "disabled"}; endpoint ${config.control_plane.endpoint ? "configured" : "missing"}. Connectivity and fleet adoption have not been checked.`);
		}
		const unreadableTelemetryQueue =
			telemetryLoss.state === "unavailable" ||
			telemetryLoss.namespaces.some((entry: { state: string }) => entry.state === "unavailable");
		console.log(
			`Telemetry queue: ${telemetryLoss.state}; ${telemetryLoss.pendingEvents} event(s) undelivered, ${telemetryLoss.lostTotal} lost` +
				(telemetryLoss.pendingEvents > 0 ? `, oldest ${telemetryLoss.oldestAgeSeconds}s` : "") +
				(unreadableTelemetryQueue ? " — at least one queue could not be read." : "."),
		);
		const auditSummary =
			`Audit log: ${auditLoss.writeFailures} append(s) could not be written, ${persistedAuditLoss ? auditLoss.rotationDrops : "an unknown number of"} rotation(s) dropped the oldest file.` +
			(auditLoss.lastError ? ` Last error: ${auditLoss.lastError}.` : "");
		console.log(auditSummary);
		console.log(configurationReady ? "Local installation checks passed. Run an agent-host canary to confirm actual enforcement." : "Installation requires attention. Check configuration and connector registration above.");
		console.log("A package or hook registration does not prove that the host executes it.");
	}
	if (!configurationReady) process.exitCode = 1;
}
