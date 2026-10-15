import { existsSync } from "node:fs";
import {
	type AgentEnvironmentReport,
	type AgentRuntime,
	amsiSessionStatus,
	type Config,
	describeOperatorApprovalKey,
	inspectLocalAgentProfiles,
	inspectLocalDlpPolicy,
	isCommercialBuild,
	isInvalidConfig,
	type LocalDlpPolicyState,
	listPendingAsks,
	loadConfig,
	loadProvisionedDetectorContext,
	localAgentProfilesPath,
	localDlpPolicyPath,
	type OperatorApprovalStoreOptions,
	operatorApprovalStorePath,
	resolvePath,
	VERSION,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { scanAgentEnvironment } from "../utils/agent-posture.js";
import { type CodexTrustReport, inspectCodexHookTrust } from "../utils/codex-trust.js";
import { type ConnectorStatus, detectConnectorStatuses } from "../utils/connector-status.js";
import {
	type CustomerPacketOptions,
	customerReport,
	describeCustomer,
	discoverCustomerPacket,
} from "../utils/customer-packet.js";
import { localTime } from "../utils/local-time.js";
import { type MachineHookState, machineHookStatus } from "../utils/machine-hooks.js";
import {
	describeReleaseKey,
	releaseKeyFix,
	releaseKeySeverity,
	releaseKeyState,
} from "../utils/release-key.js";
import { standaloneBundleRoot } from "../utils/standalone.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";
import { auditLogFiles, readAuditEntries, redactAuditEntry } from "./audit.js";

type CheckStatus = "ok" | "warn" | "fail";

interface DoctorCheck {
	id: string;
	status: CheckStatus;
	/** One line, in the current locale. */
	summary: string;
	/** The explanation behind the line, printed with `--verbose` (and kept in `--json`). */
	notes?: string[];
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
	/** Agent environment posture scan. */
	agentEnvironment?: (connectors: ConnectorStatus[]) => AgentEnvironmentReport;
	/** Local agent permission profile document location. */
	agentProfilesPath?: string;
	/** Local (unsigned) DLP policy location; defaults to `AIDR_DLP_POLICY_PATH` or the home file. */
	localDlpPolicyPath?: string;
	/** Customer packet discovery: candidate files, key registry, clock. */
	customerPacket?: CustomerPacketOptions;
	/** System-wide (machine policy) hook registrations. */
	machine?: () => readonly MachineHookState[];
	/** Codex hook trust inspection of the user's Codex home. */
	codexTrust?: () => CodexTrustReport;
	/** AMSI host probe (Windows/WSL); injectable for tests. */
	amsiStatus?: typeof amsiSessionStatus;
	/** Reads the control plane's clock (its HTTP `Date` header); defaults to a HEAD request. */
	serverTime?: (endpoint: string) => Promise<ServerTimeSample>;
}

/** One reading of the control plane's clock, bracketed by the local clock. */
export interface ServerTimeSample {
	/** Local time (ms) just before the request was sent. */
	sentAt: number;
	/** Local time (ms) when the response arrived. */
	receivedAt: number;
	/** The server's `Date` header in ms, or null when it sent none. */
	serverAt: number | null;
}

function message(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

/** `local` / `managed` in the current locale. */
export function modeLabel(mode: Config["mode"]): string {
	return mode === "managed" ? ct("mode.managed") : ct("mode.local");
}

async function checkConfiguration(
	deps: DoctorDeps,
): Promise<{ check: DoctorCheck; config: Config }> {
	const path = deps.configPath ?? resolvePath("~/.singularity-aidr/config.json");
	// loadConfig applies the same release-build override the hooks apply, so the
	// mode printed here is the mode the hooks enforce.
	const config = await loadConfig(deps.configPath);
	const present = existsSync(path);
	const fileNote = ct("doctor.configFile", { path });
	if (isInvalidConfig(config)) {
		return {
			config,
			check: {
				id: "configuration",
				status: "fail",
				summary: ct("doctor.configInvalid"),
				notes: [fileNote],
				detail: { path, state: "invalid" },
			},
		};
	}
	const managedIncomplete =
		config.mode === "managed" && !(config.control_plane.enabled && config.control_plane.endpoint);
	const notes = [present ? fileNote : ct("doctor.configDefaults")];
	if (isCommercialBuild()) notes.push(ct("mode.releaseBuildNote"));
	return {
		config,
		check: {
			id: "configuration",
			status: managedIncomplete ? "fail" : "ok",
			summary: managedIncomplete
				? ct("doctor.configManagedIncomplete")
				: ct("doctor.configMode", { mode: modeLabel(config.mode) }),
			notes,
			detail: {
				path,
				state: present ? "valid" : "defaults",
				mode: config.mode,
				release_build: isCommercialBuild(),
			},
		},
	};
}

function checkReleaseKey(config: Config): DoctorCheck {
	const state = releaseKeyState(config);
	const status = releaseKeySeverity(state);
	return {
		id: "integrity",
		status,
		summary: describeReleaseKey(state),
		...(status === "fail" ? { notes: [ct("integrity.missingWhy", { fix: releaseKeyFix() })] } : {}),
		detail: { ...state },
	};
}

/**
 * The customer packet and its license, when the installer placed one. Never a
 * failure: an ended license stops new update packs, not detection.
 */
function checkCustomer(deps: DoctorDeps): DoctorCheck | null {
	const discovery = discoverCustomerPacket(standaloneBundleRoot(), deps.customerPacket);
	const described = describeCustomer(discovery);
	if (!described) return null;
	return {
		id: "customer_license",
		status: described.severity,
		summary: described.line,
		detail: customerReport(discovery),
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
				? ct("doctor.detectionOk", { rules })
				: ct("doctor.detectionFailed", { reason: selfTest.reason || "no rules", rules }),
			detail: { rules, self_test: ok ? "passed" : "failed" },
		};
	} catch (error) {
		return {
			id: "detection",
			status: "fail",
			summary: ct("doctor.detectionCrashed", { error: message(error) }),
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
	let summary = ct("doctor.connectorsOk", { hosts: installed.map((c) => c.label).join(", ") });
	let notes: string[] = [];
	if (broken.length > 0) {
		status = "fail";
		summary = ct("doctor.connectorsBroken", { hosts: broken.map((c) => c.label).join(", ") });
		notes = broken.map((c) => `${c.label}: ${c.detail}${c.remedy ? ` (${c.remedy})` : ""}`);
	} else if (installed.length === 0) {
		status = "fail";
		summary =
			hostsDetected.length > 0
				? ct("doctor.connectorsUnprotected", {
						hosts: hostsDetected.map((c) => c.label).join(", "),
					})
				: ct("doctor.connectorsNone");
	}
	return {
		id: "connectors",
		status,
		summary,
		...(notes.length > 0 ? { notes } : {}),
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

/**
 * Codex drops an untrusted or disabled hook without a word and runs the call
 * uninspected, so a registered AIDR hook is not proof of protection there.
 * Null when Codex is absent or registers no AIDR handler (the connector check
 * reports that).
 */
function checkCodexTrust(connectors: ConnectorStatus[], deps: DoctorDeps): DoctorCheck | null {
	const codex = connectors.find((c) => c.id === "codex");
	if (!codex || codex.state === "not_detected") return null;
	const machine = (deps.machine ?? machineHookStatus)().find((entry) => entry.host === "codex");
	if (machine?.registered) {
		return {
			id: "codex_hook_trust",
			status: "ok",
			summary: ct("doctor.codexTrustManaged"),
			detail: { trust: "managed", path: machine.path },
		};
	}
	const report = (
		deps.codexTrust ?? (() => inspectCodexHookTrust(deps.home ?? resolvePath("~")))
	)();
	if (report.handlers.length === 0) return null;
	const events = (trust: string) =>
		[...new Set(report.handlers.filter((h) => h.trust === trust).map((h) => h.event))].join(", ");
	const detail = { handlers: report.handlers.map((h) => ({ event: h.event, trust: h.trust })) };
	for (const trust of ["untrusted", "disabled"] as const) {
		if (!report.handlers.some((h) => h.trust === trust)) continue;
		return {
			id: "codex_hook_trust",
			status: "fail",
			summary: ct(
				trust === "untrusted" ? "doctor.codexTrustUntrusted" : "doctor.codexTrustDisabled",
				{
					events: events(trust),
				},
			),
			notes: [ct("doctor.codexTrustFix")],
			detail,
		};
	}
	return {
		id: "codex_hook_trust",
		status: "ok",
		summary: ct("doctor.codexTrustRecorded", { events: events("trust_recorded") }),
		detail,
	};
}

type DlpSource = "signed_bundle" | "local_file" | "none";

/**
 * Where the effective DLP policy for one runtime comes from. A local-mode
 * install with no signed bundle enforces the operator's unsigned
 * `dlp-policy.json`; this check must say so rather than claim "no DLP".
 */
function dlpSourceFor(
	context: Awaited<ReturnType<typeof loadProvisionedDetectorContext>>,
	local: LocalDlpPolicyState,
	mode: Config["mode"],
): DlpSource {
	const dlp = context.runtimeDetectors?.dlp;
	if (!dlp?.enabled) return "none";
	const fromLocalFile =
		mode === "local" &&
		local.status === "loaded" &&
		JSON.stringify(dlp.policy) === JSON.stringify(local.policy);
	return fromLocalFile ? "local_file" : "signed_bundle";
}

/** Machine-readable per-runtime state for `--json` (stable English values). */
const DLP_SOURCE_LABEL = {
	signed_bundle: "enabled (signed managed detector policy)",
	local_file: "enabled (local dlp-policy.json, unsigned)",
} as const;

function runtimeDlpState(
	context: Awaited<ReturnType<typeof loadProvisionedDetectorContext>>,
	source: DlpSource,
): string {
	if (source !== "none") return DLP_SOURCE_LABEL[source];
	return context.runtimeDetectors ? "policy present, DLP disabled" : "not provisioned";
}

/** Explanations of the local DLP file that do not fit the one-line summary. */
function localDlpNotes(local: LocalDlpPolicyState, mode: Config["mode"]): string[] {
	if (local.status === "invalid") {
		return [ct("doctor.dlpLocalInvalidNote", { path: local.path, reason: local.reason })];
	}
	if (local.status === "loaded" && mode !== "local") {
		return [ct("doctor.dlpLocalIgnored", { path: local.path, mode: modeLabel(mode) })];
	}
	return [];
}

/** Summary when no installed runtime enforces DLP. */
function inactiveDlpSummary(
	runtimeCount: number,
	local: LocalDlpPolicyState,
	mode: Config["mode"],
): { status: CheckStatus; summary: string; notes: string[] } {
	if (runtimeCount === 0 && mode === "local" && local.status === "loaded") {
		// No hook to evaluate per runtime, but the file every local connector reads is valid.
		return {
			status: "ok",
			summary: ct("doctor.dlpLocalPending"),
			notes: [ct("doctor.dlpLocalFile", { path: local.path })],
		};
	}
	const notes = localDlpNotes(local, mode);
	if (local.status === "invalid") {
		return { status: "warn", summary: ct("doctor.dlpLocalInvalid"), notes };
	}
	if (mode === "local") {
		return {
			status: "warn",
			summary: ct("doctor.dlpNoneLocal"),
			notes: [ct("doctor.dlpLocalFile", { path: local.path }), ...notes],
		};
	}
	return { status: "warn", summary: ct("doctor.dlpNoneManaged"), notes };
}

async function checkDlp(
	connectors: ConnectorStatus[],
	deps: DoctorDeps,
	config: Config,
): Promise<DoctorCheck> {
	const load = deps.loadDetectors ?? loadProvisionedDetectorContext;
	const local = await inspectLocalDlpPolicy(deps.localDlpPolicyPath ?? localDlpPolicyPath());
	const runtimes = connectors
		.filter((c) => c.state === "installed")
		.map((c) => c.id as AgentRuntime);
	const results: Record<string, string> = {};
	const sources: Record<string, DlpSource> = {};
	const failures: string[] = [];
	const failureNotes: string[] = [];
	for (const runtime of runtimes) {
		try {
			const context = await load(runtime);
			const source = dlpSourceFor(context, local, config.mode);
			sources[runtime] = source;
			results[runtime] = runtimeDlpState(context, source);
		} catch (error) {
			results[runtime] = `invalid: ${message(error)}`;
			failures.push(runtime);
			failureNotes.push(`${runtime}: ${message(error)}`);
		}
	}
	const detail = {
		runtimes: results,
		sources,
		mode: config.mode,
		local_policy: { path: local.path, status: local.status },
	};
	if (failures.length > 0) {
		return {
			id: "dlp",
			status: "fail",
			summary: ct("doctor.dlpInvalid", { runtimes: failures.join(", ") }),
			notes: failureNotes,
			detail,
		};
	}
	const enabled = Object.entries(sources).filter(([, source]) => source !== "none");
	if (enabled.length === 0) {
		return { id: "dlp", ...inactiveDlpSummary(runtimes.length, local, config.mode), detail };
	}
	const described = enabled
		.map(([runtime, source]) =>
			source === "local_file"
				? ct("doctor.dlpItemLocal", { runtime, path: local.path })
				: ct("doctor.dlpItemSigned", { runtime }),
		)
		.join(", ");
	const notes = localDlpNotes(local, config.mode);
	return {
		id: "dlp",
		status: local.status === "invalid" ? "warn" : "ok",
		summary: ct("doctor.dlpEnabled", { runtimes: described }),
		...(notes.length > 0 ? { notes } : {}),
		detail,
	};
}

/**
 * Agent permission profiles. An invalid local document is refused by every
 * connector (so the operator's restrictions are NOT in force); an invalid
 * managed section denies every call for that connector. Both are failures.
 */
/** Managed profile names per installed connector, and the connectors whose section is invalid. */
async function managedAgentProfiles(
	connectors: ConnectorStatus[],
	load: typeof loadProvisionedDetectorContext,
): Promise<{ managed: Record<string, string>; managedFailures: string[] }> {
	const managed: Record<string, string> = {};
	const managedFailures: string[] = [];
	for (const connector of connectors.filter((c) => c.state === "installed")) {
		try {
			const context = await load(connector.id as AgentRuntime);
			const layer = context.agentProfiles?.layers.find((item) => item.source === "managed");
			if (!layer) continue;
			if (layer.status === "invalid") {
				managed[connector.id] = `invalid: ${layer.reason}`;
				managedFailures.push(connector.id);
			} else {
				managed[connector.id] = layer.document.profiles.map((p) => p.name).join(", ");
			}
		} catch {
			// A bundle that fails to load at all is reported by the DLP check.
		}
	}
	return { managed, managedFailures };
}

function localProfileDetail(
	local: Awaited<ReturnType<typeof inspectLocalAgentProfiles>>,
): Record<string, unknown> {
	return {
		path: local.path,
		status: local.status,
		...(local.status === "invalid" ? { reason: local.reason } : {}),
		...(local.status === "loaded"
			? { profiles: local.document.profiles.map((p) => p.name), diagnostics: local.diagnostics }
			: {}),
	};
}

async function checkAgentProfiles(
	connectors: ConnectorStatus[],
	deps: DoctorDeps,
): Promise<DoctorCheck> {
	const local = await inspectLocalAgentProfiles(deps.agentProfilesPath ?? localAgentProfilesPath());
	const { managed, managedFailures } = await managedAgentProfiles(
		connectors,
		deps.loadDetectors ?? loadProvisionedDetectorContext,
	);
	const detail = { local: localProfileDetail(local), managed };
	const problems: string[] = [];
	if (local.status === "invalid") problems.push(ct("doctor.profilesLocalInvalid"));
	if (managedFailures.length > 0) {
		problems.push(ct("doctor.profilesManagedInvalid", { runtimes: managedFailures.join(", ") }));
	}
	if (problems.length > 0) {
		const notes =
			local.status === "invalid"
				? [ct("doctor.profilesLocalInvalidNote", { path: local.path, reason: local.reason })]
				: undefined;
		return { id: "agent_profiles", status: "fail", summary: problems.join(" "), notes, detail };
	}
	const parts: string[] = [];
	if (local.status === "loaded") {
		parts.push(ct("doctor.profilesLocalCount", { count: local.document.profiles.length }));
	}
	const managedNames = Object.keys(managed);
	if (managedNames.length > 0) {
		parts.push(ct("doctor.profilesManagedFor", { runtimes: managedNames.join(", ") }));
	}
	const diagnostics = local.status === "loaded" ? local.diagnostics.length : 0;
	return {
		id: "agent_profiles",
		status: diagnostics > 0 ? "warn" : "ok",
		summary:
			parts.length > 0
				? ct("doctor.profilesSummary", {
						parts: parts.join("; "),
						diagnostics:
							diagnostics > 0 ? ct("doctor.profilesDiagnostics", { count: diagnostics }) : "",
					})
				: ct("doctor.profilesNone"),
		detail,
	};
}

function describeKeyLocation(key: ReturnType<typeof describeOperatorApprovalKey>): string {
	if (!key.present) return ct("doctor.keyNotCreated");
	if (key.location === "os-vault") return ct("doctor.keyOsVault", { store: key.store ?? "" });
	if (key.location === "encrypted-file") return ct("doctor.keyEncryptedFile");
	return ct("doctor.keyPlainFile");
}

async function checkApprovals(deps: DoctorDeps, config: Config): Promise<DoctorCheck> {
	const store: OperatorApprovalStoreOptions = deps.operatorApprovals ?? {
		keyStorage: config.operator_approvals?.key_storage,
	};
	try {
		const pending = await listPendingAsks(store);
		const key = describeOperatorApprovalKey(store);
		const unverified = pending.filter((p) => !p.verified).length;
		const plainFile = key.location === "file" || key.storage === "file";
		const notes: string[] = [];
		if (!key.available && key.reason) notes.push(key.reason);
		if (plainFile) notes.push(ct("doctor.keyPlainFileWarning"));
		if (key.location === "encrypted-file" || key.anchor === "encrypted-file") {
			notes.push(ct("doctor.keyEncryptedFileNote"));
		}
		const counts = ct("doctor.approvalsPending", {
			count: pending.length,
			unverified: unverified > 0 ? ct("doctor.approvalsUnverified", { count: unverified }) : "",
		});
		const summary = !key.available
			? ct("doctor.approvalsDisabled", { pending: counts })
			: ct("doctor.approvalsSummary", { pending: counts, where: describeKeyLocation(key) });
		return {
			id: "operator_approvals",
			status: unverified > 0 || !key.available || plainFile ? "warn" : "ok",
			summary,
			...(notes.length > 0 ? { notes } : {}),
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
			summary: ct("doctor.approvalsUnusable"),
			notes: [message(error), ct("doctor.storePath", { path: operatorApprovalStorePath(store) })],
			detail: { store: operatorApprovalStorePath(store) },
		};
	}
}

/**
 * Agent environment and autonomy posture. Findings are advisory: they warn, and
 * never fail the doctor, because AIDR still enforces on a permissive host.
 */
function checkAgentEnvironment(connectors: ConnectorStatus[], deps: DoctorDeps): DoctorCheck {
	let report: AgentEnvironmentReport;
	try {
		report = deps.agentEnvironment
			? deps.agentEnvironment(connectors)
			: scanAgentEnvironment({ home: deps.home, connectors });
	} catch (error) {
		return {
			id: "agent_environment",
			status: "warn",
			summary: ct("doctor.environmentUnchecked"),
			notes: [message(error)],
		};
	}
	const serious = report.findings.filter((f) => f.severity === "critical" || f.severity === "high");
	const gaps = report.unreadable.length;
	const summary =
		report.findings.length === 0
			? ct("doctor.environmentClean")
			: ct("doctor.environmentFindings", {
					count: report.findings.length,
					serious: serious.length,
					ids: [...new Set(report.findings.map((f) => f.id))].join(", "),
				});
	return {
		id: "agent_environment",
		status: report.findings.length > 0 || gaps > 0 ? "warn" : "ok",
		summary:
			gaps > 0 ? `${summary} ${ct("doctor.environmentUnreadable", { count: gaps })}` : summary,
		...(report.findings.length > 0
			? { notes: report.findings.map((f) => `${f.id} (${f.host}): ${f.remediation}`) }
			: {}),
		detail: {
			findings: report.findings.map((f) => ({
				id: f.id,
				severity: f.severity,
				host: f.host,
				count: f.count,
				remediation: f.remediation,
				...(f.evidence.key ? { key: f.evidence.key } : {}),
				...(f.evidence.names ? { names: f.evidence.names } : {}),
			})),
			unreadable: report.unreadable,
		},
	};
}

/** Above this offset the doctor warns; signed-artifact checks still tolerate it. */
export const CLOCK_WARN_SECONDS = 60;
/**
 * Above this offset the doctor fails: it is the tolerance the core allows for
 * attestations and audit epochs, so anything larger is rejected somewhere.
 */
export const CLOCK_FAIL_SECONDS = 300;
const CLOCK_TIMEOUT_MS = 5_000;

async function headServerTime(endpoint: string): Promise<ServerTimeSample> {
	const sentAt = Date.now();
	const response = await fetch(endpoint, {
		method: "HEAD",
		redirect: "manual",
		signal: AbortSignal.timeout(CLOCK_TIMEOUT_MS),
	});
	const receivedAt = Date.now();
	const header = response.headers.get("date");
	const parsed = header ? Date.parse(header) : Number.NaN;
	return { sentAt, receivedAt, serverAt: Number.isFinite(parsed) ? parsed : null };
}

/**
 * Local clock against the control plane's. Only in managed mode with an
 * endpoint: a local-only install has no reference clock and makes no network
 * call here. `Date` has one-second resolution, so an offset within half the
 * round trip plus one second is reported as in sync.
 */
async function checkClock(config: Config, deps: DoctorDeps): Promise<DoctorCheck | null> {
	const endpoint = config.control_plane.endpoint;
	if (config.mode !== "managed" || !config.control_plane.enabled || !endpoint) return null;
	const read = deps.serverTime ?? headServerTime;
	let sample: ServerTimeSample;
	try {
		sample = await read(endpoint);
	} catch (error) {
		return {
			id: "clock",
			status: "warn",
			summary: ct("doctor.clockUnchecked", { reason: message(error) }),
			notes: [ct("doctor.clockWhy")],
			detail: { endpoint, state: "unreachable" },
		};
	}
	if (sample.serverAt === null) {
		return {
			id: "clock",
			status: "warn",
			summary: ct("doctor.clockUnchecked", { reason: "no Date header" }),
			notes: [ct("doctor.clockWhy")],
			detail: { endpoint, state: "no_date_header" },
		};
	}
	const uncertaintyMs = (sample.receivedAt - sample.sentAt) / 2 + 1_000;
	const rawOffsetMs = (sample.sentAt + sample.receivedAt) / 2 - sample.serverAt;
	const offsetMs = Math.abs(rawOffsetMs) <= uncertaintyMs ? 0 : rawOffsetMs;
	const seconds = Math.round(Math.abs(offsetMs) / 1_000);
	const direction = offsetMs > 0 ? ct("doctor.clockAhead") : ct("doctor.clockBehind");
	let status: CheckStatus = "ok";
	let summary = ct("doctor.clockOk", { seconds: CLOCK_WARN_SECONDS });
	if (seconds > CLOCK_FAIL_SECONDS) {
		status = "fail";
		summary = ct("doctor.clockSkewed", { seconds, direction });
	} else if (seconds > CLOCK_WARN_SECONDS) {
		status = "warn";
		summary = ct("doctor.clockDrift", { seconds, direction });
	}
	return {
		id: "clock",
		status,
		summary,
		notes: [ct("doctor.clockWhy")],
		detail: {
			endpoint,
			state: "compared",
			offset_ms: Math.round(offsetMs),
			uncertainty_ms: Math.round(uncertaintyMs),
			warn_seconds: CLOCK_WARN_SECONDS,
			fail_seconds: CLOCK_FAIL_SECONDS,
		},
	};
}

async function checkLastVerdict(config: Config): Promise<DoctorCheck> {
	if (!config.logging.enabled) {
		return { id: "last_verdict", status: "warn", summary: ct("doctor.auditDisabled") };
	}
	try {
		const { entries } = await readAuditEntries(auditLogFiles(config.logging));
		const last = [...entries].reverse().find((entry) => entry.type === "runtime_verdict");
		if (!last) {
			return { id: "last_verdict", status: "warn", summary: ct("doctor.noVerdict") };
		}
		const redacted = redactAuditEntry(last);
		return {
			id: "last_verdict",
			status: "ok",
			summary: ct("doctor.lastVerdict", {
				verdict: String(redacted.verdict),
				tool: String(redacted.tool_name),
				time: localTime(String(redacted.timestamp)),
			}),
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
			summary: ct("doctor.auditUnreadable"),
			notes: [message(error)],
		};
	}
}

/**
 * Windows/WSL AMSI: probe once (or read a fresh "unavailable" host record) and
 * say whether content is AMSI-scanned. Nothing is reported where the leg does
 * not apply (no AMSI on the platform, or `amsi_check.enabled: false`).
 */
async function checkAmsi(config: Config, deps: DoctorDeps): Promise<DoctorCheck | null> {
	try {
		const record = await (deps.amsiStatus ?? amsiSessionStatus)(config.amsi_check.enabled);
		if (!record) return null;
		if (record.state === "unavailable") {
			return {
				id: "amsi",
				status: "warn",
				summary: ct("doctor.amsiUnavailable"),
				notes: [record.reason],
			};
		}
		if (record.backend === "powershell-persistent") {
			return { id: "amsi", status: "warn", summary: ct("doctor.amsiSlowFallback") };
		}
		return {
			id: "amsi",
			status: "ok",
			summary: ct("doctor.amsiAvailable", { backend: record.backend }),
		};
	} catch (error) {
		return {
			id: "amsi",
			status: "warn",
			summary: ct("doctor.amsiUnavailable"),
			notes: [message(error)],
		};
	}
}

export async function runDoctor(deps: DoctorDeps = {}): Promise<DoctorReport> {
	const checks: DoctorCheck[] = [
		{ id: "core_version", status: "ok", summary: ct("doctor.version", { version: VERSION }) },
	];
	const { check: configCheck, config } = await checkConfiguration(deps);
	checks.push(configCheck);
	checks.push(checkReleaseKey(config));
	const customer = checkCustomer(deps);
	if (customer) checks.push(customer);
	const clock = await checkClock(config, deps);
	if (clock) checks.push(clock);
	checks.push(await checkRules());
	const connectors = deps.connectors
		? deps.connectors()
		: detectConnectorStatuses(deps.home ?? resolvePath("~"));
	checks.push(checkConnectors(connectors));
	const codexTrust = checkCodexTrust(connectors, deps);
	if (codexTrust) checks.push(codexTrust);
	checks.push(await checkDlp(connectors, deps, config));
	checks.push(await checkAgentProfiles(connectors, deps));
	checks.push(await checkApprovals(deps, config));
	checks.push(checkAgentEnvironment(connectors, deps));
	const amsi = await checkAmsi(config, deps);
	if (amsi) checks.push(amsi);
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

/** The human report: one line per check; the notes only with `--verbose`. */
export function formatDoctorReport(report: DoctorReport, verbose = false): string[] {
	const lines = [ct("doctor.title")];
	for (const check of report.checks) {
		lines.push(`  ${MARK[check.status]} ${check.summary}`);
		if (verbose) for (const note of check.notes ?? []) lines.push(`      ${note}`);
	}
	lines.push(report.ok ? ct("doctor.footerOk") : ct("doctor.footerFail"));
	if (!verbose && report.checks.some((c) => (c.notes?.length ?? 0) > 0)) {
		lines.push(ct("doctor.verboseHint"));
	}
	return lines;
}

/** `aidr doctor` — exits non-zero when any check fails. */
export default async function doctorCommand(
	options: { json?: boolean; verbose?: boolean } = {},
	deps: DoctorDeps = {},
): Promise<void> {
	const report = await runDoctor(deps);
	if (options.json) {
		console.log(JSON.stringify(report, null, 2));
	} else {
		for (const line of formatDoctorReport(report, options.verbose === true)) console.log(line);
	}
	if (!report.ok) process.exitCode = 1;
}
