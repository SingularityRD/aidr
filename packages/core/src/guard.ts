/**
 * Guard orchestrator for soft-gated connectors (OpenCode, OpenClaw).
 * Wraps evaluateToolCall with approval store checks, paranoid promotion,
 * and shared message formatting / allowlist operations.
 *
 * ── Approval authority ─────────────────────────────────────────────────────
 * The `ApprovalStore` is the *mechanism*; connectors must never expose it (or
 * an `approve` action wrapping it) as a tool the policed agent can call. An
 * agent that can approve its own blocked action defeats the gate entirely,
 * because it already receives the actionId in the block message. Approvals must
 * come from an out-of-band, human-only action (see `formatAskMessage`).
 *
 * The persistent out-of-band channel is `operator-approvals.ts`: every `ask`
 * issued here is recorded as a pending ask, the operator approves it with the
 * `aidr approve <actionId>` CLI (interactive confirmation), and the retry of the
 * exact same call spends that approval once. Nothing in this module can create
 * an approval.
 *
 * In MANAGED mode an `ask` is additionally submitted to the AIDR dashboard
 * (`dashboard-approvals.ts`): an administrator approves it there and the retry is
 * released by a control-plane-signed, single-use token. With
 * `operator_approvals.dashboard_only` that is the ONLY channel.
 */

import {
	addCommand,
	addFilePath,
	addUrl,
	loadAllowlist,
	removeCommand,
	removeFilePath,
	removeUrl,
	saveAllowlist,
} from "./allowlist.js";
import { ApprovalStore } from "./approval-store.js";
import {
	logAllowedResponseActions,
	logResponseActions,
	logVerdict,
	toolInputSummaryForAudit,
} from "./audit-log.js";
import { isInvalidConfig, loadConfig } from "./config.js";
import {
	DASHBOARD_APPROVAL_SOURCE,
	type DashboardApprovalOptions,
	type DashboardApprovalOutcome,
	processDashboardApproval,
} from "./dashboard-approvals.js";
import type { ToolEvaluationContext, ToolEvaluationRequest } from "./evaluator.js";
import { allowVerdict, evaluateToolCall } from "./evaluator.js";
import {
	consumeOperatorApproval,
	findOperatorAllowlistGrant,
	markOperatorAllowlistGrantUsed,
	type OperatorApprovalStoreOptions,
	recordHostDialogAsk,
	recordPendingAsk,
} from "./operator-approvals.js";
import {
	DEFAULT_RESPONSE_OPTIONS,
	type PreOperationSnapshot,
	type ResponseActionRecord,
	type ResponseOptions,
	rollbackPreOperationSnapshot,
	runPreAllowedResponseActions,
	runResponseActions,
	summarizeResponseActions,
} from "./response-actions.js";
import {
	DEFAULT_RESPONSE_AUDIT_CONFIG,
	logResponseActionToChain,
	type ResponseAuditor,
	type ResponseChainWrite,
	responseAuditorFromConfig,
} from "./response-audit.js";
import { normalizeToolEvaluationRequest } from "./tool-normalization.js";
import type { Allowlist, Artifact, Config, Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";
import { hashCommand, normalizeFilePath, normalizeUrl } from "./url-utils.js";

// ── guardToolCall ──────────────────────────────────────────────────

export interface GuardResult {
	verdict: Verdict;
	actionId?: string;
	/**
	 * Response actions taken as a result of the verdict (snapshot, ...).
	 *
	 * Empty when nothing was configured or applicable. Present so a caller can
	 * tell the user what the runtime actually did, instead of the response being
	 * invisible.
	 */
	responseActions?: ResponseActionRecord[];
	/**
	 * Set when an ALLOWED destructive call had its target snapshotted first.
	 *
	 * The call was not blocked, so the snapshot is not a response to a verdict — it
	 * is the thing that makes the allowed call reversible. Pass this whole
	 * `GuardResult` to `executeWithRollback` (or `finalizeSnapshot` /
	 * `rollbackSnapshotFromGuardResult`) once the call finishes.
	 */
	snapshot?: PreOperationSnapshot;
	/** What happened when the response was written to the signed chain. */
	signedChain?: ResponseChainWrite;
	/**
	 * Finish the snapshot lifecycle for this call. Omitted when no snapshot was
	 * taken. `rolledBack: true` means the restore succeeded. `false` also covers a
	 * failed restore, which remains retryable and is recorded in the response audit.
	 */
	finalizeSnapshot?: (outcome: "success" | "failure") => Promise<{ rolledBack: boolean }>;
	/**
	 * For an `ask`: whether the pending ask reached the operator approval store,
	 * so `aidr pending` / `aidr approve` can see it. False means the block stands
	 * but the operator cannot approve this call until the store is repaired.
	 */
	pendingRecorded?: boolean;
	/** Set when an `ask` was released by an operator or a dashboard approval. */
	approvedBy?: "operator" | "dashboard";
	/**
	 * Managed mode: what happened with the dashboard approval for this `ask`
	 * (request submitted, still pending, denied, ...). Absent in local mode.
	 */
	dashboardApproval?: DashboardApprovalOutcome;
}

/** Guard options that are not detection context. */
export interface GuardOptions {
	/**
	 * Where the file-backed operator approval channel lives. `false` disables it
	 * (callers that already have a host-native confirmation, and isolated tests).
	 */
	operatorApprovals?: OperatorApprovalStoreOptions | false;
	/**
	 * Managed-mode dashboard approvals. `false` disables them (isolated tests);
	 * the default uses the real control plane, state file and nonce ledger.
	 */
	dashboardApprovals?: DashboardApprovalOptions | false;
}

/** Whether `operator_approvals.dashboard_only` is in force (managed mode only). */
function isDashboardOnly(config: Config | undefined): boolean {
	return config?.mode === "managed" && config.operator_approvals?.dashboard_only === true;
}

/** The released verdict for an `ask` an approval channel let through. */
function releasedVerdict(verdict: Verdict, source: string, by: string): Verdict {
	return {
		...allowVerdict(source),
		artifacts: verdict.artifacts,
		matchedThreatId: verdict.matchedThreatId,
		reasons: [`Released by ${by} approval of ${verdict.category}`],
	};
}

/**
 * Run the managed dashboard approval step for an `ask` and, when a verified
 * token released it, audit the override. Never throws; null in local mode.
 */
async function dashboardApprovalStep(
	request: ToolEvaluationRequest,
	actionId: string,
	verdict: Verdict,
	config: Config,
	connector: string | undefined,
	logger: Logger,
	options: DashboardApprovalOptions | false | undefined,
): Promise<{ outcome: DashboardApprovalOutcome | null; released: Verdict | null }> {
	if (options === false || config.mode !== "managed") return { outcome: null, released: null };
	const outcome = await processDashboardApproval(
		{
			actionId,
			toolName: request.toolName,
			toolInput: request.toolInput,
			artifacts: request.artifacts,
			sessionId: request.sessionId,
			verdict,
			connector,
		},
		config,
		{ logger, ...options },
	);
	if (!outcome) return { outcome: null, released: null };
	if (isDashboardOnly(config)) outcome.dashboardOnly = true;
	if (outcome.status !== "released") return { outcome, released: null };
	const released = releasedVerdict(verdict, DASHBOARD_APPROVAL_SOURCE, "dashboard");
	if (config.logging) {
		await logVerdict(
			config.logging,
			request.sessionId,
			request.toolName,
			request.toolInput,
			released,
			true,
		);
	}
	return { outcome, released };
}

/** Result of {@link resolveAskWithDashboardApproval}. */
export interface AskApprovalResolution {
	/** The released allow verdict, or the unchanged input verdict. */
	verdict: Verdict;
	approvedBy?: "dashboard";
	dashboardApproval?: DashboardApprovalOutcome;
	/**
	 * `operator_approvals.dashboard_only` is in force: a host with its own
	 * confirmation dialog must BLOCK instead of asking, since only a dashboard
	 * approval may release the call.
	 */
	dashboardOnly: boolean;
}

/**
 * Dashboard approvals for connectors that call `evaluateToolCall` directly and
 * have a native confirmation dialog (Claude Code, Cursor / VS Code hook).
 *
 * Pass the verdict the evaluator returned. For an `ask` in managed mode this
 * submits or polls the dashboard request and releases the call when a verified,
 * unspent token for exactly this call exists. Everything else is returned
 * unchanged. Never throws: a failure keeps the verdict.
 */
export async function resolveAskWithDashboardApproval(
	request: ToolEvaluationRequest,
	verdict: Verdict,
	context: Pick<ToolEvaluationContext, "configPath" | "logger" | "agentRuntime">,
	options: DashboardApprovalOptions | false = {},
): Promise<AskApprovalResolution> {
	const logger = context.logger ?? nullLogger;
	const unchanged: AskApprovalResolution = { verdict, dashboardOnly: false };
	if (verdict.decision !== "ask") return unchanged;
	try {
		const config = await loadConfig(context.configPath, logger);
		if (!config || isInvalidConfig(config)) return unchanged;
		const dashboardOnly = isDashboardOnly(config);
		const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);
		const { outcome, released } = await dashboardApprovalStep(
			request,
			actionId,
			verdict,
			config,
			context.agentRuntime,
			logger,
			options,
		);
		if (released) {
			return {
				verdict: released,
				approvedBy: "dashboard",
				dashboardApproval: outcome ?? undefined,
				dashboardOnly,
			};
		}
		return { verdict, dashboardApproval: outcome ?? undefined, dashboardOnly };
	} catch (error) {
		logger.warn("Dashboard approval resolution failed; the verdict is unchanged", {
			error: error instanceof Error ? error.name : typeof error,
		});
		return unchanged;
	}
}

// ── Host-dialog connectors (Claude Code, Cursor / VS Code) ─────────────

/** How a host with its own confirmation dialog resolves an `ask`. */
export type HostAskMode = "host_dialog" | "operator";

/**
 * Longest the default (`host_dialog`) path waits to list an ask in `aidr
 * pending`. The record is informational, so it must never delay the hook.
 */
export const HOST_DIALOG_RECORD_BUDGET_MS = 1_500;

/**
 * The approval mode in force. `operator` only when the config asks for it AND
 * `dashboard_only` is not in force (then only the dashboard may release a call).
 */
export function hostAskMode(config: Config | undefined): HostAskMode {
	if (isDashboardOnly(config)) return "host_dialog";
	return config?.operator_approvals?.mode === "operator" ? "operator" : "host_dialog";
}

export interface HostAskOptions {
	/** Managed-mode dashboard approvals; `false` disables them (isolated tests). */
	dashboardApprovals?: DashboardApprovalOptions | false;
	/** The operator approval store; `false` disables it (isolated tests). */
	operatorApprovals?: OperatorApprovalStoreOptions | false;
}

/** Result of {@link resolveHostAsk}. */
export interface HostAskResolution {
	/** The released allow verdict, or the unchanged input verdict. */
	verdict: Verdict;
	approvedBy?: "dashboard" | "operator";
	dashboardApproval?: DashboardApprovalOutcome;
	/** `operator_approvals.dashboard_only`: the host must block, not ask. */
	dashboardOnly: boolean;
	mode: HostAskMode;
	/**
	 * `operator` mode, unreleased ask: the host must DENY the call and show
	 * `message` (the approval reference and how the user approves it out of band).
	 * The host's own dialog must never be shown, since it would let the policed
	 * session's user interface, not the operator CLI, release the call.
	 */
	operatorHold?: { actionId: string; pendingRecorded: boolean; message: string };
	/** `host_dialog` mode: whether the ask was listed in `aidr pending` (informational). */
	informationalRecorded?: boolean;
}

function withBudget<T>(work: Promise<T>, ms: number): Promise<T | "timeout"> {
	let timer: NodeJS.Timeout | undefined;
	const timeout = new Promise<"timeout">((resolve) => {
		timer = setTimeout(() => resolve("timeout"), ms);
		timer.unref?.();
	});
	return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

/** Everything one `resolveHostAsk` call shares between its steps. */
interface HostAskCall {
	request: ToolEvaluationRequest;
	verdict: Verdict;
	config: Config;
	logger: Logger;
	connector: ToolEvaluationContext["agentRuntime"];
	actionId: string;
	operatorStore: OperatorApprovalStoreOptions | null;
}

function pendingAskInput(call: HostAskCall) {
	return {
		actionId: call.actionId,
		toolName: call.request.toolName,
		toolInput: call.request.toolInput,
		artifacts: call.request.artifacts,
		sessionId: call.request.sessionId,
		verdict: call.verdict,
		connector: call.connector,
	};
}

/** Spend an operator approval for exactly this call; the released verdict, or null. */
async function spendHostOperatorApproval(call: HostAskCall): Promise<Verdict | null> {
	if (!call.operatorStore) return null;
	const { request } = call;
	const consumed = await consumeOperatorApproval(
		{ actionId: call.actionId, tool: request.toolName, artifacts: request.artifacts },
		call.operatorStore,
	);
	if (!consumed.approved) {
		if (consumed.reason !== "not_found") {
			call.logger.warn("Operator approval was not applied; the ask stays blocked", {
				reason: consumed.reason,
			});
		}
		return null;
	}
	const released = releasedVerdict(call.verdict, "operator_approval", "operator");
	if (call.config.logging) {
		await logVerdict(
			call.config.logging,
			request.sessionId,
			request.toolName,
			request.toolInput,
			released,
			true,
		);
	}
	return released;
}

/** Operator mode: record the approvable pending ask and build the hold. */
async function holdForOperator(
	call: HostAskCall,
	dashboardApproval?: DashboardApprovalOutcome,
): Promise<NonNullable<HostAskResolution["operatorHold"]>> {
	let pendingRecorded = false;
	if (call.operatorStore) {
		try {
			await recordPendingAsk(pendingAskInput(call), call.operatorStore);
			pendingRecorded = true;
		} catch (error) {
			call.logger.warn("Pending ask could not be recorded for operator approval", {
				error: error instanceof Error ? error.name : typeof error,
			});
		}
	}
	return {
		actionId: call.actionId,
		pendingRecorded,
		message: formatAskMessage(
			call.actionId,
			call.verdict,
			call.request.artifacts,
			undefined,
			pendingRecorded,
			dashboardApproval,
		),
	};
}

/** host_dialog mode: list the ask in `aidr pending` (informational), within a budget. */
async function recordInformationalAsk(call: HostAskCall): Promise<boolean | undefined> {
	if (!call.operatorStore) return undefined;
	const recorded = await withBudget(
		recordHostDialogAsk(pendingAskInput(call), call.operatorStore).then(
			() => true,
			() => false,
		),
		HOST_DIALOG_RECORD_BUDGET_MS,
	);
	return recorded === true;
}

async function resolveLoadedHostAsk(
	call: HostAskCall,
	mode: HostAskMode,
	dashboardOnly: boolean,
	dashboardOptions: DashboardApprovalOptions | false | undefined,
): Promise<HostAskResolution> {
	const base = { dashboardOnly, mode };
	if (mode === "operator") {
		const released = await spendHostOperatorApproval(call);
		if (released) return { ...base, verdict: released, approvedBy: "operator" };
	}
	const step = await dashboardApprovalStep(
		call.request,
		call.actionId,
		call.verdict,
		call.config,
		call.connector,
		call.logger,
		dashboardOptions,
	);
	const dashboardApproval = step.outcome ?? undefined;
	if (step.released) {
		return { ...base, verdict: step.released, approvedBy: "dashboard", dashboardApproval };
	}
	if (mode === "operator") {
		return {
			...base,
			verdict: call.verdict,
			dashboardApproval,
			operatorHold: await holdForOperator(call, dashboardApproval),
		};
	}
	return {
		...base,
		verdict: call.verdict,
		dashboardApproval,
		informationalRecorded: await recordInformationalAsk(call),
	};
}

/**
 * The `ask` path for connectors whose host has a native confirmation dialog
 * (Claude Code PreToolUse, the Cursor / VS Code hook). Pass the verdict the
 * evaluator returned; anything but an `ask` is returned unchanged.
 *
 * - `operator_approvals.mode: operator`: an unspent `aidr approve` for exactly
 *   this call (same action id, tool and artifact set; HMAC under the OS-vault
 *   key; spent once in the consumption ledger) releases it. Otherwise the ask is
 *   recorded as an approvable pending ask and `operatorHold` tells the host to
 *   deny with the approval reference. `paranoid` sensitivity turns the ask into
 *   a plain deny, as on the soft-gated connectors.
 * - `host_dialog` (default): behaviour is unchanged; the ask is additionally
 *   listed in `aidr pending` as an informational, never-approvable record.
 *
 * Managed-mode dashboard approvals apply in both modes. Nothing here can create
 * an approval: that is only `aidr approve` (TTY-confirmed) or the dashboard.
 * Never throws: a failure keeps the verdict, and in operator mode keeps the hold.
 */
export async function resolveHostAsk(
	request: ToolEvaluationRequest,
	verdict: Verdict,
	context: Pick<ToolEvaluationContext, "configPath" | "logger" | "agentRuntime">,
	options: HostAskOptions = {},
): Promise<HostAskResolution> {
	const logger = context.logger ?? nullLogger;
	const unchanged: HostAskResolution = { verdict, dashboardOnly: false, mode: "host_dialog" };
	if (verdict.decision !== "ask") return unchanged;
	const config = await loadConfig(context.configPath, logger).catch(() => null);
	if (!config || isInvalidConfig(config)) return unchanged;
	const dashboardOnly = isDashboardOnly(config);
	const mode = hostAskMode(config);
	if (mode === "operator" && config.sensitivity === "paranoid") {
		// Same rule as the soft-gated connectors: a paranoid ask is a deny that no
		// approval channel can release.
		return { verdict: { ...verdict, decision: "deny" }, dashboardOnly, mode };
	}
	const call: HostAskCall = {
		request,
		verdict,
		config,
		logger,
		connector: context.agentRuntime,
		actionId: ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId),
		operatorStore:
			options.operatorApprovals === false
				? null
				: {
						logger,
						keyStorage: config.operator_approvals?.key_storage,
						...options.operatorApprovals,
					},
	};
	try {
		return await resolveLoadedHostAsk(call, mode, dashboardOnly, options.dashboardApprovals);
	} catch (error) {
		logger.warn("Host ask resolution failed; the verdict is unchanged", {
			error: error instanceof Error ? error.name : typeof error,
		});
		if (mode !== "operator") return { ...unchanged, dashboardOnly };
		return {
			verdict,
			dashboardOnly,
			mode,
			operatorHold: {
				actionId: call.actionId,
				pendingRecorded: false,
				message: formatAskMessage(call.actionId, verdict, request.artifacts, undefined, false),
			},
		};
	}
}

/**
 * Read the response settings off a config object defensively.
 *
 * Partial or mocked config objects exist in practice (and in tests), and a missing
 * `response` block must mean "no response actions" - never a crash on the security
 * path, and never an accidentally enabled mutation.
 *
 * The same applies to a MISSING SIBLING: Zod's nested `.default({})` only fires
 * when the key itself is absent, so `response: { actions: {...} }` leaves
 * `response.audit` undefined. Absent therefore has to be handled here, not assumed
 * away.
 */
function resolveResponseActions(config: Config): Partial<ResponseOptions> {
	const actions = config.response?.actions;
	return {
		snapshotOnDeny: actions?.snapshot_on_deny ?? DEFAULT_RESPONSE_OPTIONS.snapshotOnDeny,
		snapshotDir: actions?.snapshot_dir ?? DEFAULT_RESPONSE_OPTIONS.snapshotDir,
		snapshotMinSeverity:
			actions?.snapshot_min_severity ?? DEFAULT_RESPONSE_OPTIONS.snapshotMinSeverity,
		snapshotMaxBytes: actions?.snapshot_max_bytes ?? DEFAULT_RESPONSE_OPTIONS.snapshotMaxBytes,
		snapshotBeforeDestructive:
			actions?.snapshot_before_destructive ?? DEFAULT_RESPONSE_OPTIONS.snapshotBeforeDestructive,
		protectPaths: actions?.protect_paths ?? DEFAULT_RESPONSE_OPTIONS.protectPaths,
		snapshotRootDir: actions?.snapshot_root_dir ?? DEFAULT_RESPONSE_OPTIONS.snapshotRootDir,
		snapshotRetentionDays:
			actions?.snapshot_retention_days ?? DEFAULT_RESPONSE_OPTIONS.snapshotRetentionDays,
		snapshotMaxTotalBytes:
			actions?.snapshot_max_total_bytes ?? DEFAULT_RESPONSE_OPTIONS.snapshotMaxTotalBytes,
	};
}

/** Response settings resolved from config, for callers wrapping the operation. */
export interface GuardResponseSettings {
	responseOptions: Partial<ResponseOptions>;
	auditor?: ResponseAuditor;
	/** Why the signed chain is unavailable, when it is. */
	chainUnavailableReason?: string;
}

/**
 * Resolve the response configuration once, so the guard and the
 * rollback wrapper cannot disagree about which snapshot directory to use.
 */
export async function resolveGuardResponseSettings(
	configPath: string | undefined,
	logger: Logger = nullLogger,
): Promise<GuardResponseSettings> {
	const config = (await loadConfig(configPath, logger)) ?? ({} as Config);
	return guardResponseSettingsFromConfig(config, logger);
}

function guardResponseSettingsFromConfig(config: Config, logger: Logger): GuardResponseSettings {
	const { auditor, unavailableReason } = responseAuditorFromConfig(
		// `response.audit` is genuinely optional: `.default({})` on a nested object is
		// not applied when a sibling key is present. Defaulted here so "off" is the
		// answer for a partial config rather than an exception.
		config.response?.audit ?? DEFAULT_RESPONSE_AUDIT_CONFIG,
		logger,
	);
	return {
		responseOptions: resolveResponseActions(config),
		auditor,
		chainUnavailableReason: unavailableReason,
	};
}

/** Bounded, redacted description of the call, shared by every audit surface. */
export function guardInputSummary(toolName: string, toolInput: Record<string, unknown>): string {
	return toolInputSummaryForAudit(toolName, toolInput);
}

/**
 * Roll an allowed destructive operation back from the snapshot the guard took.
 *
 * Never throws: the caller has already told the user the operation failed, and a
 * rollback problem must not replace that error with a confusing one. The returned
 * record says whether the target was actually restored.
 */
export async function rollbackSnapshotFromGuardResult(
	result: GuardResult,
	request: {
		toolName: string;
		toolInput?: Record<string, unknown>;
		sessionId: string;
		configPath?: string;
	},
	settings: Pick<
		GuardResponseSettings,
		"responseOptions" | "auditor" | "chainUnavailableReason"
	> = {
		responseOptions: {},
	},
	logger: Logger = nullLogger,
): Promise<ResponseActionRecord | null> {
	if (!result.snapshot) return null;

	// Resolve the chain from config when the caller did not hand one over.
	//
	// This is not a convenience: a rollback that is not on the signed chain is
	// indistinguishable from a rollback that never happened, so silently skipping
	// the write because a caller forgot an argument would quietly destroy the
	// evidence. Failures inside `loadConfig` are already handled there.
	let effectiveSettings: GuardResponseSettings = settings;
	if (!settings.auditor) {
		const resolved = await resolveGuardResponseSettings(request.configPath, logger);
		effectiveSettings = {
			auditor: resolved.auditor,
			responseOptions:
				Object.keys(settings.responseOptions).length > 0
					? settings.responseOptions
					: resolved.responseOptions,
			chainUnavailableReason: resolved.chainUnavailableReason,
		};
	}

	const record = await rollbackPreOperationSnapshot(
		result.snapshot,
		{
			toolName: request.toolName,
			toolInput: request.toolInput,
			sessionId: request.sessionId,
			verdict: result.verdict,
		},
		effectiveSettings.responseOptions,
		logger,
		effectiveSettings.auditor,
	);

	// The plain audit log gets the same record shape as every other response, and
	// the signed chain gets the tamper-evident one.
	try {
		const loggingConfig = (await loadConfig(request.configPath, logger))?.logging;
		if (loggingConfig) {
			await logAllowedResponseActions(
				loggingConfig,
				request.sessionId,
				request.toolName,
				result.verdict,
				[record],
			);
		}
	} catch (error) {
		logger.warn("Rollback happened but the plain audit entry could not be written", {
			error: String(error),
		});
	}

	if (effectiveSettings.auditor) {
		await logResponseActionToChain(
			effectiveSettings.auditor,
			[record],
			{
				decision: "allow",
				toolName: request.toolName,
				inputSummary: guardInputSummary(request.toolName, request.toolInput ?? {}),
				sessionId: request.sessionId,
				verdict: result.verdict,
				snapshotId: result.snapshot.id,
				snapshotTarget: result.snapshot.target,
			},
			logger,
		);
	} else {
		logger.warn("Rollback completed but was NOT recorded in the signed chain", {
			reason: effectiveSettings.chainUnavailableReason ?? "unknown",
			snapshotId: result.snapshot.id,
		});
	}

	return record;
}

/** Tools `runPreAllowedResponseActions` can find a destructive target for. */
const SNAPSHOT_CANDIDATE_TOOLS = new Set([
	"write",
	"edit",
	"multiedit",
	"delete",
	"notebookedit",
	"remove",
	"move",
	"rename",
	"bash",
	"shell",
	"execute",
]);

/** What `snapshotBeforeAllowedToolCall` did. */
export interface AllowedCallSnapshotResult {
	records: ResponseActionRecord[];
	snapshot: PreOperationSnapshot | null;
	signedChain?: ResponseChainWrite;
}

/**
 * Pre-operation snapshot for connectors that evaluate with `evaluateToolCall`
 * directly instead of `guardToolCall` (Claude Code, Cursor, VS Code): the same
 * allowed-path response `guardToolCall` takes, so a destructive call on a
 * protected path is snapshotted before it runs, whichever host ran it.
 *
 * Doubly opt-in exactly like the guard (`snapshot_before_destructive` plus a
 * non-empty `protect_paths`); with either off this returns after reading the
 * config and copies nothing. Never throws and never changes the verdict.
 */
export async function snapshotBeforeAllowedToolCall(
	request: { toolName: string; toolInput: Record<string, unknown>; sessionId: string },
	verdict: Verdict,
	options: { configPath?: string; logger?: Logger; config?: Config } = {},
): Promise<AllowedCallSnapshotResult> {
	const logger = options.logger ?? nullLogger;
	const none: AllowedCallSnapshotResult = { records: [], snapshot: null };
	// Cheap gate first: most calls cannot destroy a file, and they must not pay
	// for a config read on the hook's hot path.
	if (
		verdict.decision !== "allow" ||
		!SNAPSHOT_CANDIDATE_TOOLS.has(request.toolName.toLowerCase())
	) {
		return none;
	}
	try {
		const config = options.config ?? (await loadConfig(options.configPath, logger));
		const actions = config.response?.actions;
		if (!actions?.snapshot_before_destructive || (actions.protect_paths ?? []).length === 0) {
			return none;
		}
		const settings = guardResponseSettingsFromConfig(config, logger);
		const preAllowed = await runPreAllowedResponseActions(
			verdict,
			request,
			settings.responseOptions,
			logger,
		);
		if (preAllowed.records.length === 0) return preAllowed;
		if (config.logging) {
			await logAllowedResponseActions(
				config.logging,
				request.sessionId,
				request.toolName,
				verdict,
				preAllowed.records,
			);
		}
		let signedChain: ResponseChainWrite | undefined;
		if (settings.auditor) {
			signedChain = await logResponseActionToChain(
				settings.auditor,
				preAllowed.records,
				{
					decision: "allow",
					toolName: request.toolName,
					inputSummary: guardInputSummary(request.toolName, request.toolInput),
					sessionId: request.sessionId,
					verdict,
					snapshotId: preAllowed.snapshot?.id,
					snapshotTarget: preAllowed.snapshot?.target,
				},
				logger,
			);
		} else if (settings.chainUnavailableReason) {
			signedChain = { written: false, reason: settings.chainUnavailableReason };
		}
		return { ...preAllowed, signedChain };
	} catch (error) {
		// A snapshot is a response, never a reason to change the decision.
		logger.warn("Pre-operation snapshot could not be taken", { error: String(error) });
		return none;
	}
}

export async function guardToolCall(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	approvalStore: ApprovalStore,
	options: GuardOptions = {},
): Promise<GuardResult> {
	const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);
	// Consume synchronously before awaiting evaluation so concurrent identical
	// calls cannot both spend the same out-of-band approval.
	const hasApproval = approvalStore.consumeApproval(actionId);

	const verdict = await evaluateToolCall(request, { ...context, promoteParanoidAsk: true });

	const logger = context.logger ?? nullLogger;
	// Needed for paranoid promotion and for the response settings. Read defensively:
	// a config read that yields nothing must not crash the security path, and must
	// not accidentally enable a response action.
	const loadedConfig = await loadConfig(context.configPath, logger);
	const config = loadedConfig ?? ({} as Config);

	let effective = verdict;
	if (verdict.decision === "ask" && config.sensitivity === "paranoid") {
		effective = { ...verdict, decision: "deny" };
	}
	const operatorStore =
		options.operatorApprovals === false
			? null
			: {
					logger,
					keyStorage: config.operator_approvals?.key_storage,
					...options.operatorApprovals,
				};
	const approvable = effective.decision === "ask" && loadedConfig && !isInvalidConfig(loadedConfig);
	// Managed + dashboard_only: the local operator CLI is not an approval channel.
	const dashboardOnly = isDashboardOnly(config);
	let approvedBy: GuardResult["approvedBy"];
	let dashboardApproval: DashboardApprovalOutcome | undefined;
	if (approvable && hasApproval) {
		effective = allowVerdict("approved");
	} else if (approvable && operatorStore && !dashboardOnly) {
		// The persistent operator channel. It only ever releases an `ask` (never a
		// deny or a paranoid-promoted ask), only for the exact tool and artifact set
		// the operator saw, and it never throws: any failure keeps the block.
		const consumed = await consumeOperatorApproval(
			{ actionId, tool: request.toolName, artifacts: request.artifacts },
			operatorStore,
		);
		if (consumed.approved) {
			effective = releasedVerdict(verdict, "operator_approval", "operator");
			approvedBy = "operator";
			// The release is an operator override of a flagged call: record it.
			if (config.logging) {
				await logVerdict(
					config.logging,
					request.sessionId,
					request.toolName,
					request.toolInput,
					effective,
					true,
				);
			}
		} else if (consumed.reason !== "not_found") {
			logger.warn("Operator approval was not applied; the ask stays blocked", {
				reason: consumed.reason,
			});
		}
	}
	if (approvable && effective.decision === "ask") {
		// Managed mode: the dashboard channel (submit, poll, verify, spend once).
		const step = await dashboardApprovalStep(
			request,
			actionId,
			verdict,
			config,
			context.agentRuntime,
			logger,
			options.dashboardApprovals,
		);
		dashboardApproval = step.outcome ?? undefined;
		if (step.released) {
			effective = step.released;
			approvedBy = "dashboard";
		}
	}

	const responseOptions = resolveResponseActions(config);
	const normalizedRequest = normalizeToolEvaluationRequest(request);
	const responseRequest =
		normalizedRequest.toolInput.__aidr_input_normalization_failed === true ||
		normalizedRequest.toolInput.__aidr_malformed_command === true ||
		normalizedRequest.toolInput.__aidr_patch_parse_failed === true
			? { toolName: "unknown", toolInput: {} }
			: normalizedRequest;
	const { auditor, unavailableReason } = responseAuditorFromConfig(
		config.response?.audit ?? DEFAULT_RESPONSE_AUDIT_CONFIG,
		logger,
	);
	const inputSummary = guardInputSummary(request.toolName, request.toolInput);

	let responseActions: ResponseActionRecord[] = [];
	let signedChain: ResponseChainWrite | undefined;

	if (effective.decision !== "allow") {
		// Run the configured response actions for a blocking decision. This happens
		// before returning so the caller can report what was done, and it can never
		// change the verdict itself.
		responseActions = await runResponseActions(
			effective,
			{ toolName: responseRequest.toolName, toolInput: responseRequest.toolInput },
			responseOptions,
			logger,
		);

		// Record what the runtime did. Without this the response would be
		// invisible: an operator could not tell whether a file had been touched.
		if (responseActions.length > 0 && config.logging) {
			await logResponseActions(
				config.logging,
				request.sessionId,
				request.toolName,
				effective,
				responseActions,
			);
		}
		if (auditor && responseActions.length > 0) {
			signedChain = await logResponseActionToChain(
				auditor,
				responseActions,
				{
					decision: effective.decision === "ask" ? "ask" : "deny",
					toolName: request.toolName,
					inputSummary,
					sessionId: request.sessionId,
					verdict: effective,
				},
				logger,
			);
		}

		if (effective.decision === "deny") {
			return { verdict: effective, responseActions, signedChain };
		}

		approvalStore.setPending(actionId, {
			artifacts: request.artifacts,
			createdAt: Date.now(),
		});

		let pendingRecorded: boolean | undefined;
		if (operatorStore && !dashboardOnly) {
			try {
				await recordPendingAsk(
					{
						actionId,
						toolName: request.toolName,
						toolInput: request.toolInput,
						artifacts: request.artifacts,
						sessionId: request.sessionId,
						verdict: effective,
						connector: context.agentRuntime,
					},
					operatorStore,
				);
				pendingRecorded = true;
			} catch (error) {
				// The call stays blocked either way; only the approval path is lost.
				pendingRecorded = false;
				logger.warn("Pending ask could not be recorded for operator approval", {
					error: error instanceof Error ? error.name : typeof error,
				});
			}
		}

		return {
			verdict: effective,
			actionId,
			responseActions,
			signedChain,
			pendingRecorded,
			dashboardApproval,
		};
	}

	// ── Allowed path ────────────────────────────────────────────────
	//
	// The call is going to run. If it is destructive and targets a protected path,
	// preserve the target FIRST so a failed or regretted operation can be undone.
	// This is the only place in the product that makes an allowed operation
	// reversible, and it is doubly opt-in (flag + non-empty protect_paths).
	//
	// The auditor is deliberately NOT threaded in here: `guardToolCall` is the single
	// writer for this call's signed-chain entry, so a response can never produce two
	// chain records for one decision.
	const preAllowed = await runPreAllowedResponseActions(
		effective,
		{
			toolName: responseRequest.toolName,
			toolInput: responseRequest.toolInput,
			sessionId: request.sessionId,
		},
		responseOptions,
		logger,
	);

	if (preAllowed.records.length === 0) {
		return { verdict: effective, responseActions: [], signedChain, approvedBy };
	}

	if (config.logging) {
		await logAllowedResponseActions(
			config.logging,
			request.sessionId,
			request.toolName,
			effective,
			preAllowed.records,
		);
	}
	if (auditor) {
		signedChain = await logResponseActionToChain(
			auditor,
			preAllowed.records,
			{
				decision: "allow",
				toolName: request.toolName,
				inputSummary,
				sessionId: request.sessionId,
				verdict: effective,
				snapshotId: preAllowed.snapshot?.id,
				snapshotTarget: preAllowed.snapshot?.target,
			},
			logger,
		);
	} else if (unavailableReason) {
		// A response happened but there is no chain to record it in. Say so in the
		// result rather than leaving the caller to infer it from an absent field:
		// "we did something and could not record it" is information the operator
		// needs, and an absent `signedChain` reads as "nothing to report".
		signedChain = { written: false, reason: unavailableReason };
	}

	const snapshot = preAllowed.snapshot;
	let finalized = false;
	let rollbackInFlight: Promise<{ rolledBack: boolean }> | null = null;
	const result: GuardResult = {
		verdict: effective,
		responseActions: preAllowed.records,
		snapshot: snapshot ?? undefined,
		signedChain,
		approvedBy,
	};

	if (snapshot) {
		result.finalizeSnapshot = async (outcome) => {
			if (rollbackInFlight) return rollbackInFlight;
			if (finalized) return { rolledBack: false };
			if (outcome === "success") {
				finalized = true;
				return { rolledBack: false };
			}
			rollbackInFlight = (async () => {
				const record = await rollbackSnapshotFromGuardResult(
					result,
					{
						toolName: request.toolName,
						toolInput: request.toolInput,
						sessionId: request.sessionId,
						configPath: context.configPath,
					},
					{ responseOptions, auditor },
					logger,
				);
				if (record?.outcome !== "success") return { rolledBack: false };
				finalized = true;
				return { rolledBack: true };
			})();
			try {
				return await rollbackInFlight;
			} finally {
				rollbackInFlight = null;
			}
		};
	}

	if (snapshot && !signedChain?.written) {
		// The snapshot exists but the tamper-evident record of it does not. Report
		// that plainly: a caller must not be able to read `snapshot` and assume the
		// chain holds the corresponding entry.
		logger.warn("Pre-operation snapshot taken but NOT recorded in the signed chain", {
			reason: signedChain?.reason ?? unavailableReason ?? "unknown",
			detail: signedChain?.detail,
			snapshotId: snapshot.id,
		});
	}

	return result;
}

/**
 * Run an allowed operation with the snapshot the guard already took, rolling the
 * target back if the operation fails.
 *
 * This is the end-to-end shape of a real response: `guardToolCall` allowed the
 * call and preserved the target, the connector runs the call, and this wrapper
 * decides what to do about the outcome. When the guard did not take a snapshot
 * (feature off, unprotected path, nothing to preserve) it simply runs the
 * operation — it never weakens the decision and never invents a rollback.
 */
export async function executeWithRollback<T>(
	result: GuardResult,
	request: { toolName: string; toolInput?: Record<string, unknown>; sessionId: string },
	operation: () => Promise<T>,
	settings: Pick<GuardResponseSettings, "responseOptions" | "auditor"> & {
		onFailure?: "rollback" | "notify";
	} = { responseOptions: {} },
	logger: Logger = nullLogger,
): Promise<T> {
	try {
		return await operation();
	} catch (error) {
		const shouldRollback = (settings.onFailure ?? "rollback") === "rollback";
		if (shouldRollback && result.snapshot && result.finalizeSnapshot) {
			// The guard's finalize handle records the rollback in the plain log AND the
			// signed chain. It reports its own failure, which must not replace the
			// operation's error — that is the error the caller needs to see.
			try {
				await result.finalizeSnapshot("failure");
			} catch (rollbackError) {
				logger.error("Rollback after a failed operation did not complete", {
					snapshotId: result.snapshot.id,
					error: String(rollbackError),
				});
			}
		}
		throw error;
	}
}

// ── Message formatting ─────────────────────────────────────────────

const MAX_ARTIFACT_VALUE_LEN = 120;

function truncateValue(value: string): string {
	const singleLine = value.replaceAll("\n", "\\n");
	if (singleLine.length <= MAX_ARTIFACT_VALUE_LEN) return singleLine;
	return `${singleLine.slice(0, MAX_ARTIFACT_VALUE_LEN)}…`;
}

export function summarizeArtifacts(artifacts: Artifact[]): string {
	if (artifacts.length === 0) return "none";
	return artifacts
		.slice(0, 3)
		.map((artifact) => `${artifact.type} '${truncateValue(artifact.value)}'`)
		.join(", ");
}

/**
 * Line telling the user what the runtime DID, so a response action is visible
 * rather than silent. Returns null only when nothing was attempted or every
 * action was a deliberate skip (not something the user must act on).
 */
function responseLine(actions?: ResponseActionRecord[]): string | null {
	if (!actions || actions.length === 0) return null;
	const parts: string[] = [];

	const succeeded = summarizeResponseActions(actions);
	if (succeeded) parts.push(succeeded);

	// A FAILED action must be reported even when nothing succeeded, otherwise the
	// user is told only that the call was blocked and never learns that the
	// runtime tried and failed to preserve anything.
	const failures = actions.filter((a) => a.outcome === "failure");
	if (failures.length > 0) {
		parts.push(
			`response action(s) failed: ${failures
				.map((f) => `${f.action} (${f.reason ?? "unknown"})`)
				.join(", ")} - nothing was preserved`,
		);
	}

	return parts.length > 0 ? parts.join("; ") : null;
}

/**
 * The severity line, and the rule line when a rule or policy decided the
 * verdict. The label is the rule's own severity whenever one is known, so a
 * `high` rule is never shown as `warning` next to its id.
 */
export function verdictRuleLines(verdict: Verdict): string[] {
	const lines = [`Severity: ${verdict.ruleSeverity ?? verdict.severity}`];
	if (verdict.matchedThreatId) lines.push(`Rule: ${verdict.matchedThreatId}`);
	return lines;
}

export function formatDenyMessage(verdict: Verdict, actions?: ResponseActionRecord[]): string {
	const reasons =
		verdict.reasons.length > 0 ? verdict.reasons.slice(0, 5).join("; ") : verdict.category;

	const lines = [
		"Singularity AIDR blocked this action.",
		...verdictRuleLines(verdict),
		`Category: ${verdict.category}`,
		`Reason: ${reasons}`,
	];

	const responded = responseLine(actions);
	if (responded) lines.push(`Response: ${responded}`);

	return lines.join("\n");
}

/**
 * The user-facing lines about a managed-mode dashboard approval, or null when
 * there is nothing to say (local mode, or the call was released). Shared by
 * every connector so the wording is the same everywhere; it names the request
 * id and never offers the agent a way to approve.
 */
export function formatDashboardApprovalNotice(
	outcome: DashboardApprovalOutcome | undefined,
): string | null {
	if (!outcome) return null;
	const id = outcome.requestId;
	switch (outcome.status) {
		case "released":
			return null;
		case "requested":
		case "pending":
			return [
				`Approval requested in the AIDR dashboard: ${id}`,
				"(For the user: an AIDR administrator must approve this request in the dashboard; the",
				"approval then covers one retry of this exact call.)",
			].join("\n");
		case "denied":
			return `The AIDR dashboard approval request ${id} was denied; the action stays blocked.`;
		case "expired":
			return `The AIDR dashboard approval request ${id} expired; the action stays blocked.`;
		case "rejected":
			return `The AIDR dashboard approval for request ${id} could not be verified (${outcome.reason ?? "unknown"}); the action stays blocked.`;
		case "request_failed":
			return `The approval request could not be sent to the AIDR dashboard (${outcome.reason ?? "unknown"}); the action stays blocked.`;
		case "unavailable":
			// Only worth saying when the dashboard is the sole channel; otherwise the
			// local operator channel below still applies.
			return outcome.dashboardOnly
				? `AIDR dashboard approvals are unavailable (${outcome.reason ?? "unknown"}); the action stays blocked.`
				: null;
	}
}

/**
 * The block message for an `ask`. Pass `pendingRecorded` from the
 * {@link GuardResult}: when it is `false` the ask never reached the operator
 * approval store (approvals disabled, or the store is broken), and the message
 * says so instead of sending the user to `aidr approve`. Pass
 * `dashboardApproval` too, so a managed-mode request id reaches the user.
 */
export function formatAskMessage(
	actionId: string,
	verdict: Verdict,
	artifacts: Artifact[],
	actions?: ResponseActionRecord[],
	pendingRecorded?: boolean,
	dashboardApproval?: DashboardApprovalOutcome,
): string {
	const reasons =
		verdict.reasons.length > 0 ? verdict.reasons.slice(0, 3).join("; ") : verdict.category;

	const lines = [
		"Singularity AIDR flagged this action and blocked it pending explicit user approval.",
		...verdictRuleLines(verdict),
		`Category: ${verdict.category}`,
		`Reason: ${reasons}`,
		`Artifacts: ${summarizeArtifacts(artifacts)}`,
	];

	const responded = responseLine(actions);
	if (responded) lines.push(`Response: ${responded}`);

	lines.push(
		"",
		`Approval reference: actionId: "${actionId}"`,
		"You cannot approve this action yourself and no tool available to you can approve it.",
		"Approval is an out-of-band, human-only action. Report the reference above to the user and",
		"stop here: do NOT retry this tool call and do NOT try to work around the block. The action",
		"stays blocked until the user approves it out of band or permanently allowlists the artifact.",
	);
	const dashboardNotice = formatDashboardApprovalNotice(dashboardApproval);
	if (dashboardNotice) lines.push(dashboardNotice);
	if (dashboardApproval?.dashboardOnly) {
		// The local CLI is not an approval channel under dashboard_only.
		if (!dashboardNotice)
			lines.push("(For the user: only an AIDR dashboard approval can release it.)");
	} else if (pendingRecorded === false) {
		lines.push(
			"(For the user: this ask could NOT be recorded for operator approval — operator approvals",
			"are disabled or the approval store is unavailable, so `aidr approve` cannot release it.",
			"Run `aidr doctor` in your own terminal to see why.)",
		);
	} else {
		lines.push(
			"(For the user: review it with `aidr pending` and approve it with `aidr approve <actionId>`",
			"in your own terminal; the approval covers one retry of this exact call for 15 minutes.)",
		);
	}

	return lines.join("\n");
}

// ── Allowlist tool logic ───────────────────────────────────────────

/**
 * Record an approval for a pending action and return an operator-facing message.
 *
 * OUT-OF-BAND / OPERATOR ONLY: call this from a human-facing approval channel
 * (host UI, CLI prompt, an MCP tool whose confirmation comes from the user).
 * Never expose it as a tool the policed agent can call — that would let the
 * agent approve its own blocked actions.
 */
export async function approveAction(store: ApprovalStore, actionId: string): Promise<string> {
	const entry = store.approve(actionId);
	if (!entry) {
		return "No pending Singularity AIDR approval found for this action ID.";
	}
	return [
		`Approved action ${actionId}. Retry the original tool call now.`,
		"",
		"Inform the user that they can ask you to permanently allowlist this artifact. Do NOT add it to the allowlist unless the user explicitly requests it.",
	].join("\n");
}

/** The operator approval store `addToAllowlist` checks, or null when disabled (`false`). */
function operatorApprovalStore(
	config: Config,
	logger: Logger,
	operatorApprovals: OperatorApprovalStoreOptions | false,
): OperatorApprovalStoreOptions | null {
	if (operatorApprovals === false) return null;
	return {
		logger,
		// Read defensively: a config read that yields nothing must not crash here.
		keyStorage: (config as Config | undefined)?.operator_approvals?.key_storage,
		...operatorApprovals,
	};
}

function addAllowlistEntry(
	allowlist: Allowlist,
	type: "url" | "command" | "file_path",
	value: string,
	reason: string,
): void {
	if (type === "url") addUrl(allowlist, value, reason, "ask");
	else if (type === "command") addCommand(allowlist, value, reason, "ask");
	else addFilePath(allowlist, value, reason, "ask");
}

/**
 * Turn an out-of-band approval into a permanent allowlist entry.
 *
 * Succeeds only when a human already approved this exact artifact: either an
 * in-process approval (`ApprovalStore`) or an operator approval recorded with
 * `aidr approve <actionId> --permit-allowlist`. One operator grant yields one
 * entry per artifact. The agent can call this, but it cannot create either kind
 * of approval, so it cannot widen the allowlist on its own.
 */
export async function addToAllowlist(
	store: ApprovalStore,
	type: "url" | "command" | "file_path",
	value: string,
	reason?: string,
	configPath?: string,
	logger: Logger = nullLogger,
	operatorApprovals: OperatorApprovalStoreOptions | false = {},
): Promise<string> {
	const config = await loadConfig(configPath, logger);
	const operatorStore = operatorApprovalStore(config, logger, operatorApprovals);
	const inProcess = store.hasApprovedArtifact(type, value);
	const operatorGrant =
		!inProcess && operatorStore
			? await findOperatorAllowlistGrant(type, value, operatorStore)
			: null;
	if (!inProcess && !operatorGrant) {
		return [
			"Cannot add to allowlist: no recent user approval found for this artifact.",
			"Only the user can grant one, out of band, with `aidr approve <actionId> --permit-allowlist`",
			"or `aidr allowlist add` in their own terminal.",
		].join(" ");
	}

	const allowlist = await loadAllowlist(config.allowlist, logger);
	const entryReason =
		reason ??
		(operatorGrant
			? `Approved by operator (aidr approve ${operatorGrant.slice(0, 12)})`
			: "Approved by user (out-of-band approval)");

	addAllowlistEntry(allowlist, type, value, entryReason);

	if (operatorGrant && operatorStore) {
		// Spend the grant before writing, so a concurrent second call cannot also
		// use it. A failed save then costs the grant, never widens the allowlist.
		const spent = await markOperatorAllowlistGrantUsed(operatorGrant, type, value, operatorStore);
		if (!spent) {
			return "Cannot add to allowlist: the operator approval was already used or has expired.";
		}
	}

	const saved = await saveAllowlist(allowlist, config.allowlist, logger);
	if (!saved) {
		return operatorGrant
			? "Failed to save allowlist. The operator approval was spent; ask the user to approve again."
			: "Failed to save allowlist. Approval preserved — retry is safe.";
	}
	if (inProcess) store.consumeApprovedArtifact(type, value);
	return `Added ${type} to Singularity AIDR allowlist.`;
}

export async function removeFromAllowlist(
	type: "url" | "command" | "file_path",
	value: string,
	configPath?: string,
	logger: Logger = nullLogger,
): Promise<string> {
	const config = await loadConfig(configPath, logger);
	const allowlist = await loadAllowlist(config.allowlist, logger);

	let removed: boolean;
	let removedViaHash = false;
	switch (type) {
		case "url":
			removed = removeUrl(allowlist, value);
			break;
		case "command":
			removed = removeCommand(allowlist, value);
			if (!removed) {
				removed = removeCommand(allowlist, hashCommand(value));
				removedViaHash = true;
			}
			break;
		case "file_path":
			removed = removeFilePath(allowlist, value);
			break;
	}

	if (!removed) {
		return "Artifact not found in Singularity AIDR allowlist.";
	}

	const saved = await saveAllowlist(allowlist, config.allowlist, logger);
	if (!saved) {
		return "Failed to save allowlist after removal. Please retry.";
	}
	let rendered: string;
	switch (type) {
		case "url":
			rendered = normalizeUrl(value);
			break;
		case "command":
			rendered = `${(removedViaHash ? hashCommand(value) : value).slice(0, 12)}...`;
			break;
		case "file_path":
			rendered = normalizeFilePath(value);
			break;
	}
	return `Removed ${type} from Singularity AIDR allowlist: ${rendered}`;
}
