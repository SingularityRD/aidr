/**
 * Connector-side prompt protection: one shared runner around {@link scanPrompt}
 * for every connector whose host exposes a pre-model prompt hook (Cursor
 * `beforeSubmitPrompt`, VS Code Local and Codex `UserPromptSubmit`, OpenCode
 * `chat.message`, OpenClaw `before_agent_run`). Claude Code keeps its own
 * `UserPromptSubmit` entry point with the same policy.
 *
 * Canary credentials (`aidr canary deploy`) are checked first: a prompt that
 * carries a decoy token value is blocked and recorded as a `user_prompt` canary
 * trigger (audit entry and, in managed mode, an incident; canary ids only). A
 * canary registry that cannot be read is logged and skipped, and the regular
 * scan still decides.
 *
 * The runner loads the local `prompt_protection` config and the operator-provisioned
 * tenant DLP policy for the connector's runtime, scans the prompt under a deadline,
 * audits the outcome (kinds and counts only, never the prompt) and applies the
 * documented failure policy. Each connector only maps the returned outcome onto
 * its host's wire format.
 *
 * Failure policy (identical to the Claude Code hook):
 *   - a prompt that cannot be inspected (missing or non-text input, an internal
 *     error) blocks when `prompt_protection.secrets` is `block` (the default) and is
 *     otherwise sent with a visible "not inspected" notice;
 *   - a prompt not fully inspected before the deadline blocks when secrets are
 *     `block` or a tenant DLP policy applies, and is otherwise sent with a notice;
 *   - a provisioned tenant DLP policy that cannot be verified always blocks.
 *
 * Messages are fixed text or come from {@link scanPrompt}; neither ever echoes
 * the prompt, an error message or a matched value.
 */

import { logVerdict } from "./audit-log.js";
import { CANARY_PROMPT_BLOCK_MESSAGE, checkPromptForCanaries } from "./canary-triggers.js";
import { loadConfig } from "./config.js";
import { loadProvisionedDetectorContext } from "./detector-provisioning.js";
import {
	DEFAULT_PROMPT_PROTECTION,
	type PromptProtectionResult,
	PromptScanDeadlineError,
	type PromptTenantDlp,
	scanPrompt,
} from "./prompt-protection.js";
import type { TenantPromptSafetyPolicy } from "./prompt-safety.js";
import {
	type AgentRuntime,
	type Config,
	type Logger,
	nullLogger,
	type PromptProtectionConfig,
	type Verdict,
} from "./types.js";

/** Why an outcome was reached; stable codes for tests, audit and host observations. */
export type PromptInspectionReason =
	| "clean"
	| "findings"
	| "canary"
	| "not_inspected"
	| "deadline"
	| "tenant_policy_unverified";

export type PromptInspectionOutcome =
	| { decision: "allow"; reason: "clean" }
	| {
			decision: "warn";
			reason: PromptInspectionReason;
			/** Notice for the user; names kinds only. */
			userMessage: string;
			/** Notice for the model, where the host can deliver one. */
			modelContext: string;
	  }
	| {
			decision: "block";
			reason: PromptInspectionReason;
			/** Reason shown to the user; names kinds only, never the value. */
			userMessage: string;
	  };

export interface PromptInspectionRequest {
	/** Runtime the connector serves; selects the tenant detector policy file. Never from a payload. */
	runtime: AgentRuntime;
	/** Host event name, recorded as the audit entry's tool name (e.g. `beforeSubmitPrompt`). */
	hookEvent: string;
	sessionId: string;
	/** The prompt text. Anything other than a string is an uninspectable prompt. */
	prompt: unknown;
	/** Wall-clock deadline (`Date.now()` milliseconds) for the whole inspection. */
	deadlineAt: number;
	logger?: Logger;
	/** Preloaded configuration; loaded from the default location when omitted. */
	config?: Config;
	/** Tenant DLP loader; defaults to the signed/local provisioned policy for `runtime`. */
	loadTenantDlp?: (runtime: AgentRuntime) => Promise<PromptTenantDlp | undefined>;
	/**
	 * Tenant prompt-safety floor loader; defaults to the signed provisioned policy
	 * for `runtime`. A load failure blocks, like an unverifiable tenant DLP policy.
	 */
	loadTenantPromptSafety?: (runtime: AgentRuntime) => Promise<TenantPromptSafetyPolicy | undefined>;
}

export const PROMPT_INSPECTION_DEADLINE_ENV = "AIDR_PROMPT_INSPECTION_DEADLINE_MS";
export const MIN_PROMPT_INSPECTION_DEADLINE_MS = 100;

/**
 * Internal inspection deadline for a connector. `AIDR_PROMPT_INSPECTION_DEADLINE_MS`
 * may shorten or lengthen it within [100, maxMs]; anything else uses the default, so a
 * typo can never push the answer past the host's own timeout.
 */
export function resolvePromptInspectionDeadlineMs(
	env: Record<string, string | undefined>,
	defaultMs: number,
	maxMs: number,
): number {
	const raw = env[PROMPT_INSPECTION_DEADLINE_ENV];
	if (raw === undefined || !/^\d+$/.test(raw.trim())) return defaultMs;
	const value = Number(raw.trim());
	return value >= MIN_PROMPT_INSPECTION_DEADLINE_MS && value <= maxMs ? value : defaultMs;
}

const NOT_INSPECTED_BLOCK =
	"🛡️ Singularity AIDR could not inspect this prompt for secrets, so it was not sent. Try again; if this persists, run `aidr status`.";
const NOT_INSPECTED_WARN =
	"Singularity AIDR could not inspect this prompt for secrets; it was sent without prompt protection.";
const DEADLINE_BLOCK =
	"🛡️ Singularity AIDR could not finish inspecting this prompt in time, so it was not sent. Shorten the prompt or split it up and try again.";
const DEADLINE_WARN =
	"Singularity AIDR could not finish inspecting this prompt in time; it was sent without being fully inspected for secrets or personal data.";
const TENANT_POLICY_BLOCK =
	"🛡️ Singularity AIDR could not verify your organization's data-loss prevention policy, so this prompt was not sent.";
const UNINSPECTED_MODEL_CONTEXT =
	"Singularity AIDR prompt protection notice: the user's prompt was not fully inspected for secrets or personal data. Do not repeat credentials or personal data from it, and do not copy them into files, commands, commit messages, web requests or other tools unless the user explicitly asks for that.";

/** Outcome for a prompt that was not inspected at all (unreadable input, internal error). */
export function uninspectedPromptOutcome(
	secretsMode: PromptProtectionConfig["secrets"],
): PromptInspectionOutcome {
	return secretsMode === "block"
		? { decision: "block", reason: "not_inspected", userMessage: NOT_INSPECTED_BLOCK }
		: {
				decision: "warn",
				reason: "not_inspected",
				userMessage: NOT_INSPECTED_WARN,
				modelContext: UNINSPECTED_MODEL_CONTEXT,
			};
}

function deadlineOutcome(
	secretsMode: PromptProtectionConfig["secrets"],
	tenantPolicy: boolean,
): PromptInspectionOutcome {
	return secretsMode === "block" || tenantPolicy
		? { decision: "block", reason: "deadline", userMessage: DEADLINE_BLOCK }
		: {
				decision: "warn",
				reason: "deadline",
				userMessage: DEADLINE_WARN,
				modelContext: UNINSPECTED_MODEL_CONTEXT,
			};
}

const CANARY_OUTCOME: PromptInspectionOutcome = {
	decision: "block",
	reason: "canary",
	userMessage: CANARY_PROMPT_BLOCK_MESSAGE,
};

function tenantPolicyOutcome(): PromptInspectionOutcome {
	return {
		decision: "block",
		reason: "tenant_policy_unverified",
		userMessage: TENANT_POLICY_BLOCK,
	};
}

function resultOutcome(result: PromptProtectionResult): PromptInspectionOutcome {
	if (result.decision === "block") {
		return {
			decision: "block",
			reason: "findings",
			userMessage: result.userMessage ?? NOT_INSPECTED_BLOCK,
		};
	}
	if (result.decision === "warn") {
		return {
			decision: "warn",
			reason: "findings",
			userMessage: result.userMessage ?? NOT_INSPECTED_WARN,
			modelContext: result.modelContext ?? UNINSPECTED_MODEL_CONTEXT,
		};
	}
	return { decision: "allow", reason: "clean" };
}

async function defaultTenantPromptSafety(
	runtime: AgentRuntime,
): Promise<TenantPromptSafetyPolicy | undefined> {
	return (await loadProvisionedDetectorContext(runtime)).runtimeDetectors?.promptSafety;
}

/**
 * Tenant DLP and the tenant prompt-safety floor. An injected DLP loader (tests,
 * embedded runtimes) owns the tenant policy unless a prompt-safety loader is
 * injected too. Throws when a provisioned policy cannot be verified.
 */
async function loadTenantPromptPolicy(request: PromptInspectionRequest): Promise<{
	tenant?: PromptTenantDlp;
	tenantPromptSafety?: TenantPromptSafetyPolicy;
}> {
	const tenant = await (request.loadTenantDlp ?? defaultTenantDlp)(request.runtime);
	const loadPromptSafety =
		request.loadTenantPromptSafety ??
		(request.loadTenantDlp ? undefined : defaultTenantPromptSafety);
	return { tenant, tenantPromptSafety: await loadPromptSafety?.(request.runtime) };
}

async function defaultTenantDlp(runtime: AgentRuntime): Promise<PromptTenantDlp | undefined> {
	const detectors = (await loadProvisionedDetectorContext(runtime)).runtimeDetectors;
	return detectors?.dlp?.enabled === true
		? { tenantId: detectors.tenantId, policy: detectors.dlp.policy }
		: undefined;
}

/** Audit record: kinds, counts and static reason codes only; the prompt itself is never stored. */
function auditVerdict(
	outcome: Exclude<PromptInspectionOutcome, { decision: "allow" }>,
	result: PromptProtectionResult | undefined,
): Verdict {
	const blocked = outcome.decision === "block";
	const detail = result
		? [
				...result.findings.map((finding) => `${finding.kind} x${finding.count}`),
				...(result.incomplete
					? [`personal-data inspection incomplete (${result.incomplete.reasons.join(", ")})`]
					: []),
			].join(", ") +
			(result.partial
				? " (scan stopped at the first blocking finding; counts are lower bounds)"
				: "")
		: `prompt not inspected (${outcome.reason})`;
	return {
		decision: blocked ? "deny" : "allow",
		category: blocked ? "prompt_protection" : "prompt_protection_warning",
		confidence: 1,
		severity: blocked ? "critical" : "warning",
		source: "prompt_protection",
		artifacts: [],
		matchedThreatId: null,
		reasons: [`Prompt ${blocked ? "blocked" : "warning"}: ${detail}`],
	};
}

/**
 * Inspect one user prompt for a connector. Never throws: every failure maps to
 * the documented fail-closed (or visibly degraded) outcome.
 */
export async function inspectUserPrompt(
	request: PromptInspectionRequest,
): Promise<PromptInspectionOutcome> {
	const logger = request.logger ?? nullLogger;
	// What an unfinished inspection falls back to. Starts fail-closed (the default
	// secrets mode) and is updated as the config and tenant policy load.
	const fallback = {
		secretsMode: DEFAULT_PROMPT_PROTECTION.secrets as PromptProtectionConfig["secrets"],
		tenantPolicy: false,
		// A detected canary blocks whatever happens afterwards (deadline, error).
		canary: false,
	};
	const unfinished = (outcome: PromptInspectionOutcome) =>
		fallback.canary ? CANARY_OUTCOME : outcome;
	let config: Config | undefined = request.config;
	let result: PromptProtectionResult | undefined;

	const work = async (): Promise<PromptInspectionOutcome> => {
		config ??= await loadConfig(undefined, logger);
		const policy = config.prompt_protection ?? DEFAULT_PROMPT_PROTECTION;
		fallback.secretsMode = policy.secrets;
		if (typeof request.prompt !== "string") return uninspectedPromptOutcome(policy.secrets);

		// Canary values first: no tenant policy or scan result can release a decoy.
		const canary = await checkPromptForCanaries({
			sessionId: request.sessionId,
			hookEvent: request.hookEvent,
			prompt: request.prompt,
			agentRuntime: request.runtime,
			config,
			logger,
		});
		if (canary === "triggered") {
			fallback.canary = true;
			return CANARY_OUTCOME;
		}

		let tenant: PromptTenantDlp | undefined;
		let tenantPromptSafety: TenantPromptSafetyPolicy | undefined;
		try {
			({ tenant, tenantPromptSafety } = await loadTenantPromptPolicy(request));
		} catch {
			return tenantPolicyOutcome();
		}
		if (tenant) fallback.tenantPolicy = true;

		try {
			result = scanPrompt(request.prompt, policy, tenant, {
				deadlineAt: request.deadlineAt,
				tenantPromptSafety,
			});
		} catch (error) {
			if (error instanceof PromptScanDeadlineError) {
				return deadlineOutcome(fallback.secretsMode, fallback.tenantPolicy);
			}
			throw error;
		}
		return resultOutcome(result);
	};

	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<PromptInspectionOutcome>((resolve) => {
		timer = setTimeout(
			() => resolve(unfinished(deadlineOutcome(fallback.secretsMode, fallback.tenantPolicy))),
			Math.max(0, request.deadlineAt - Date.now()),
		);
		timer.unref?.();
	});

	let outcome: PromptInspectionOutcome;
	try {
		outcome = await Promise.race([
			work().catch(() => unfinished(uninspectedPromptOutcome(fallback.secretsMode))),
			deadline,
		]);
	} finally {
		clearTimeout(timer);
	}

	// A canary block is already audited (and reported) by the canary recorder.
	if (outcome.decision !== "allow" && outcome.reason !== "canary" && config) {
		try {
			await logVerdict(
				config.logging,
				request.sessionId,
				request.hookEvent,
				{ content_omitted: "user prompt" },
				auditVerdict(outcome, outcome.reason === "findings" ? result : undefined),
			);
		} catch {
			// An audit failure cannot change the prompt decision.
		}
	}
	return outcome;
}
