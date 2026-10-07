#!/usr/bin/env node
/**
 * Singularity AIDR UserPromptSubmit hook entry point (prompt protection).
 *
 * Inspects the user's prompt before Claude Code sends it to the model:
 *   - secrets and private keys: `prompt_protection.secrets` (default `block`)
 *   - personal data: `prompt_protection.pii` (default `warn`), including Turkish
 *     ID numbers, IBANs and TR phone numbers. A personal-data scan that could not
 *     inspect the whole prompt is never treated as clean: `block` blocks the
 *     prompt, `warn` sends it with a notice to the user and the model.
 *   - jailbreak and content-safety patterns: `prompt_protection.jailbreak`
 *     (default `warn`) and `prompt_protection.content_safety.<category>`; a
 *     signed tenant `prompt_safety` floor can only tighten them.
 *   - an operator-provisioned tenant DLP policy, when present: any non-allow
 *     outcome blocks (a prompt cannot be rewritten by this hook).
 *   - canary credentials (`aidr canary deploy`): a prompt carrying a decoy
 *     token value is blocked and recorded as a canary incident.
 *
 * Output (Claude Code UserPromptSubmit protocol):
 *   - block: `{"decision":"block","reason":…}` — the prompt is not sent and the
 *     reason is shown to the user only. The reason names what was found, never
 *     the value.
 *   - warn:  `systemMessage` for the user plus `additionalContext` for the model.
 *   - allow: no output.
 *
 * Failure policy: an internal error (unreadable or oversized input, a detector
 * exception) blocks the prompt only when `prompt_protection.secrets` is `block`
 * (the default). With secrets set to `warn` or `off` the prompt proceeds with a
 * visible "not inspected" notice rather than a silent clean result. A tenant DLP
 * policy that is provisioned but cannot be verified always blocks: that is a
 * configured security control. The hook always exits 0.
 *
 * Deadline: Claude Code kills this hook after 10 s and then sends the prompt,
 * so the hook answers itself first (default 7 s, `AIDR_USER_PROMPT_SUBMIT_DEADLINE_MS`).
 * A prompt not fully inspected by then is blocked when secrets are `block` or a
 * tenant DLP policy applies, and otherwise sent with a "not fully inspected"
 * notice. The scan checks the same deadline between detector passes, so a
 * slow synchronous scan cannot hold the answer past it.
 */

import {
	CANARY_PROMPT_BLOCK_MESSAGE,
	checkPromptForCanaries,
	DEFAULT_PROMPT_PROTECTION,
	exitAfterStdoutFlush,
	initSentry,
	type Logger,
	loadConfig,
	logVerdict,
	type PromptProtectionConfig,
	type PromptProtectionResult,
	PromptScanDeadlineError,
	type PromptTenantDlp,
	scanPrompt,
	type TenantPromptSafetyPolicy,
	type Verdict,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import pino from "pino";
import { loadProvisionedDetectorContext } from "./detector-provisioning.js";
import { readStdinJson, resolveUserPromptSubmitDeadlineMs } from "./hook-input.js";

/** Measured from module start: the host's timeout runs from process launch. */
const deadlineAt = Date.now() + resolveUserPromptSubmitDeadlineMs(process.env);

initSentry({ name: "aidr-claude-code-user-prompt-submit" });

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

/** Hook payload ceiling: prompt plus Claude Code's metadata fields. */
const MAX_PROMPT_HOOK_INPUT_BYTES = 2 * 1024 * 1024;

const HOOK_EVENT = "UserPromptSubmit";

/**
 * What an unfinished inspection falls back to. Starts fail-closed (the default
 * secrets mode) and is updated as the config and tenant policy load.
 */
const fallback: {
	secretsMode: PromptProtectionConfig["secrets"];
	tenantPolicy: boolean;
} = { secretsMode: DEFAULT_PROMPT_PROTECTION.secrets, tenantPolicy: false };

/**
 * The hook answers exactly once: after the deadline response has been
 * written, a late scan result must not append a second (possibly allowing) one.
 */
let responded = false;

function write(output: Record<string, unknown>, onWritten?: () => void): boolean {
	if (responded) return false;
	responded = true;
	const line = `${JSON.stringify(output)}\n`;
	if (onWritten) process.stdout.write(line, onWritten);
	else process.stdout.write(line);
	return true;
}

/** Fixed response for an uninspected prompt; never echoes input or error text. */
function writeInspectionFailure(): void {
	if (fallback.secretsMode === "block") {
		write({
			decision: "block",
			reason:
				"🛡️ Singularity AIDR could not inspect this prompt for secrets, so it was not sent. Try again; if this persists, run `aidr status`.",
		});
		return;
	}
	write({
		systemMessage:
			"Singularity AIDR could not inspect this prompt for secrets; it was sent without prompt protection.",
	});
}

/** Fixed response for a prompt whose inspection did not finish before the deadline. */
function writeDeadlineResponse(onWritten?: () => void): boolean {
	if (fallback.secretsMode === "block" || fallback.tenantPolicy) {
		return write(
			{
				decision: "block",
				reason:
					"🛡️ Singularity AIDR could not finish inspecting this prompt in time, so it was not sent. Shorten the prompt or split it up and try again.",
			},
			onWritten,
		);
	}
	return write(
		{
			systemMessage:
				"Singularity AIDR could not finish inspecting this prompt in time; it was sent without being fully inspected for secrets or personal data.",
		},
		onWritten,
	);
}

function writeTenantPolicyFailure(): void {
	write({
		decision: "block",
		reason:
			"🛡️ Singularity AIDR could not verify your organization's data-loss prevention policy, so this prompt was not sent.",
	});
}

function writeResult(result: PromptProtectionResult): void {
	if (result.decision === "block") {
		write({ decision: "block", reason: result.userMessage });
	} else if (result.decision === "warn") {
		write({
			systemMessage: result.userMessage,
			hookSpecificOutput: { hookEventName: HOOK_EVENT, additionalContext: result.modelContext },
		});
	}
}

/** Audit record: kinds, counts and static reason codes only; the prompt itself is never stored. */
function auditVerdict(result: PromptProtectionResult): Verdict {
	const blocked = result.decision === "block";
	const counts = [
		...result.findings.map((finding) => `${finding.kind} x${finding.count}`),
		...(result.incomplete
			? [`personal-data inspection incomplete (${result.incomplete.reasons.join(", ")})`]
			: []),
	].join(", ");
	return {
		decision: blocked ? "deny" : "allow",
		category: blocked ? "prompt_protection" : "prompt_protection_warning",
		confidence: 1,
		severity: blocked ? "critical" : "warning",
		source: "prompt_protection",
		artifacts: [],
		matchedThreatId: null,
		reasons: [
			`Prompt ${blocked ? "blocked" : "warning"}: ${counts}${
				result.partial
					? " (scan stopped at the first blocking finding; counts are lower bounds)"
					: ""
			}`,
		],
	};
}

async function readPrompt(): Promise<{ sessionId: string; prompt: string } | null> {
	const input = await readStdinJson<unknown>(MAX_PROMPT_HOOK_INPUT_BYTES);
	if (input.status !== "parsed") return null;
	const value = input.value;
	if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
	const fields = value as Record<string, unknown>;
	if (typeof fields.prompt !== "string") return null;
	return {
		sessionId: typeof fields.session_id === "string" ? fields.session_id : "unknown",
		prompt: fields.prompt,
	};
}

/** Tenant DLP and the tenant prompt-safety floor from the signed detector policy. */
async function tenantPolicy(): Promise<{
	dlp?: PromptTenantDlp;
	promptSafety?: TenantPromptSafetyPolicy;
}> {
	const provisioned = await loadProvisionedDetectorContext();
	const detectors = provisioned.runtimeDetectors;
	return {
		dlp:
			detectors?.dlp?.enabled === true
				? { tenantId: detectors.tenantId, policy: detectors.dlp.policy }
				: undefined,
		promptSafety: detectors?.promptSafety,
	};
}

async function main(): Promise<void> {
	try {
		await verifyArtifactIntegrityAndLog({
			artifactDir: __dirname,
			artifactId: "claude-code/dist",
			logger,
		});
		const config = await loadConfig(undefined, logger);
		const policy = config.prompt_protection ?? DEFAULT_PROMPT_PROTECTION;
		fallback.secretsMode = policy.secrets;

		const input = await readPrompt();
		if (!input) {
			writeInspectionFailure();
			return;
		}
		// Canary values first (shared with every connector's prompt path): a hit is
		// recorded as a canary incident and the prompt is blocked.
		const canary = await checkPromptForCanaries({
			sessionId: input.sessionId,
			hookEvent: HOOK_EVENT,
			prompt: input.prompt,
			agentRuntime: "claude-code",
			config,
			logger,
		});
		if (canary === "triggered") {
			write({ decision: "block", reason: CANARY_PROMPT_BLOCK_MESSAGE });
			return;
		}

		let tenant: PromptTenantDlp | undefined;
		let tenantPromptSafety: TenantPromptSafetyPolicy | undefined;
		try {
			({ dlp: tenant, promptSafety: tenantPromptSafety } = await tenantPolicy());
		} catch {
			writeTenantPolicyFailure();
			return;
		}
		if (tenant) fallback.tenantPolicy = true;
		// The deadline may have answered while the policy loaded.
		if (responded) return;

		let result: PromptProtectionResult;
		try {
			result = scanPrompt(input.prompt, policy, tenant, { deadlineAt, tenantPromptSafety });
		} catch (error) {
			if (error instanceof PromptScanDeadlineError) {
				writeDeadlineResponse();
				return;
			}
			throw error;
		}
		if (result.decision !== "allow") {
			try {
				await logVerdict(
					config.logging,
					input.sessionId,
					HOOK_EVENT,
					{ content_omitted: "user prompt" },
					auditVerdict(result),
				);
			} catch {
				// An audit failure cannot change the prompt decision.
			}
		}
		writeResult(result);
	} catch {
		writeInspectionFailure();
	}
}

// Internal deadline, shorter than the host's hook timeout. It covers the
// asynchronous phases (integrity check, config and policy loading); the scan
// itself checks `deadlineAt` between passes.
const deadline = setTimeout(
	() => {
		// Pending work may keep the event loop alive past the host timeout; the
		// response is on stdout, so exit once it has been flushed.
		if (!writeDeadlineResponse(() => process.exit(0))) process.exit(0);
	},
	Math.max(0, deadlineAt - Date.now()),
);

main()
	.catch(() => {
		writeInspectionFailure();
	})
	.finally(() => {
		clearTimeout(deadline);
		// The answer is written: exit once it is flushed so pending handles
		// cannot keep the hook alive until the host kills it.
		exitAfterStdoutFlush(0);
	});
