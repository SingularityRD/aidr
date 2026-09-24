#!/usr/bin/env node
/**
 * Singularity AIDR UserPromptSubmit hook entry point (prompt protection).
 *
 * Inspects the user's prompt before Claude Code sends it to the model:
 *   - secrets and private keys: `prompt_protection.secrets` (default `block`)
 *   - personal data: `prompt_protection.pii` (default `warn`)
 *   - an operator-provisioned tenant DLP policy, when present: any non-allow
 *     outcome blocks (a prompt cannot be rewritten by this hook).
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
 * configured security control. The hook always exits 0; a hook killed before it
 * writes anything cannot block, which is a host limitation.
 */

import {
	DEFAULT_PROMPT_PROTECTION,
	initSentry,
	type Logger,
	loadConfig,
	logVerdict,
	type PromptProtectionConfig,
	type PromptProtectionResult,
	type PromptTenantDlp,
	scanPrompt,
	type Verdict,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import pino from "pino";
import { loadProvisionedDetectorContext } from "./detector-provisioning.js";
import { readBoundedJson } from "./hook-input.js";

initSentry({ name: "aidr-claude-code-user-prompt-submit" });

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

/** Hook payload ceiling: prompt plus Claude Code's metadata fields. */
const MAX_PROMPT_HOOK_INPUT_BYTES = 2 * 1024 * 1024;

const HOOK_EVENT = "UserPromptSubmit";

function write(output: Record<string, unknown>): void {
	process.stdout.write(`${JSON.stringify(output)}\n`);
}

/** Fixed response for an uninspected prompt; never echoes input or error text. */
function writeInspectionFailure(secretsMode: PromptProtectionConfig["secrets"]): void {
	if (secretsMode === "block") {
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

/** Audit record: kinds and counts only; the prompt itself is never stored. */
function auditVerdict(result: PromptProtectionResult): Verdict {
	const blocked = result.decision === "block";
	return {
		decision: blocked ? "deny" : "allow",
		category: blocked ? "prompt_protection" : "prompt_protection_warning",
		confidence: 1,
		severity: blocked ? "critical" : "warning",
		source: "prompt_protection",
		artifacts: [],
		matchedThreatId: null,
		reasons: [
			`Prompt ${blocked ? "blocked" : "warning"}: ${result.findings
				.map((finding) => `${finding.kind} x${finding.count}`)
				.join(", ")}`,
		],
	};
}

function readPrompt(): { sessionId: string; prompt: string } | null {
	const input = readBoundedJson<unknown>(0, MAX_PROMPT_HOOK_INPUT_BYTES);
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

async function tenantDlp(): Promise<PromptTenantDlp | undefined> {
	const provisioned = await loadProvisionedDetectorContext();
	const detectors = provisioned.runtimeDetectors;
	return detectors?.dlp?.enabled === true
		? { tenantId: detectors.tenantId, policy: detectors.dlp.policy }
		: undefined;
}

async function main(): Promise<void> {
	let secretsMode: PromptProtectionConfig["secrets"] = DEFAULT_PROMPT_PROTECTION.secrets;
	try {
		await verifyArtifactIntegrityAndLog({
			artifactDir: __dirname,
			artifactId: "claude-code/dist",
			logger,
		});
		const config = await loadConfig(undefined, logger);
		const policy = config.prompt_protection ?? DEFAULT_PROMPT_PROTECTION;
		secretsMode = policy.secrets;

		const input = readPrompt();
		if (!input) {
			writeInspectionFailure(secretsMode);
			return;
		}

		let tenant: PromptTenantDlp | undefined;
		try {
			tenant = await tenantDlp();
		} catch {
			writeTenantPolicyFailure();
			return;
		}

		const result = scanPrompt(input.prompt, policy, tenant);
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
		writeInspectionFailure(secretsMode);
	}
}

main().catch(() => {
	writeInspectionFailure(DEFAULT_PROMPT_PROTECTION.secrets);
});
