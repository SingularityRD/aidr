import { scanModelOutput } from "@singularityrd/aidr-core";

export const MAX_TOOL_OUTPUT_BYTES = 256 * 1024;

const QUARANTINE_TITLE = "Singularity AIDR quarantined tool output";

export type OpenCodeAfterToolInput = {
	tool: string;
	sessionID: string;
	callID: string;
	args: unknown;
};

export type OpenCodeAfterToolOutput = {
	title: string;
	output: unknown;
	metadata: unknown;
};

type InspectionStatus =
	| "inspected_clean"
	| "quarantined_finding"
	| "quarantined_size_limit"
	| "quarantined_unsupported_output"
	| "quarantined_inspection_error";

type StructuredLogger = {
	debug(data: Record<string, unknown>, message: string): void;
	info(data: Record<string, unknown>, message: string): void;
	warn(data: Record<string, unknown>, message: string): void;
	error(data: Record<string, unknown>, message: string): void;
};

function emitCoverageEvent(
	logger: StructuredLogger,
	level: "debug" | "warn" | "error",
	status: InspectionStatus,
	input: OpenCodeAfterToolInput,
	extra: Record<string, unknown> = {},
): void {
	logger[level](
		{
			event: "aidr.output_inspection.coverage",
			connector: "opencode",
			channel: "tool_output",
			hook: "tool.execute.after",
			status,
			tool: input.tool,
			sessionId: input.sessionID,
			callId: input.callID,
			...extra,
		},
		"Singularity AIDR OpenCode output inspection coverage",
	);
}

function quarantine(output: OpenCodeAfterToolOutput, reason: string): void {
	output.title = QUARANTINE_TITLE;
	output.output = `[Singularity AIDR] ${reason} The original tool output was withheld before model consumption. Review the source through an approved out-of-band workflow.`;
}

function serialiseOutput(value: unknown): string | null {
	if (typeof value === "string") return value;
	if (value === null) return "null";
	try {
		const serialised = JSON.stringify(value);
		return typeof serialised === "string" ? serialised : null;
	} catch {
		return null;
	}
}

/**
 * Produce additional bounded views that reveal common chunk-boundary and
 * Unicode obfuscation without ever copying output into logs or diagnostics.
 */
function inspectionViews(text: string): string[] {
	const canonical = text.normalize("NFKC").replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
	const structuralJoin = canonical.replace(/["'`{},:[\]\\]/g, "");
	return structuralJoin === canonical ? [canonical] : [canonical, structuralJoin];
}

function uniqueFindings(text: string): ReturnType<typeof scanModelOutput> {
	const byRule = new Map<string, ReturnType<typeof scanModelOutput>[number]>();
	for (const view of inspectionViews(text)) {
		for (const finding of scanModelOutput(view)) {
			if (!byRule.has(finding.ruleId)) byRule.set(finding.ruleId, finding);
		}
	}
	return [...byRule.values()];
}

export function reportOpenCodeOutputCoverage(logger: StructuredLogger): void {
	logger.info(
		{
			event: "aidr.output_inspection.health",
			connector: "opencode",
			channel: "tool_output",
			status: "configured",
			hook: "tool.execute.after",
			maxBytes: MAX_TOOL_OUTPUT_BYTES,
			failureMode: "quarantine",
		},
		"Singularity AIDR OpenCode output inspection capability",
	);
	logger.warn(
		{
			event: "aidr.output_inspection.health",
			connector: "opencode",
			channel: "provider_stream_and_non_tool_content",
			status: "unsupported_by_host_preconsumption_api",
			reason:
				"OpenCode exposes completed message events only after provider content exists; those events cannot guarantee pre-consumption enforcement",
		},
		"Singularity AIDR OpenCode output inspection coverage gap",
	);
}

export function createOutputHandlers(logger: StructuredLogger) {
	const afterToolUse = async (
		input: OpenCodeAfterToolInput,
		output: OpenCodeAfterToolOutput,
	): Promise<void> => {
		const text = serialiseOutput(output.output);
		if (text === null) {
			quarantine(output, "The host returned an unsupported output representation.");
			emitCoverageEvent(logger, "warn", "quarantined_unsupported_output", input);
			return;
		}

		const bytes = Buffer.byteLength(text, "utf8");
		if (bytes > MAX_TOOL_OUTPUT_BYTES) {
			quarantine(
				output,
				`Tool output exceeded the ${MAX_TOOL_OUTPUT_BYTES}-byte inspection limit and was not classified as clean.`,
			);
			emitCoverageEvent(logger, "warn", "quarantined_size_limit", input, {
				outputBytes: bytes,
				maxBytes: MAX_TOOL_OUTPUT_BYTES,
			});
			return;
		}

		try {
			const findings = uniqueFindings(text);
			if (findings.length > 0) {
				const ruleIds = findings.map((finding) => finding.ruleId).sort();
				quarantine(output, `Tool output matched security rules: ${ruleIds.join(", ")}.`);
				emitCoverageEvent(logger, "warn", "quarantined_finding", input, {
					outputBytes: bytes,
					findingCount: findings.length,
					findingRuleIds: ruleIds,
				});
				return;
			}

			// Defensive runtime support for JSON-shaped outputs. The current SDK
			// contract is string-only, so ordinary strings remain byte-for-byte intact.
			if (typeof output.output !== "string") output.output = text;
			emitCoverageEvent(logger, "debug", "inspected_clean", input, { outputBytes: bytes });
		} catch (error) {
			quarantine(output, "Output inspection was unavailable for this response.");
			emitCoverageEvent(logger, "error", "quarantined_inspection_error", input, {
				errorType: error instanceof Error ? error.name : typeof error,
			});
		}
	};

	return {
		"tool.execute.after": afterToolUse,
	};
}
