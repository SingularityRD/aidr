import {
	type AuditedBlock,
	type Config,
	FALSE_POSITIVE_REASON_CODES,
	type FalsePositiveReportResult,
	findAuditedBlocks,
	loadConfig,
	resolvePath,
	safeDisplayUrl,
	submitFalsePositiveReport,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { localTime } from "../utils/local-time.js";

export interface ReportFpOptions {
	reason?: string;
	note?: string;
	json?: boolean;
	dryRun?: boolean;
}

/** Test seams; production callers pass nothing. */
export interface ReportFpDeps {
	config?: Config;
	submit?: typeof submitFalsePositiveReport;
	out?: (text: string) => void;
	err?: (text: string) => void;
}

type ReasonCode = (typeof FALSE_POSITIVE_REASON_CODES)[number];

function describe(block: AuditedBlock): string {
	return ct("reportFp.found", {
		id: block.actionId.slice(0, 12),
		decision: ct(block.decision === "ask" ? "reportFp.decision.ask" : "reportFp.decision.deny"),
		rule: block.ruleId ?? "-",
		severity: block.severity ?? "-",
		tool: block.tool ?? "-",
		time: block.timestamp ? localTime(block.timestamp) : "-",
	});
}

/** The one audited block the id names, or null after saying why there is none. */
async function findOneBlock(
	config: Config,
	id: string,
	support: string | null,
	fail: (message: string) => void,
	err: (text: string) => void,
): Promise<AuditedBlock | null> {
	const blocks = await findAuditedBlocks(config.logging, id);
	if (blocks.length === 0) {
		fail(ct("reportFp.notFound", { id, path: resolvePath(config.logging.path) }));
		if (support) err(ct("reportFp.support", { url: support }));
		return null;
	}
	if (blocks.length > 1) {
		fail(ct("reportFp.ambiguous", { id, count: blocks.length }));
		for (const block of blocks.slice(0, 10)) err(`  ${describe(block)}`);
		return null;
	}
	return blocks[0] ?? null;
}

function jsonReport(
	block: AuditedBlock,
	reason: string,
	result: FalsePositiveReportResult | null,
	support: string | null,
): Record<string, unknown> {
	return {
		action_id: block.actionId,
		rule_id: block.ruleId,
		decision: block.decision,
		severity: block.severity,
		tool: block.tool,
		occurred_at: block.timestamp,
		reason_code: reason,
		submitted: result?.ok === true,
		...(result?.ok ? { report_id: result.reportId, created: result.created } : {}),
		...(result && !result.ok ? { error: result.error } : {}),
		...(support ? { support_contact_url: support } : {}),
	};
}

function printReport(
	block: AuditedBlock,
	result: FalsePositiveReportResult | null,
	notManaged: boolean,
	support: string | null,
	out: (text: string) => void,
	err: (text: string) => void,
): void {
	out(describe(block));
	if (!result) out(ct("reportFp.dryRun"));
	else if (result.ok) {
		out(ct(result.created ? "reportFp.sent" : "reportFp.duplicate", { reportId: result.reportId }));
	} else if (notManaged) out(ct("reportFp.local"));
	else err(ct("reportFp.failed", { error: result.error }));
	if (support) out(ct("reportFp.support", { url: support }));
}

/**
 * `aidr report-fp <actionId>`: report a block as a false positive.
 *
 * Finds the call in the local audit log by the short id the block message
 * printed and files it in the control plane's false-positive queue (ids, rule,
 * decision and an optional redacted note; never the command or file content).
 * Without a control plane it prints the details to hand to the IT or security
 * team, with the organisation's `support_contact_url`. A report never allows
 * anything by itself.
 */
export async function reportFpCommand(
	actionId: string,
	options: ReportFpOptions = {},
	deps: ReportFpDeps = {},
): Promise<void> {
	const out = deps.out ?? ((text: string) => console.log(text));
	const err = deps.err ?? ((text: string) => console.error(text));
	const fail = (message: string) => {
		err(message);
		process.exitCode = 1;
	};
	const id = (actionId ?? "").trim().toLowerCase();
	if (!/^[a-f0-9]{8,64}$/.test(id)) return fail(ct("reportFp.invalidId"));
	const reason = (options.reason ?? "other").trim();
	if (!(FALSE_POSITIVE_REASON_CODES as readonly string[]).includes(reason)) {
		return fail(
			ct("reportFp.invalidReason", { reason, reasons: FALSE_POSITIVE_REASON_CODES.join(", ") }),
		);
	}
	const config = deps.config ?? (await loadConfig());
	const support = safeDisplayUrl(config.support_contact_url);
	const block = await findOneBlock(config, id, support, fail, err);
	if (!block) return;
	let result: FalsePositiveReportResult | null = null;
	if (!options.dryRun) {
		result = await (deps.submit ?? submitFalsePositiveReport)(config, {
			block,
			reasonCode: reason as ReasonCode,
			note: options.note,
			agentRuntime: "cli",
		});
	}
	const notManaged = result !== null && !result.ok && result.error.startsWith("not_managed");
	if (options.json) out(JSON.stringify(jsonReport(block, reason, result, support), null, 2));
	else printReport(block, result, notManaged, support, out, err);
	// A local-mode install has nowhere to send it: that is not a failure.
	if (result && !result.ok && !notManaged) process.exitCode = 1;
}
