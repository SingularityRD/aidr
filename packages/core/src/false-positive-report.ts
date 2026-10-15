/**
 * `aidr report-fp <actionId>`: a developer reports a block they think is wrong.
 *
 * The block message names the call's short action id. This module finds that
 * call in the local audit log (`action_id` on runtime verdict records), turns
 * the report into a versioned false-positive feedback record
 * (`false-positive-feedback.ts`, so the same statement always has the same id
 * and a resubmission is a no-op server side) and files it in the control
 * plane's false-positive queue (`POST /v1/false-positive-reports`, tenant API
 * key). Only ids, the rule, the decision and a bounded, redacted note leave the
 * machine: never the command, file content, URL or a secret.
 *
 * Nothing here suppresses a detection or changes a policy: an administrator
 * reviews the queue and, if they agree, adds a time-limited exception.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { userInfo } from "node:os";
import { controlPlaneUrl } from "./clients/control-plane-url.js";
import { resolvePath } from "./config.js";
import {
	type DashboardApprovalOptions,
	resolveDashboardApprovalContext,
} from "./dashboard-approvals.js";
import {
	createFalsePositiveFeedbackStore,
	createSha256HasherContext,
	type FalsePositiveFeedbackInput,
	type FalsePositiveReasonCode,
	recordFalsePositiveFeedback,
} from "./false-positive-feedback.js";
import { redactTelemetryString } from "./telemetry-redaction.js";
import type { Config, LoggingConfig } from "./types.js";
import { VERSION } from "./version.js";

export const FALSE_POSITIVE_REASON_CODES: readonly FalsePositiveReasonCode[] = [
	"benign_automation",
	"benign_maintenance",
	"expected_egress",
	"expected_file_write",
	"legitimate_mcp_tool",
	"developer_test",
	"environment_specific",
	"insufficient_context",
	"policy_too_strict",
	"other",
];

/** Longest note sent with a report (after redaction). */
const FALSE_POSITIVE_NOTE_MAX = 500;
const MAX_AUDIT_FILE_BYTES = 64 * 1024 * 1024;
const ACTION_PREFIX = /^[a-f0-9]{8,64}$/;

/** A blocked or held call found in the local audit log. */
export interface AuditedBlock {
	actionId: string;
	timestamp: string | null;
	decision: "deny" | "ask";
	ruleId: string | null;
	severity: string | null;
	category: string | null;
	tool: string | null;
	sessionId: string | null;
}

function str(value: unknown, max = 200): string | null {
	return typeof value === "string" && value.length > 0 && value.length <= max ? value : null;
}

function blockFrom(record: Record<string, unknown>): AuditedBlock | null {
	if (record.type !== "runtime_verdict") return null;
	const actionId = str(record.action_id, 64);
	const decision = record.verdict;
	if (!actionId || (decision !== "deny" && decision !== "ask")) return null;
	return {
		actionId,
		timestamp: str(record.timestamp, 64),
		decision,
		ruleId: str(record.matched_threat_id, 128),
		severity: str(record.severity, 32),
		category: str(record.category, 64),
		tool: str(record.tool_name, 64),
		sessionId: str(record.session_id, 200),
	};
}

/**
 * Blocked or held calls in the local audit log (active file and rotations)
 * whose action id starts with `prefix`, newest first, one entry per id. An
 * unreadable file is skipped. Throws only for a malformed prefix.
 */
export async function findAuditedBlocks(
	logging: Pick<LoggingConfig, "path" | "max_files">,
	prefix: string,
): Promise<AuditedBlock[]> {
	const wanted = prefix.trim().toLowerCase();
	if (!ACTION_PREFIX.test(wanted)) throw new Error("invalid_action_id");
	const base = resolvePath(logging.path);
	const files = [base];
	for (let index = 1; index <= Math.min(logging.max_files ?? 5, 50); index++) {
		files.push(`${base}.${index}`);
	}
	const found = new Map<string, AuditedBlock>();
	for (const file of files) {
		let content: string;
		try {
			const buffer = await readFile(file);
			if (buffer.byteLength > MAX_AUDIT_FILE_BYTES) continue;
			content = buffer.toString("utf8");
		} catch {
			continue;
		}
		for (const line of content.split("\n")) {
			if (!line.includes(wanted)) continue;
			try {
				const record = JSON.parse(line) as Record<string, unknown>;
				const block = blockFrom(record);
				if (!block || !block.actionId.startsWith(wanted)) continue;
				const previous = found.get(block.actionId);
				if (!previous || (block.timestamp ?? "") > (previous.timestamp ?? "")) {
					found.set(block.actionId, block);
				}
			} catch {
				// A torn or foreign line is not a record.
			}
		}
	}
	return [...found.values()].sort((a, b) => (b.timestamp ?? "").localeCompare(a.timestamp ?? ""));
}

/** A non-reversible reference to the OS user, never the name itself. */
function actorRef(): string {
	let name = "unknown";
	try {
		name = userInfo().username || "unknown";
	} catch {
		// No user database entry (container): one shared reference.
	}
	return `user:${createHash("sha256").update(`aidr-fp-actor\0${name}`).digest("hex").slice(0, 32)}`;
}

/** The note as it may leave the machine: redacted, single line, bounded. */
export function falsePositiveNote(note: string | undefined): string {
	if (!note) return "";
	const single = note
		.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, " ")
		.replace(/\s+/g, " ")
		.trim();
	return redactTelemetryString(single, FALSE_POSITIVE_NOTE_MAX).slice(0, FALSE_POSITIVE_NOTE_MAX);
}

export interface FalsePositiveReportInput {
	block: AuditedBlock;
	reasonCode: FalsePositiveReasonCode;
	note?: string;
	agentRuntime?: string;
}

export type FalsePositiveReportResult =
	| { ok: true; reportId: string; created: boolean; feedbackId: string }
	| {
			ok: false;
			/** `not_managed`: no control plane is usable; show the support contact instead. */
			error: string;
	  };

export interface FalsePositiveReportOptions extends DashboardApprovalOptions {
	timeoutMs?: number;
}

/** The request body; exported for tests and `--dry-run`. */
export function buildFalsePositiveReportBody(
	input: FalsePositiveReportInput,
	context: { tenantId: string; iid: string },
): { body: Record<string, unknown>; feedbackId: string } {
	const hasher = createSha256HasherContext();
	const rationale = falsePositiveNote(input.note);
	const submission: FalsePositiveFeedbackInput = {
		tenantId: context.tenantId,
		binding: {
			policyRevision: `release-${VERSION}`.replace(/[^A-Za-z0-9._:@/-]/g, "-").slice(0, 200),
			incidentId: `action:${input.block.actionId}`,
			candidateDigest: createHash("sha256").update(`aidr-release\0${VERSION}`).digest("hex"),
			deviceId: `iid:${context.iid}`.replace(/[^A-Za-z0-9._:@/-]/g, "-").slice(0, 200),
			actorRef: actorRef(),
		},
		feedback: "false_positive",
		reasonCode: input.reasonCode,
		rationale,
		origin: "runtime_verdict",
	};
	const { outcome } = recordFalsePositiveFeedback(
		createFalsePositiveFeedbackStore(context.tenantId),
		submission,
		hasher,
	);
	if (!outcome.record) throw new Error(`false_positive_feedback_${outcome.reason}`);
	const block = input.block;
	return {
		feedbackId: outcome.record.feedbackId,
		body: {
			feedback_id: outcome.record.feedbackId,
			record_hash: outcome.record.recordHash,
			iid: context.iid,
			...(input.agentRuntime ? { agent_runtime: input.agentRuntime } : {}),
			action_id: block.actionId,
			...(block.ruleId ? { rule_id: block.ruleId } : {}),
			decision: block.decision,
			...(block.severity ? { severity: block.severity } : {}),
			...(block.category ? { category: block.category } : {}),
			...(block.tool ? { tool: block.tool } : {}),
			reason_code: input.reasonCode,
			rationale,
			...(block.timestamp ? { occurred_at: block.timestamp } : {}),
		},
	};
}

/**
 * File the report in the control plane's false-positive queue. Never throws;
 * `not_managed` when this installation has no usable control plane (local
 * mode, not enrolled), so the caller can point at the support contact instead.
 */
export async function submitFalsePositiveReport(
	config: Config,
	input: FalsePositiveReportInput,
	options: FalsePositiveReportOptions = {},
): Promise<FalsePositiveReportResult> {
	try {
		const resolved = await resolveDashboardApprovalContext(config, options);
		if (!resolved.available) {
			return {
				ok: false,
				error: resolved.reason === "local_mode" ? "not_managed" : `not_managed:${resolved.reason}`,
			};
		}
		const { context } = resolved;
		const { body, feedbackId } = buildFalsePositiveReportBody(input, context);
		const fetchImpl = options.fetch ?? globalThis.fetch;
		const response = await fetchImpl(controlPlaneUrl(context.endpoint, "false-positive-reports"), {
			method: "POST",
			redirect: "error",
			signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
			headers: {
				Accept: "application/json",
				Authorization: `Bearer ${context.apiKey}`,
				"Content-Type": "application/json",
				"User-Agent": "aidr",
			},
			body: JSON.stringify(body),
		});
		const text = await response.text();
		let parsed: Record<string, unknown> = {};
		try {
			const value: unknown = JSON.parse(text);
			if (value && typeof value === "object" && !Array.isArray(value)) {
				parsed = value as Record<string, unknown>;
			}
		} catch {
			// Not JSON: reported by status below.
		}
		if (!response.ok) {
			const code =
				typeof parsed.error === "string" && /^[a-z0-9_:]{1,64}$/.test(parsed.error)
					? parsed.error
					: `http_${response.status}`;
			return { ok: false, error: code };
		}
		if (typeof parsed.report_id !== "string") return { ok: false, error: "invalid_response" };
		return {
			ok: true,
			reportId: parsed.report_id,
			created: parsed.created === true,
			feedbackId,
		};
	} catch (error) {
		const name = error instanceof Error ? error.name : "";
		return {
			ok: false,
			error: name === "TimeoutError" || name === "AbortError" ? "timeout" : "request_failed",
		};
	}
}
