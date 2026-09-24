import {
	getPendingAsk,
	type ListedPendingAsk,
	listPendingAsks,
	OPERATOR_APPROVAL_DEFAULT_TTL_MS,
	OperatorApprovalError,
	type OperatorApprovalStoreOptions,
	operatorApprovalStorePath,
	recordOperatorApproval,
} from "@singularityrd/aidr-core";
import {
	type ConfirmationStreams,
	confirmOperatorAction,
	OperatorConfirmationError,
	operatorIdentity,
} from "../utils/operator-confirm.js";

/** Test seams; production callers pass nothing. */
export interface ApprovalCommandDeps {
	store?: OperatorApprovalStoreOptions;
	env?: NodeJS.ProcessEnv;
	streams?: ConfirmationStreams;
}

function describePending(p: ListedPendingAsk): string[] {
	const lines = [
		`actionId:   ${p.actionId}`,
		`connector:  ${p.connector}   tool: ${p.tool}`,
		`risk:       ${p.severity} ${p.category}${p.threatId ? ` (${p.threatId})` : ""}`,
		`call:       ${p.summary}`,
	];
	for (const artifact of p.artifacts)
		lines.push(`artifact:   ${artifact.type} ${artifact.preview}`);
	for (const reason of p.reasons) lines.push(`reason:     ${reason}`);
	lines.push(`asked:      ${p.createdAt} (approvable until ${p.expiresAt})`);
	if (!p.verified) lines.push("integrity:  FAILED — this record cannot be approved");
	return lines;
}

function fail(message: string): void {
	console.error(message);
	process.exitCode = 1;
}

/** `aidr pending` — list asks waiting for an operator decision. */
export async function pendingCommand(
	options: { json?: boolean } = {},
	deps: ApprovalCommandDeps = {},
): Promise<void> {
	let pending: ListedPendingAsk[];
	try {
		pending = await listPendingAsks(deps.store);
	} catch (error) {
		fail(
			`Could not read the approval store: ${error instanceof Error ? error.message : String(error)}`,
		);
		return;
	}
	if (options.json) {
		console.log(JSON.stringify({ store: operatorApprovalStorePath(deps.store), pending }, null, 2));
		return;
	}
	if (pending.length === 0) {
		console.log("No Singularity AIDR asks are waiting for approval.");
		return;
	}
	console.log(`${pending.length} ask(s) waiting for an operator decision (newest first):`);
	for (const p of pending) {
		console.log("");
		for (const line of describePending(p)) console.log(`  ${line}`);
	}
	console.log("");
	console.log("Approve one retry of a call with: aidr approve <actionId>");
}

export interface ApproveOptions {
	yes?: boolean;
	ttl?: string;
	permitAllowlist?: boolean;
	json?: boolean;
}

function parseTtlMinutes(value: string | undefined): number | null {
	if (value === undefined) return OPERATOR_APPROVAL_DEFAULT_TTL_MS;
	if (!/^\d{1,4}$/.test(value.trim())) return null;
	return Number(value.trim()) * 60 * 1000;
}

/**
 * `aidr approve <actionId>` — the out-of-band, human-only approval of one ask.
 *
 * The approval is bound to the action id, the tool and the exact artifact set the
 * operator was shown, expires (15 minutes by default) and is spent by the first
 * matching retry.
 */
export async function approveCommand(
	actionId: string,
	options: ApproveOptions = {},
	deps: ApprovalCommandDeps = {},
): Promise<void> {
	const ttlMs = parseTtlMinutes(options.ttl);
	if (ttlMs === null) {
		fail("--ttl must be a whole number of minutes (1-1440).");
		return;
	}
	const normalizedId = actionId.trim().replace(/^"|"$/g, "").toLowerCase();

	let pending: ListedPendingAsk | null;
	try {
		pending = await getPendingAsk(normalizedId, deps.store);
	} catch (error) {
		fail(error instanceof Error ? error.message : String(error));
		return;
	}
	if (!pending) {
		fail(
			"No pending Singularity AIDR ask has this actionId (it may have expired or already been approved). Run `aidr pending` to list open asks.",
		);
		return;
	}
	if (!pending.verified) {
		fail(
			"This pending ask failed integrity verification (the record was edited or the approval key changed). It was not approved; have the agent retry to record a fresh ask.",
		);
		return;
	}

	const allowlistNote = options.permitAllowlist
		? "The agent will also be allowed to add these artifacts to the permanent allowlist once."
		: "The approval does not allow the agent to allowlist anything.";
	let mode: Awaited<ReturnType<typeof confirmOperatorAction>>;
	try {
		mode = await confirmOperatorAction({
			prompt: [
				"Singularity AIDR — approve a blocked agent action",
				...describePending(pending).map((line) => `  ${line}`),
				`This allows ONE retry of exactly this call within ${Math.round(ttlMs / 60000)} minute(s).`,
				allowlistNote,
			].join("\n"),
			word: "approve",
			yes: options.yes,
			env: deps.env,
			streams: deps.streams,
		});
	} catch (error) {
		fail(error instanceof OperatorConfirmationError ? error.message : String(error));
		return;
	}

	try {
		const approval = await recordOperatorApproval(
			normalizedId,
			{
				approver: operatorIdentity(mode),
				ttlMs,
				singleUse: true,
				permitAllowlist: options.permitAllowlist === true,
			},
			deps.store,
		);
		if (options.json) {
			console.log(JSON.stringify({ approved: true, approval }, null, 2));
			return;
		}
		console.log(`Approved ${approval.actionId.slice(0, 12)}… until ${approval.expiresAt}.`);
		console.log("Tell the agent to retry the same call; the approval is spent by that one retry.");
	} catch (error) {
		fail(
			error instanceof OperatorApprovalError
				? `Not approved (${error.code}): ${error.message}`
				: `Not approved: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
}
