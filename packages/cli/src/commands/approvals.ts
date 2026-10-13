import {
	describeOperatorApprovalKey,
	escapeTerminalText,
	getPendingAsk,
	type HostDialogAsk,
	type ListedPendingAsk,
	listHostDialogAsks,
	listPendingAsks,
	loadConfig,
	OPERATOR_APPROVAL_DEFAULT_TTL_MS,
	OperatorApprovalError,
	type OperatorApprovalStoreOptions,
	operatorApprovalStorePath,
	recordOperatorApproval,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
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

/**
 * Every string an agent could have influenced, with control, bidi and format
 * characters rendered visibly (`\x1b`, `\u202e`). Records are escaped when they
 * are stored; this second pass covers records from older versions and any
 * record that fails verification, so the terminal never interprets agent text.
 */
function safePending<T extends Omit<ListedPendingAsk, "verified">>(p: T): T {
	const safe = escapeTerminalText;
	return {
		...p,
		tool: safe(p.tool),
		connector: safe(p.connector),
		summary: safe(p.summary),
		artifacts: p.artifacts.map((a) => ({ ...a, type: safe(a.type), preview: safe(a.preview) })),
		severity: safe(p.severity),
		category: safe(p.category),
		reasons: p.reasons.map(safe),
		threatId: p.threatId === null ? null : safe(p.threatId),
		createdAt: safe(p.createdAt),
		expiresAt: safe(p.expiresAt),
	};
}

function describePending(pending: ListedPendingAsk): string[] {
	const p = safePending(pending);
	const lines = [
		`actionId:   ${p.actionId}`,
		`connector:  ${p.connector}   tool: ${p.tool}`,
		`risk:       ${p.severity} ${p.category}${p.threatId ? ` (${p.threatId})` : ""}`,
		`call:       ${p.summary}`,
	];
	for (const artifact of p.artifacts)
		lines.push(`artifact:   ${artifact.type} ${artifact.preview}`);
	if (p.artifactCount > p.artifacts.length) {
		lines.push(
			ct("approvals.artifactsTruncated", { shown: p.artifacts.length, total: p.artifactCount }),
		);
	}
	for (const reason of p.reasons) lines.push(`reason:     ${reason}`);
	lines.push(ct("approvals.asked", { createdAt: p.createdAt, expiresAt: p.expiresAt }));
	if (!p.verified) lines.push(ct("approvals.integrityFailed"));
	return lines;
}

/** An informational ask the host's own dialog answered: shown, never approvable. */
function describeHostDialogAsk(ask: HostDialogAsk): string[] {
	const p = safePending(ask);
	return [
		`actionId:   ${p.actionId}`,
		ct("approvals.hostDialogConnector", { connector: p.connector, tool: p.tool }),
		`risk:       ${p.severity} ${p.category}${p.threatId ? ` (${p.threatId})` : ""}`,
		`call:       ${p.summary}`,
		`asked:      ${p.createdAt}`,
	];
}

/** Informational host-dialog asks; an unreadable store lists none. */
async function hostDialogAsks(store: OperatorApprovalStoreOptions): Promise<HostDialogAsk[]> {
	try {
		return await listHostDialogAsks(store);
	} catch {
		return [];
	}
}

/** The store options with the configured key storage, unless a test injected a store. */
async function storeOptions(deps: ApprovalCommandDeps): Promise<OperatorApprovalStoreOptions> {
	if (deps.store) return deps.store;
	const config = await loadConfig();
	return { keyStorage: config.operator_approvals?.key_storage };
}

/** Say plainly when approvals cannot work, instead of an empty or confusing listing. */
function disabledNotice(store: OperatorApprovalStoreOptions): string | null {
	const status = describeOperatorApprovalKey(store);
	return status.available ? null : (status.reason ?? ct("approvals.disabled"));
}

function fail(message: string): void {
	console.error(message);
	process.exitCode = 1;
}

function printApprovablePending(pending: ListedPendingAsk[]): void {
	if (pending.length === 0) {
		console.log(ct("approvals.none"));
		return;
	}
	console.log(ct("approvals.waiting", { count: pending.length }));
	for (const p of pending) {
		console.log("");
		for (const line of describePending(p)) console.log(`  ${line}`);
	}
	console.log("");
	console.log(ct("approvals.howToApprove"));
}

function printHostDialogAsks(informational: HostDialogAsk[]): void {
	if (informational.length === 0) return;
	console.log("");
	console.log(ct("approvals.hostDialogHeader", { count: informational.length }));
	for (const ask of informational) {
		console.log("");
		for (const line of describeHostDialogAsk(ask)) console.log(`  ${line}`);
	}
	console.log("");
	console.log(ct("approvals.hostDialogRoute"));
}

/** `aidr pending` — list asks waiting for an operator decision. */
export async function pendingCommand(
	options: { json?: boolean } = {},
	deps: ApprovalCommandDeps = {},
): Promise<void> {
	const store = await storeOptions(deps);
	const disabled = disabledNotice(store);
	let pending: ListedPendingAsk[];
	try {
		pending = await listPendingAsks(store);
	} catch (error) {
		fail(
			ct("approvals.storeUnreadable", {
				error: error instanceof Error ? error.message : String(error),
			}),
		);
		return;
	}
	const informational = await hostDialogAsks(store);
	if (options.json) {
		console.log(
			JSON.stringify(
				{
					store: operatorApprovalStorePath(store),
					approvals_available: disabled === null,
					...(disabled ? { approvals_disabled_reason: disabled } : {}),
					pending: pending.map(safePending),
					host_dialog: informational.map(safePending),
				},
				null,
				2,
			),
		);
		return;
	}
	if (disabled) console.error(disabled);
	printApprovablePending(pending);
	printHostDialogAsks(informational);
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

/** The pending ask with this id if it can be approved; otherwise reports why and returns null. */
async function approvablePending(
	actionId: string,
	store: OperatorApprovalStoreOptions,
): Promise<ListedPendingAsk | null> {
	let pending: ListedPendingAsk | null;
	try {
		pending = await getPendingAsk(actionId, store);
	} catch (error) {
		fail(error instanceof Error ? error.message : String(error));
		return null;
	}
	if (!pending) {
		const informational = (await hostDialogAsks(store)).some((a) => a.actionId === actionId);
		if (informational) {
			fail(ct("approvals.answeredInHost"));
			return null;
		}
		fail(ct("approvals.notFound"));
		return null;
	}
	if (!pending.verified) {
		fail(ct("approvals.integrityRejected"));
		return null;
	}
	return pending;
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
		fail(ct("approvals.badTtl"));
		return;
	}
	const normalizedId = actionId.trim().replace(/^"|"$/g, "").toLowerCase();
	const store = await storeOptions(deps);
	const disabled = disabledNotice(store);
	if (disabled) {
		fail(ct("approvals.notApproved", { reason: disabled }));
		return;
	}

	const pending = await approvablePending(normalizedId, store);
	if (!pending) return;

	const allowlistNote = options.permitAllowlist
		? ct("approvals.allowlistPermitted")
		: ct("approvals.allowlistNotPermitted");
	let mode: Awaited<ReturnType<typeof confirmOperatorAction>>;
	try {
		mode = await confirmOperatorAction({
			prompt: [
				ct("approvals.promptTitle"),
				...describePending(pending).map((line) => `  ${line}`),
				ct("approvals.promptScope", { minutes: Math.round(ttlMs / 60000) }),
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
			store,
		);
		if (options.json) {
			console.log(JSON.stringify({ approved: true, approval }, null, 2));
			return;
		}
		console.log(
			ct("approvals.approved", {
				actionId: approval.actionId.slice(0, 12),
				expiresAt: approval.expiresAt,
			}),
		);
		console.log(ct("approvals.retryHint"));
	} catch (error) {
		fail(
			error instanceof OperatorApprovalError
				? ct("approvals.notApprovedCode", { code: error.code, reason: error.message })
				: ct("approvals.notApproved", {
						reason: error instanceof Error ? error.message : String(error),
					}),
		);
	}
}
