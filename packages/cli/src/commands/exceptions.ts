import {
	addDetectionException,
	DETECTION_EXCEPTION_MAX_TTL_MS,
	DETECTION_EXCEPTION_MIN_TTL_MS,
	DetectionExceptionError,
	type DetectionExceptionStoreOptions,
	type DetectionExceptionSubject,
	detectionExceptionStorePath,
	escapeTerminalText,
	isProtectedRule,
	type ListedDetectionException,
	listDetectionExceptions,
	loadConfig,
	OperatorApprovalError,
	removeDetectionException,
} from "@singularityrd/aidr-core";
import {
	type ConfirmationStreams,
	confirmOperatorAction,
	OperatorConfirmationError,
	operatorIdentity,
} from "../utils/operator-confirm.js";

/**
 * `aidr exception add|list|remove` — time-limited detection exceptions.
 *
 * An exception lifts one detection rule for one user, agent or repository until
 * it expires (at most 30 days). Adding one widens what the policed agent may do,
 * so it is operator-only: interactive confirmation (or `--yes` with
 * AIDR_OPERATOR_NONINTERACTIVE=1), the record signed with the operator approval
 * key from the OS vault, and the self-defense rule CLT-SELF-007 denies an agent
 * command that runs `aidr exception add`. Self-defense rules cannot be excepted.
 */

/** Test seams; production callers pass nothing. */
export interface ExceptionCommandDeps {
	store?: DetectionExceptionStoreOptions;
	env?: NodeJS.ProcessEnv;
	streams?: ConfirmationStreams;
}

export interface ExceptionAddOptions {
	user?: string;
	agent?: string;
	repo?: string;
	expires?: string;
	reason?: string;
	artifact?: string;
	yes?: boolean;
	json?: boolean;
}

function fail(message: string): void {
	console.error(message);
	process.exitCode = 1;
}

async function storeOptions(deps: ExceptionCommandDeps): Promise<DetectionExceptionStoreOptions> {
	if (deps.store) return deps.store;
	const config = await loadConfig();
	return { approvals: { keyStorage: config.operator_approvals?.key_storage } };
}

const UNIT_MS: Record<string, number> = { m: 60_000, h: 3_600_000, d: 86_400_000 };

/** `30m`, `12h`, `7d` → milliseconds within the allowed window, or null. */
export function parseExceptionDuration(value: string | undefined): number | null {
	const match = /^(\d{1,5})([mhd])$/.exec((value ?? "").trim().toLowerCase());
	if (!match) return null;
	const ms = Number(match[1]) * (UNIT_MS[match[2] as string] ?? 0);
	return ms >= DETECTION_EXCEPTION_MIN_TTL_MS && ms <= DETECTION_EXCEPTION_MAX_TTL_MS ? ms : null;
}

function subjectFrom(options: ExceptionAddOptions): DetectionExceptionSubject | null {
	const given = (
		[
			["user", options.user],
			["agent", options.agent],
			["repo", options.repo],
		] as const
	).filter(([, value]) => typeof value === "string" && value.trim() !== "");
	if (given.length !== 1) return null;
	const [kind, value] = given[0] as readonly [DetectionExceptionSubject["kind"], string];
	return { kind, value: value.trim() };
}

function describeException(e: ListedDetectionException): string[] {
	const safe = escapeTerminalText;
	const lines = [
		`id:        ${safe(e.id)}`,
		`rule:      ${safe(e.ruleId)}${e.artifactSha256 ? ` (one artifact, sha256 ${e.artifactSha256.slice(0, 12)}…)` : " (every artifact)"}`,
		`subject:   ${e.subject.kind} ${safe(e.subject.value)}`,
		`expires:   ${safe(e.expiresAt)}`,
		`reason:    ${safe(e.reason)}`,
		`created:   ${safe(e.createdAt)} by ${safe(e.createdBy)}`,
	];
	if ("verified" in e && !e.verified) {
		lines.push("integrity: FAILED — this record is ignored by every connector");
	}
	if ("expired" in e && e.expired) lines.push("state:     expired (no longer applied)");
	return lines;
}

function errorText(error: unknown): string {
	if (error instanceof DetectionExceptionError || error instanceof OperatorApprovalError) {
		return `${error.message} (${error.code})`;
	}
	return error instanceof Error ? error.message : String(error);
}

/** `aidr exception add <ruleId>` — operator only, interactive confirmation. */
export async function exceptionAddCommand(
	ruleId: string,
	options: ExceptionAddOptions = {},
	deps: ExceptionCommandDeps = {},
): Promise<void> {
	const subject = subjectFrom(options);
	if (!subject) {
		fail("Name exactly one subject: --user <name>, --agent <runtime> or --repo <path|remote>.");
		return;
	}
	const ttlMs = parseExceptionDuration(options.expires);
	if (ttlMs === null) {
		fail("--expires is required: a duration such as 30m, 12h or 7d (5 minutes to 30 days).");
		return;
	}
	if (!options.reason?.trim()) {
		fail("--reason is required.");
		return;
	}
	if (isProtectedRule(ruleId)) {
		fail(`${ruleId} is a self-defense rule; it cannot be excepted.`);
		return;
	}

	const expiresAt = new Date(Date.now() + ttlMs).toISOString();
	let mode: Awaited<ReturnType<typeof confirmOperatorAction>>;
	try {
		mode = await confirmOperatorAction({
			prompt: [
				"Singularity AIDR — add a time-limited detection exception",
				`  rule:     ${escapeTerminalText(ruleId)}`,
				`  scope:    ${options.artifact ? `exactly ${escapeTerminalText(options.artifact)}` : "every artifact this rule matches"}`,
				`  subject:  ${subject.kind} ${escapeTerminalText(subject.value)}`,
				`  expires:  ${expiresAt} (lifts automatically)`,
				`  reason:   ${escapeTerminalText(options.reason.trim())}`,
				"Matches of this rule will NOT be blocked or flagged for this subject until then; every use is audited.",
			].join("\n"),
			word: "except",
			yes: options.yes,
			env: deps.env,
			streams: deps.streams,
		});
	} catch (error) {
		fail(error instanceof OperatorConfirmationError ? error.message : String(error));
		return;
	}

	try {
		const store = await storeOptions(deps);
		const created = await addDetectionException(
			{
				ruleId,
				artifact: options.artifact,
				subject,
				ttlMs,
				reason: options.reason,
				createdBy: operatorIdentity(mode),
			},
			store,
		);
		if (options.json) {
			console.log(JSON.stringify({ added: true, exception: created }, null, 2));
			return;
		}
		console.log(`Added exception ${created.id} for ${created.ruleId} until ${created.expiresAt}.`);
	} catch (error) {
		fail(`Not added: ${errorText(error)}`);
	}
}

/** `aidr exception list` — local exceptions (active by default). */
export async function exceptionListCommand(
	options: { all?: boolean; json?: boolean } = {},
	deps: ExceptionCommandDeps = {},
): Promise<void> {
	const store = await storeOptions(deps);
	let listed: ListedDetectionException[];
	try {
		listed = await listDetectionExceptions(store, { includeExpired: options.all === true });
	} catch (error) {
		fail(`Could not read the exception store: ${errorText(error)}`);
		return;
	}
	if (options.json) {
		console.log(
			JSON.stringify({ store: detectionExceptionStorePath(store), exceptions: listed }, null, 2),
		);
		return;
	}
	if (listed.length === 0) {
		console.log("No local Singularity AIDR detection exceptions are active.");
		return;
	}
	console.log(`${listed.length} detection exception(s), newest first:`);
	for (const e of listed) {
		console.log("");
		for (const line of describeException(e)) console.log(`  ${line}`);
	}
}

/** `aidr exception remove <id>` — revoke now (recorded in the operator ledger). */
export async function exceptionRemoveCommand(
	id: string,
	options: { json?: boolean } = {},
	deps: ExceptionCommandDeps = {},
): Promise<void> {
	try {
		const store = await storeOptions(deps);
		const removed = await removeDetectionException(id.trim(), store);
		if (options.json) {
			console.log(JSON.stringify({ removed: true, exception: removed }, null, 2));
			return;
		}
		console.log(`Removed exception ${removed.id} (${removed.ruleId}); it no longer applies.`);
	} catch (error) {
		fail(`Not removed: ${errorText(error)}`);
	}
}
