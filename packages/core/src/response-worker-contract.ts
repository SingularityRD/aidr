/**
 * Installed endpoint response-worker contract (T13).
 *
 * The fleet worker in `response-command-worker-v6.ts` already re-checks adapter
 * capability after a restart and reports `unsupported_action` instead of running
 * a removed action. What this module adds is the *contract* an installed worker
 * has to satisfy before it may touch a host:
 *
 *   1. **Capability is declared, never assumed.** An adapter that does not
 *      declare an action cannot be asked to run it, and the request is refused
 *      with `unsupported_action` - the host is untouched.
 *   2. **Preconditions are checked against live state.** A quarantine whose
 *      target no longer exists, whose digest changed, or whose symlink resolves
 *      outside the workspace is refused before the first write.
 *   3. **Commands are idempotent under a TTL.** The same idempotency key within
 *      its TTL returns the original receipt; after the TTL expires it is refused
 *      as stale rather than applied twice.
 *   4. **Every applied step has a named rollback.** A step the adapter cannot
 *      reverse is reported as `irreversible`, which makes the whole action
 *      `partial` instead of `applied`, so a UI can never show a clean success.
 *   5. **Nothing here inspects a filesystem.** All host access goes through the
 *      injected adapter, so the contract is exercised deterministically and an
 *      adapter that cannot do the work fails loudly instead of silently.
 */

export type ResponseCapability =
	| "quarantine_file"
	| "restore_file"
	| "terminate_process"
	| "isolate_host"
	| "revoke_credential";

export const RESPONSE_CAPABILITIES: readonly ResponseCapability[] = [
	"quarantine_file",
	"restore_file",
	"terminate_process",
	"isolate_host",
	"revoke_credential",
];

/** What an installed worker or platform adapter is allowed to attempt. */
export interface ResponseAdapter {
	readonly adapterId: string;
	readonly platform: string;
	/** The complete set of capabilities this adapter implements on this host. */
	capabilities(): readonly ResponseCapability[];
	/**
	 * Execute one primitive. Implementations must be idempotent for a repeated
	 * `idempotencyKey` and must never report success they did not observe.
	 */
	execute(step: ResponseStep): Promise<ResponseStepOutcome>;
}

export interface ResponseTargetBinding {
	/** Absolute host path for file actions, process id for process actions. */
	target: string;
	/** Expected digest of the target at planning time, when the action is file based. */
	expectedSha256: string | null;
	/** Incident/command identity this action belongs to. */
	incidentId: string;
	/** Reason the action was authorized, preserved in the receipt. */
	authorizedBy: string;
}

/**
 * Normalize an operator identity using the rule `planResponseStep` applies to
 * `binding.authorizedBy`: a missing, blank or implausibly short string is not an
 * identity.
 *
 * The response and rollback paths share this so that "who authorized this" cannot
 * be recorded as an empty string that reads like a real operator, and so the
 * minimum length is defined in exactly one place.
 */
export function normalizeAuthorizedBy(value: string | null | undefined): string | undefined {
	const trimmed = value?.trim();
	return trimmed !== undefined && trimmed.length >= 3 ? trimmed : undefined;
}

export interface ResponseStep {
	capability: ResponseCapability;
	binding: ResponseTargetBinding;
	/** Where a quarantined file is moved to. Required for file actions. */
	vaultPath: string | null;
	/** Milliseconds after which this step must not be applied. */
	ttlMs: number;
	/** Stable key; a repeat within the TTL returns the original outcome. */
	idempotencyKey: string;
	/** Whether the adapter is expected to be able to reverse this step. */
	reversible: boolean;
}

export type ResponseStepOutcome =
	| { status: "applied"; observed: string; rollbackToken: string | null }
	| { status: "noop"; observed: string; rollbackToken: null }
	| { status: "failed"; code: string; detail: string; rollbackToken: string | null }
	| { status: "refused"; code: string; detail: string };

export type ResponsePlanDecision =
	| { ok: true; step: ResponseStep }
	| { ok: false; code: string; detail: string };

const CAPABILITY_SET = new Set<string>(RESPONSE_CAPABILITIES);
const IDEMPOTENCY_KEY = /^[A-Za-z0-9_.:-]{8,200}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;

export interface PlanResponseRequest {
	adapter: Pick<ResponseAdapter, "adapterId" | "platform" | "capabilities">;
	capability: ResponseCapability;
	binding: ResponseTargetBinding;
	vaultPath?: string | null;
	ttlMs?: number;
	idempotencyKey: string;
	/**
	 * Live digest of the target, as observed by the caller. `null` means the
	 * caller could not read the target. A file action with a planned digest and
	 * an unreadable or mismatched live digest is refused: moving a file that
	 * already changed would silently discard the newer content.
	 */
	liveSha256?: string | null;
	/** Whether the caller can prove the target currently exists. */
	liveExists?: boolean;
	/** Whether the target path resolves through a symlink out of the workspace. */
	escapesWorkspace?: boolean;
	/** Whether the machine currently has the privilege the action needs. */
	hasPrivilege?: boolean;
}

/**
 * Decide whether a response step may be planned.
 *
 * Every refusal carries a machine-readable code, and none of them touch the
 * host. The caller must surface the code: an operator needs to distinguish "we
 * chose not to" from "we could not".
 */
export function planResponseStep(request: PlanResponseRequest): ResponsePlanDecision {
	if (!CAPABILITY_SET.has(request.capability)) {
		return { ok: false, code: "unknown_capability", detail: String(request.capability) };
	}
	const declared = request.adapter.capabilities();
	if (!declared.includes(request.capability)) {
		// The adapter is the authority on what this host can do. A control-plane
		// request for anything else is refused, never attempted and never faked.
		return {
			ok: false,
			code: "unsupported_action",
			detail: `${request.adapter.adapterId} does not declare ${request.capability}`,
		};
	}
	if (!IDEMPOTENCY_KEY.test(request.idempotencyKey)) {
		return { ok: false, code: "invalid_idempotency_key", detail: "idempotency key is malformed" };
	}
	const ttlMs = request.ttlMs ?? 5 * 60 * 1000;
	if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > MAX_TTL_MS) {
		return { ok: false, code: "invalid_ttl", detail: "ttl must be between 1s and 24h" };
	}
	const binding = request.binding;
	if (!binding || typeof binding.target !== "string" || binding.target.trim() === "") {
		return { ok: false, code: "missing_target", detail: "target is required" };
	}
	if (typeof binding.incidentId !== "string" || binding.incidentId.trim() === "") {
		return { ok: false, code: "missing_incident", detail: "incidentId is required" };
	}
	if (typeof binding.authorizedBy !== "string" || binding.authorizedBy.trim().length < 3) {
		return { ok: false, code: "missing_authorization", detail: "authorizedBy is required" };
	}
	if (binding.expectedSha256 !== null && !SHA256.test(binding.expectedSha256)) {
		return {
			ok: false,
			code: "invalid_expected_digest",
			detail: "expectedSha256 must be a SHA-256",
		};
	}
	if (request.escapesWorkspace === true) {
		return {
			ok: false,
			code: "target_escapes_workspace",
			detail: "the resolved target is outside the permitted root",
		};
	}

	const fileAction =
		request.capability === "quarantine_file" || request.capability === "restore_file";
	if (fileAction) {
		if (request.liveExists !== true) {
			return { ok: false, code: "target_missing", detail: "the target does not exist" };
		}
		if (typeof request.vaultPath !== "string" || request.vaultPath.trim() === "") {
			return { ok: false, code: "missing_vault_path", detail: "a vault path is required" };
		}
		if (binding.expectedSha256 !== null) {
			if (typeof request.liveSha256 !== "string" || !SHA256.test(request.liveSha256)) {
				return {
					ok: false,
					code: "target_unreadable",
					detail: "the target digest could not be read",
				};
			}
			if (request.liveSha256 !== binding.expectedSha256) {
				return {
					ok: false,
					code: "target_changed",
					detail: "the target digest no longer matches the authorized digest",
				};
			}
		}
	}
	if (request.capability === "isolate_host" && request.hasPrivilege !== true) {
		return {
			ok: false,
			code: "insufficient_privilege",
			detail: "host isolation requires an elevated platform adapter",
		};
	}
	if (
		(request.capability === "terminate_process" || request.capability === "revoke_credential") &&
		request.hasPrivilege !== true
	) {
		return {
			ok: false,
			code: "insufficient_privilege",
			detail: `${request.capability} requires the documented privilege`,
		};
	}

	return {
		ok: true,
		step: {
			capability: request.capability,
			binding,
			vaultPath: fileAction ? (request.vaultPath as string) : null,
			ttlMs,
			idempotencyKey: request.idempotencyKey,
			reversible: request.capability !== "isolate_host",
		},
	};
}

export interface ResponseReceipt {
	commandId: string;
	incidentId: string;
	adapterId: string;
	platform: string;
	capability: ResponseCapability;
	status: "applied" | "partial" | "failed" | "refused" | "noop";
	code: string;
	target: string;
	observed: string | null;
	rollbackToken: string | null;
	rollbackPossible: boolean;
	appliedAtUtc: string;
	/** True only when every applied step was reversible and observed. */
	fullyReversible: boolean;
	idempotencyKey: string;
}

export interface ResponseJournalEntry {
	idempotencyKey: string;
	expiresAtMs: number;
	outcome: ResponseStepOutcome;
	receipt: ResponseReceipt;
}

/** Storage the worker supplies; it is expected to be durable across restarts. */
export interface ResponseJournal {
	get(idempotencyKey: string): Promise<ResponseJournalEntry | null>;
	put(entry: ResponseJournalEntry): Promise<void>;
}

/** In-memory journal for tests and for a worker without durable storage yet. */
export class MemoryResponseJournal implements ResponseJournal {
	#entries = new Map<string, ResponseJournalEntry>();
	get(idempotencyKey: string): Promise<ResponseJournalEntry | null> {
		return Promise.resolve(this.#entries.get(idempotencyKey) ?? null);
	}
	put(entry: ResponseJournalEntry): Promise<void> {
		this.#entries.set(entry.idempotencyKey, entry);
		return Promise.resolve();
	}
}

export interface ExecuteResponseOptions {
	adapter: ResponseAdapter;
	journal: ResponseJournal;
	/** Injected clock, in epoch milliseconds. */
	now?: () => number;
}

export interface ExecuteResponseResult {
	receipt: ResponseReceipt;
	/** True when the receipt was replayed from the journal rather than re-applied. */
	replayed: boolean;
}

/**
 * Execute one planned response step.
 *
 * A repeated idempotency key inside its TTL returns the original receipt with
 * `replayed: true` and never calls the adapter again. A repeated key whose TTL
 * has expired is `refused` with `stale_command` - the operator has to
 * re-authorize, because the world may have moved on.
 */
export async function executeResponseStep(
	step: ResponseStep,
	options: ExecuteResponseOptions,
): Promise<ExecuteResponseResult> {
	const now = options.now ?? Date.now;
	const startedAt = now();
	const existing = await options.journal.get(step.idempotencyKey);
	if (existing) {
		if (existing.expiresAtMs > startedAt) return { receipt: existing.receipt, replayed: true };
		return {
			replayed: true,
			receipt: {
				commandId: step.idempotencyKey,
				incidentId: step.binding.incidentId,
				adapterId: options.adapter.adapterId,
				platform: options.adapter.platform,
				capability: step.capability,
				status: "refused",
				code: "stale_command",
				target: step.binding.target,
				observed: null,
				rollbackToken: null,
				rollbackPossible: false,
				appliedAtUtc: new Date(startedAt).toISOString(),
				fullyReversible: false,
				idempotencyKey: step.idempotencyKey,
			},
		};
	}

	let outcome: ResponseStepOutcome;
	try {
		outcome = await options.adapter.execute(step);
	} catch (error) {
		outcome = {
			status: "failed",
			code: "adapter_threw",
			detail: error instanceof Error ? error.message : String(error),
			rollbackToken: null,
		};
	}

	const status: ResponseReceipt["status"] =
		outcome.status === "applied"
			? step.reversible && outcome.rollbackToken !== null
				? "applied"
				: step.reversible
					? // An applied step with no rollback token cannot be undone on
						// request, so the action is partial and the operator must know.
						"partial"
					: "partial"
			: outcome.status === "noop"
				? "noop"
				: outcome.status;

	const receipt: ResponseReceipt = {
		commandId: step.idempotencyKey,
		incidentId: step.binding.incidentId,
		adapterId: options.adapter.adapterId,
		platform: options.adapter.platform,
		capability: step.capability,
		status,
		code:
			outcome.status === "applied"
				? status === "applied"
					? "applied"
					: "applied_without_rollback"
				: outcome.status === "noop"
					? "already_in_desired_state"
					: outcome.code,
		target: step.binding.target,
		observed: outcome.status === "applied" || outcome.status === "noop" ? outcome.observed : null,
		rollbackToken: outcome.status === "refused" ? null : outcome.rollbackToken,
		rollbackPossible: outcome.status !== "refused" && outcome.rollbackToken !== null,
		appliedAtUtc: new Date(startedAt).toISOString(),
		fullyReversible: status === "applied",
		idempotencyKey: step.idempotencyKey,
	};

	await options.journal.put({
		idempotencyKey: step.idempotencyKey,
		expiresAtMs: startedAt + step.ttlMs,
		outcome,
		receipt,
	});
	return { receipt, replayed: false };
}

export interface ResponseRollbackRequest {
	adapter: Pick<ResponseAdapter, "adapterId" | "capabilities">;
	receipt: ResponseReceipt;
	/** Rollback is only attempted for a receipt that carried a token. */
	idempotencyKey: string;
}

/**
 * Build the rollback step for a receipt.
 *
 * A receipt without a rollback token cannot be reversed: the result is an
 * explicit `refused`/`no_rollback_token` rather than a silent no-op that a UI
 * could render as "restored".
 */
export function planResponseRollback(request: ResponseRollbackRequest): ResponsePlanDecision {
	const { receipt } = request;
	if (receipt.rollbackToken === null) {
		return {
			ok: false,
			code: "no_rollback_token",
			detail: `${receipt.capability} recorded no rollback token`,
		};
	}
	const inverse: Partial<Record<ResponseCapability, ResponseCapability>> = {
		quarantine_file: "restore_file",
		restore_file: "quarantine_file",
	};
	const capability = inverse[receipt.capability];
	if (!capability) {
		return {
			ok: false,
			code: "no_inverse_action",
			detail: `${receipt.capability} has no inverse on this adapter`,
		};
	}
	if (!request.adapter.capabilities().includes(capability)) {
		return {
			ok: false,
			code: "unsupported_action",
			detail: `${request.adapter.adapterId} does not declare ${capability}`,
		};
	}
	return {
		ok: true,
		step: {
			capability,
			binding: {
				target: receipt.target,
				expectedSha256: null,
				incidentId: receipt.incidentId,
				authorizedBy: `rollback:${receipt.commandId}`,
			},
			vaultPath: receipt.rollbackToken,
			ttlMs: 5 * 60 * 1000,
			idempotencyKey: request.idempotencyKey,
			reversible: false,
		},
	};
}

/**
 * The installed-worker capability report.
 *
 * This is the contract the control plane consumes to decide whether it may
 * advertise an action for a device. A device that reports a capability it did
 * not declare is inconsistent, and inconsistency is reported rather than
 * resolved in the action's favour.
 */
export interface WorkerCapabilityReport {
	adapterId: string;
	platform: string;
	declared: readonly ResponseCapability[];
	/** Capabilities the control plane asked about that this worker cannot do. */
	missing: readonly ResponseCapability[];
	/** Human-readable limitations the operator UI must show. */
	limitations: readonly string[];
}

export function reportWorkerCapabilities(
	adapter: Pick<ResponseAdapter, "adapterId" | "platform" | "capabilities">,
	requested: readonly string[],
): WorkerCapabilityReport {
	const declared = adapter.capabilities();
	const known = requested.filter((entry): entry is ResponseCapability => CAPABILITY_SET.has(entry));
	const requestedUnknown = requested.filter((entry) => !CAPABILITY_SET.has(entry));
	const missing = known.filter((capability) => !declared.includes(capability));
	const limitations = [
		...(requestedUnknown.length
			? [`unknown capability requested: ${requestedUnknown.join(", ")}`]
			: []),
		...(missing.length ? [`not implemented on this host: ${missing.join(", ")}`] : []),
		...(declared.includes("isolate_host")
			? []
			: ["host network isolation is not provided by this adapter"]),
	];
	return {
		adapterId: adapter.adapterId,
		platform: adapter.platform,
		declared,
		missing,
		limitations,
	};
}
