/**
 * Native-host acceptance observations.
 *
 * The native-host gate (`scripts/verify-native-host-matrix-v6.mjs`) drives a
 * real installed host through seven acceptance cases. For each case it must
 * observe three independent things:
 *
 *   1. the attempt   — the host really tried to perform the action;
 *   2. the hook      — this connector was really invoked for that attempt;
 *   3. the sentinel  — whether the side effect actually happened.
 *
 * The gate supplies the receipt path, case nonce and disposable workspace to
 * instrumented connector entry points through environment variables. This
 * module records that the connector reached its hook path; it does not prove
 * that the host attempted the action or that the host prevented its side
 * effect. Those observations must come from the host run and its sentinel, and
 * still require real-host execution and independent review.
 *
 * This module is the connector side of that contract. It is deliberately tiny
 * and deliberately inert outside an acceptance run:
 *
 *   * Outside a gate run these variables are absent, `createHostObservation`
 *     returns null, and nothing is written anywhere. Production behaviour is
 *     unchanged.
 *   * Inside a gate run the connector appends one nonce-stamped line to the
 *     receipt file. The gate correlates that line with the case it launched, so
 *     a receipt from a different case cannot satisfy the observation.
 *
 * It must never write the sentinel. The sentinel records whether the protected
 * action's side effect occurred; a connector that wrote it would forge the very
 * evidence the gate exists to collect. Only the host's own action may create it.
 */

import { appendFileSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

/** Environment variables the native-host gate injects into the host process. */
export const HOST_OBSERVATION_ENV = Object.freeze({
	receipt: "AIDR_NATIVE_TEST_RECEIPT",
	nonce: "AIDR_NATIVE_TEST_CASE_NONCE",
	workspace: "AIDR_NATIVE_TEST_WORKSPACE",
});

/**
 * Marker written into the receipt. The gate matches on the nonce, so this text
 * only has to be stable and greppable; it carries no verdict.
 */
export const HOST_OBSERVATION_MARKER = "AIDR_HOOK_OBSERVED";

export interface HostObservation {
	/** Absolute path of the receipt the connector appends to. */
	readonly receiptPath: string;
	/** Nonce identifying the case this invocation belongs to. */
	readonly nonce: string;
	/** Disposable workspace the gate created for the case. */
	readonly workspace: string;
}

export interface HostObservationRecord {
	/** Connector that handled the call, for example `claude-code`. */
	connector: string;
	/** Host event name, for example `PreToolUse`. */
	event: string;
	/** Tool name the host was about to run, when it supplied one. */
	toolName?: string;
	/** Verdict the connector reached, when it reached one. */
	decision?: string;
}

/**
 * Read the gate's observation contract from the environment.
 *
 * Returns `null` when this process is not part of a native-host acceptance run,
 * which is the normal case for every real user. A partial contract (for example
 * a receipt path with no nonce) is also treated as absent rather than guessed:
 * the gate refuses to correlate an observation it cannot bind to a case, so
 * writing one would only produce a misleading receipt.
 */
export function createHostObservation(
	env: NodeJS.ProcessEnv = process.env,
): HostObservation | null {
	const receiptPath = env[HOST_OBSERVATION_ENV.receipt]?.trim();
	const nonce = env[HOST_OBSERVATION_ENV.nonce]?.trim();
	const workspace = env[HOST_OBSERVATION_ENV.workspace]?.trim();
	if (!receiptPath || !nonce || !workspace) return null;
	if (!isAbsolute(receiptPath) || !isAbsolute(workspace)) return null;
	const resolvedWorkspace = resolve(workspace);
	const resolvedReceipt = resolve(receiptPath);
	const receiptRelative = relative(resolvedWorkspace, resolvedReceipt);
	if (
		!receiptRelative ||
		receiptRelative === ".." ||
		receiptRelative.startsWith(`..${sep}`) ||
		isAbsolute(receiptRelative)
	)
		return null;
	return { receiptPath: resolvedReceipt, nonce, workspace: resolvedWorkspace };
}

/**
 * Append one observation line to the receipt.
 *
 * Never throws: an acceptance observation is diagnostic, and a connector that
 * blocked a real tool call must not turn a failed diagnostic write into a
 * different failure. A write error returns `false` so a caller that cares can
 * report it, but the verdict is already decided by then.
 */
export function recordHostObservation(
	observation: HostObservation | null,
	record: HostObservationRecord,
): boolean {
	if (!observation) return false;
	try {
		const line = JSON.stringify({
			marker: HOST_OBSERVATION_MARKER,
			nonce: observation.nonce,
			connector: record.connector,
			event: record.event,
			...(record.toolName === undefined ? {} : { toolName: record.toolName }),
			...(record.decision === undefined ? {} : { decision: record.decision }),
		});
		appendFileSync(observation.receiptPath, `${line}\n`, "utf8");
		return true;
	} catch {
		return false;
	}
}
