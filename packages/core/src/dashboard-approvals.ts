/**
 * Managed-mode dashboard approvals (client side).
 *
 * ## What this adds
 *
 * In LOCAL mode an `ask` is released by the operator CLI (`aidr approve`), which
 * runs as the same OS user as the agent. In MANAGED mode an `ask` can instead be
 * approved by an administrator in the AIDR dashboard: a different, authenticated
 * (AAL2) human on a different device. The approval travels back as a token the
 * control plane signs with the tenant's Ed25519 approval key; the verification
 * keys reach this installation only inside the ed25519-signed entitlement, so
 * neither the agent nor anything else on this machine can mint a valid token.
 *
 * ## Flow
 *
 * 1. An `ask` in managed mode: {@link processDashboardApproval} submits an approval
 *    request (`POST /v1/approval-requests`, idempotent on tenant/iid/action_id)
 *    and remembers its `request_id` in a small state file so the NEXT process
 *    (Claude Code and Codex run one process per hook call) can find it. The call
 *    stays blocked; the block reason names the request id for the user.
 * 2. The identical retry (same action id and artifact digest): the request's status
 *    is polled. `approved` comes with a token, which is verified
 *    ({@link verifyDashboardApprovalToken}): Ed25519 signature under a key id from
 *    the verified entitlement, tenant / iid / action id / artifact digest / tool
 *    binding, decision, lifetime and expiry. Its nonce is then spent in the
 *    operator-approval consumption ledger (OS vault by default, read back after
 *    writing), so it releases exactly ONE call, across processes, even if a file
 *    the agent can write is rolled back.
 *
 * ## Failure policy (fail closed)
 *
 * Every network call is bounded ({@link DASHBOARD_APPROVAL_REQUEST_TIMEOUT_MS}
 * each, {@link DASHBOARD_APPROVAL_TOTAL_BUDGET_MS} in total) so the hook never
 * outlives its own deadline. Any failure (network, bad token, unknown key,
 * mismatched binding, expiry, replay, unusable ledger) is logged and audited, and
 * the call stays blocked. Nothing here is callable by the agent: there is no tool,
 * only the out-of-band dashboard.
 */

import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { logDashboardApprovalEvent, toolInputSummaryText } from "./audit-log.js";
import { assertSecureControlPlaneEndpoint, controlPlaneUrl } from "./clients/control-plane-url.js";
import { AIDR_DIR, resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import { getInstallationId } from "./installation-id.js";
import {
	type ApprovalPublicKeyEntry,
	isEntitlementActive,
	isSyncDisabled,
	loadManagedState,
	managedStatePath,
} from "./managed.js";
import {
	artifactSetDigest,
	type OperatorApprovalStoreOptions,
	spendExternalApprovalToken,
} from "./operator-approvals.js";
import { redactTelemetryString } from "./telemetry-redaction.js";
import { boundTerminalText } from "./terminal-text.js";
import type { Artifact, Config, Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/** Audit / verdict source of a call released by a dashboard approval. */
export const DASHBOARD_APPROVAL_SOURCE = "dashboard_approval";
/** Longest lifetime of an approval token (contract: expires_at <= issued_at + 15 min). */
export const DASHBOARD_APPROVAL_TOKEN_MAX_TTL_MS = 15 * 60 * 1000;
/** Lifetime requested for an approval request (contract maximum: 30 minutes). */
export const DASHBOARD_APPROVAL_REQUEST_TTL_MS = 25 * 60 * 1000;
/** Bound on each control-plane call made on the hook path. */
export const DASHBOARD_APPROVAL_REQUEST_TIMEOUT_MS = 1_500;
/** Bound on all control-plane calls for one tool call. */
export const DASHBOARD_APPROVAL_TOTAL_BUDGET_MS = 3_000;
/** Tolerated clock skew for a token issued "in the future". */
const CLOCK_SKEW_MS = 2 * 60 * 1000;
/**
 * A spent nonce is remembered this long past its token's expiry, so a local
 * clock set back after the ledger pruned it cannot make the token valid again.
 */
const NONCE_LEDGER_MARGIN_MS = 60 * 60 * 1000;
const NONCE_LEDGER_DOMAIN = "dashboard-approval-nonce";
const STATE_FILE = "dashboard-approval-requests.json";
const MAX_STATE_BYTES = 256 * 1024;
const MAX_RECORDS = 200;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_TOKEN_LENGTH = 8 * 1024;
const MAX_SUMMARY = 512;
const MAX_TOOL = 64;
const MAX_THREAT_IDS = 16;

const ACTION_ID = /^[A-Za-z0-9._:-]{8,128}$/;
const ARTIFACT_DIGEST = /^sha256:[a-f0-9]{64}$/;
const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const KEY_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const NONCE = /^[A-Za-z0-9._~+/=:-]{16,256}$/;

// ── Binding and digests ──────────────────────────────────────────────

/** Contract artifact digest: `sha256:` + the operator-approval artifact-set digest. */
export function dashboardArtifactDigest(artifacts: readonly Pick<Artifact, "type" | "value">[]) {
	return `sha256:${artifactSetDigest(artifacts)}`;
}

/** Tool name as sent to (and bound by) the control plane. */
export function dashboardToolName(toolName: string): string {
	return toolName.slice(0, MAX_TOOL);
}

/** What an approval token must be bound to for this installation and call. */
export interface DashboardApprovalBinding {
	tenantId: string;
	iid: string;
	actionId: string;
	artifactDigest: string;
	tool: string;
}

// ── Token verification ───────────────────────────────────────────────

export interface DashboardApprovalTokenPayload {
	v: 1;
	tenant_id: string;
	iid: string;
	action_id: string;
	artifact_digest: string;
	tool: string;
	decision: "approve";
	approver_id: string;
	issued_at: string;
	expires_at: string;
	nonce: string;
}

export type DashboardTokenRejection =
	| "missing_policy_keys"
	| "unknown_key_id"
	| "malformed"
	| "bad_signature"
	| "unsupported_version"
	| "not_approved"
	| "tenant_mismatch"
	| "iid_mismatch"
	| "action_mismatch"
	| "digest_mismatch"
	| "tool_mismatch"
	| "lifetime_too_long"
	| "not_yet_valid"
	| "expired"
	| "invalid_nonce";

export type DashboardTokenVerification =
	| { ok: true; payload: DashboardApprovalTokenPayload }
	| { ok: false; reason: DashboardTokenRejection };

function reject(reason: DashboardTokenRejection): DashboardTokenVerification {
	return { ok: false, reason };
}

function ed25519Key(spkiB64: string) {
	try {
		const key = createPublicKey({
			key: Buffer.from(spkiB64, "base64"),
			format: "der",
			type: "spki",
		});
		return key.asymmetricKeyType === "ed25519" ? key : null;
	} catch {
		return null;
	}
}

function isoMs(value: unknown): number | null {
	if (typeof value !== "string" || value.length > 64) return null;
	const ms = Date.parse(value);
	return Number.isFinite(ms) ? ms : null;
}

/**
 * Verify a dashboard approval token for one specific pending ask.
 *
 * Token format: `base64url(payload) + "." + base64url(signature)`, the payload
 * being the canonical JSON the control plane signed. The Ed25519 signature is
 * checked over the payload bytes (and, for JWS-style signers, over the encoded
 * payload segment), under the key `keyId` names — which must be one of the
 * `approval_public_keys` of the verified entitlement. Pure: nonce single use is
 * the caller's job ({@link processDashboardApproval}).
 */
export function verifyDashboardApprovalToken(params: {
	token: unknown;
	keyId: unknown;
	publicKeys: readonly ApprovalPublicKeyEntry[];
	expected: DashboardApprovalBinding;
	now: number;
}): DashboardTokenVerification {
	if (params.publicKeys.length === 0) return reject("missing_policy_keys");
	const keyId = typeof params.keyId === "string" ? params.keyId : "";
	const entry = KEY_ID.test(keyId) ? params.publicKeys.find((k) => k.key_id === keyId) : undefined;
	const key = entry ? ed25519Key(entry.public_key_spki_b64) : null;
	if (!key) return reject("unknown_key_id");
	const decoded = verifiedPayloadBytes(params.token, key);
	if ("reason" in decoded) return reject(decoded.reason);
	return checkClaims(decoded.bytes, params.expected, params.now);
}

/**
 * Decode the token and check its Ed25519 signature under `key`. Returns the
 * signed payload bytes, or the rejection.
 */
function verifiedPayloadBytes(
	token: unknown,
	key: KeyObject,
): { bytes: Buffer } | { reason: DashboardTokenRejection } {
	if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) return { reason: "malformed" };
	const parts = token.split(".");
	if (parts.length !== 2 || !parts.every((part) => BASE64URL.test(part))) {
		return { reason: "malformed" };
	}
	const [encodedPayload, encodedSignature] = parts as [string, string];
	const bytes = Buffer.from(encodedPayload, "base64url");
	const signature = Buffer.from(encodedSignature, "base64url");
	if (signature.length !== 64 || bytes.length === 0) return { reason: "malformed" };
	try {
		if (cryptoVerify(null, bytes, key, signature)) return { bytes };
		if (cryptoVerify(null, Buffer.from(encodedPayload, "ascii"), key, signature)) return { bytes };
	} catch {
		// A verifier error is a failed verification.
	}
	return { reason: "bad_signature" };
}

const STRING_CLAIMS = [
	"tenant_id",
	"iid",
	"action_id",
	"artifact_digest",
	"tool",
	"approver_id",
	"nonce",
] as const;

/** Check the claims of an authentic payload against the pending ask and the clock. */
function checkClaims(
	bytes: Buffer,
	expected: DashboardApprovalBinding,
	now: number,
): DashboardTokenVerification {
	let parsed: unknown;
	try {
		parsed = JSON.parse(bytes.toString("utf8"));
	} catch {
		return reject("malformed");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return reject("malformed");
	const p = parsed as Record<string, unknown>;
	if (p.v !== 1) return reject("unsupported_version");
	if (p.decision !== "approve") return reject("not_approved");
	if (STRING_CLAIMS.some((field) => typeof p[field] !== "string")) return reject("malformed");

	const bindings: Array<[unknown, string, DashboardTokenRejection]> = [
		[p.tenant_id, expected.tenantId, "tenant_mismatch"],
		[p.iid, expected.iid, "iid_mismatch"],
		[p.action_id, expected.actionId, "action_mismatch"],
		[p.artifact_digest, expected.artifactDigest, "digest_mismatch"],
		[p.tool, expected.tool, "tool_mismatch"],
	];
	for (const [actual, wanted, reason] of bindings) {
		if (actual !== wanted) return reject(reason);
	}

	const issuedAt = isoMs(p.issued_at);
	const expiresAt = isoMs(p.expires_at);
	if (issuedAt === null || expiresAt === null || expiresAt <= issuedAt) return reject("malformed");
	if (expiresAt - issuedAt > DASHBOARD_APPROVAL_TOKEN_MAX_TTL_MS) {
		return reject("lifetime_too_long");
	}
	if (issuedAt > now + CLOCK_SKEW_MS) return reject("not_yet_valid");
	if (now >= expiresAt) return reject("expired");
	if (!NONCE.test(p.nonce as string)) return reject("invalid_nonce");
	return { ok: true, payload: p as unknown as DashboardApprovalTokenPayload };
}

// ── Managed context ──────────────────────────────────────────────────

export interface DashboardApprovalContext {
	endpoint: string;
	allowInsecureLoopback: boolean;
	apiKey: string;
	tenantId: string;
	iid: string;
	/** From the verified entitlement; empty means no token can be accepted yet. */
	publicKeys: ApprovalPublicKeyEntry[];
}

export type DashboardUnavailableReason =
	| "local_mode"
	| "control_plane_disabled"
	| "not_configured"
	| "insecure_endpoint"
	| "managed_state_unavailable"
	| "not_enrolled"
	| "sync_disabled"
	| "no_signed_entitlement"
	| "missing_installation_id";

export type DashboardContextResult =
	| { available: true; context: DashboardApprovalContext }
	| { available: false; reason: DashboardUnavailableReason };

export interface DashboardApprovalOptions {
	/** Injected for tests; defaults to the global `fetch`. */
	fetch?: typeof fetch;
	now?: () => number;
	requestTimeoutMs?: number;
	totalBudgetMs?: number;
	/** Pending-request state file; defaults to `~/.singularity-aidr/dashboard-approval-requests.json`. */
	statePath?: string;
	managedStatePath?: string;
	/** Directory holding the installation id; defaults to `~/.singularity-aidr`. */
	aidrDir?: string;
	/** Where the single-use nonce ledger lives (the operator-approval ledger). */
	ledger?: OperatorApprovalStoreOptions;
	logger?: Logger;
}

/** The control-plane endpoint dashboard approvals may use, or why there is none. */
function controlPlaneTarget(
	config: Config,
): { endpoint: string; allowInsecureLoopback: boolean } | DashboardUnavailableReason {
	if (config.mode !== "managed") return "local_mode";
	const controlPlane = config.control_plane;
	if (!controlPlane?.enabled) return "control_plane_disabled";
	const endpoint = (controlPlane.endpoint ?? "").trim();
	if (!endpoint) return "not_configured";
	const allowInsecureLoopback = controlPlane.allow_insecure_loopback === true;
	try {
		assertSecureControlPlaneEndpoint(endpoint, allowInsecureLoopback);
	} catch {
		return "insecure_endpoint";
	}
	return { endpoint, allowInsecureLoopback };
}

/**
 * Whether dashboard approvals can run for this configuration, and with what.
 * Requires managed mode, an enabled and secure control-plane endpoint, an issued
 * API key, and an ACTIVE ed25519-verified v2 entitlement (the tenant id and the
 * approval keys are read from it and from nowhere else).
 */
export async function resolveDashboardApprovalContext(
	config: Config,
	options: DashboardApprovalOptions = {},
): Promise<DashboardContextResult> {
	const unavailable = (reason: DashboardUnavailableReason): DashboardContextResult => ({
		available: false,
		reason,
	});
	const target = controlPlaneTarget(config);
	if (typeof target === "string") return unavailable(target);

	const logger = options.logger ?? nullLogger;
	const configuredKey = (config.auth?.api_key ?? "").trim();
	let state: Awaited<ReturnType<typeof loadManagedState>>;
	try {
		state = await loadManagedState(options.managedStatePath ?? managedStatePath(), {
			authToken: configuredKey || undefined,
			publicKeysPem: config.licensing?.public_keys_pem ?? [],
			onSecurityEvent: (event) =>
				logger.warn("Managed state verification failure", { code: event.code }),
		});
	} catch {
		return unavailable("managed_state_unavailable");
	}
	const apiKey = configuredKey || (typeof state.api_key === "string" ? state.api_key.trim() : "");
	if (!apiKey) return unavailable("not_enrolled");
	if (isSyncDisabled(state)) return unavailable("sync_disabled");

	const entitlement = state.entitlement;
	if (
		state.entitlement_alg !== "ed25519" ||
		entitlement?.schema_version !== 2 ||
		!isEntitlementActive(state, new Date(options.now ? options.now() : Date.now()))
	) {
		return unavailable("no_signed_entitlement");
	}

	const iid = await getInstallationId(options.aidrDir ?? resolvePath(AIDR_DIR)).catch(
		() => undefined,
	);
	if (!iid) return unavailable("missing_installation_id");

	return {
		available: true,
		context: {
			...target,
			apiKey,
			tenantId: entitlement.tenant_id,
			iid,
			publicKeys: [...(entitlement.approval_public_keys ?? [])],
		},
	};
}

// ── Control-plane client ─────────────────────────────────────────────

type HttpResult =
	| { ok: true; status: number; body: Record<string, unknown> }
	| { ok: false; status?: number; error: string };

interface RequestBudget {
	deadline: number;
	perRequestMs: number;
	now: () => number;
}

/** A JSON object body; `{}` for an empty or non-object body, null when unparsable. */
function parseObjectBody(text: string): Record<string, unknown> | null {
	if (!text.trim()) return {};
	try {
		const parsed: unknown = JSON.parse(text);
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: {};
	} catch {
		return null;
	}
}

async function callControlPlane(
	url: string,
	init: { method: "GET" | "POST"; apiKey: string; body?: unknown },
	budget: RequestBudget,
	fetchImpl: typeof fetch,
): Promise<HttpResult> {
	const remaining = budget.deadline - budget.now();
	if (remaining <= 0) return { ok: false, error: "timeout" };
	const timeoutMs = Math.max(1, Math.min(budget.perRequestMs, remaining));
	try {
		const response = await fetchImpl(url, {
			method: init.method,
			// The API key must never follow a redirect to another origin.
			redirect: "error",
			signal: AbortSignal.timeout(timeoutMs),
			headers: {
				Accept: "application/json",
				Authorization: `Bearer ${init.apiKey}`,
				"User-Agent": "aidr",
				...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
			},
			...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
		});
		const text = await response.text();
		if (text.length > MAX_RESPONSE_BYTES) {
			return { ok: false, status: response.status, error: "response_too_large" };
		}
		const body = parseObjectBody(text);
		if (!body) return { ok: false, status: response.status, error: "invalid_response" };
		if (!response.ok) {
			const code = typeof body.error === "string" && KEY_ID.test(body.error) ? body.error : "";
			return { ok: false, status: response.status, error: code || `http_${response.status}` };
		}
		return { ok: true, status: response.status, body };
	} catch (error) {
		const name = error instanceof Error ? error.name : "";
		return {
			ok: false,
			error: name === "TimeoutError" || name === "AbortError" ? "timeout" : "request_failed",
		};
	}
}

export interface ApprovalRequestBody {
	iid: string;
	agent_runtime: string;
	action_id: string;
	artifact_digest: string;
	tool: string;
	threat_ids: string[];
	summary: string;
	expires_at: string;
}

type SubmitResult = { ok: true; requestId: string } | { ok: false; error: string };

/** `POST {base}/v1/approval-requests`. Idempotent server side on (tenant, iid, action_id). */
async function submitApprovalRequest(
	context: Pick<DashboardApprovalContext, "endpoint" | "apiKey">,
	body: ApprovalRequestBody,
	budget: RequestBudget,
	fetchImpl: typeof fetch,
): Promise<SubmitResult> {
	const result = await callControlPlane(
		controlPlaneUrl(context.endpoint, "approval-requests"),
		{ method: "POST", apiKey: context.apiKey, body },
		budget,
		fetchImpl,
	);
	if (!result.ok) return { ok: false, error: result.error };
	const requestId = result.body.request_id;
	if (typeof requestId !== "string" || !REQUEST_ID.test(requestId)) {
		return { ok: false, error: "invalid_response" };
	}
	return { ok: true, requestId: requestId.toLowerCase() };
}

export type ApprovalRequestStatus = "pending" | "approved" | "denied" | "expired";

type StatusResult =
	| { ok: true; status: ApprovalRequestStatus; token?: string; keyId?: string }
	| { ok: false; error: string; notFound: boolean };

/** `GET {base}/v1/approval-requests/{request_id}`. */
async function fetchApprovalStatus(
	context: Pick<DashboardApprovalContext, "endpoint" | "apiKey">,
	requestId: string,
	budget: RequestBudget,
	fetchImpl: typeof fetch,
): Promise<StatusResult> {
	if (!REQUEST_ID.test(requestId))
		return { ok: false, error: "invalid_request_id", notFound: true };
	const result = await callControlPlane(
		`${controlPlaneUrl(context.endpoint, "approval-requests")}/${encodeURIComponent(requestId)}`,
		{ method: "GET", apiKey: context.apiKey },
		budget,
		fetchImpl,
	);
	if (!result.ok) return { ok: false, error: result.error, notFound: result.status === 404 };
	const status = result.body.status;
	if (
		status !== "pending" &&
		status !== "approved" &&
		status !== "denied" &&
		status !== "expired"
	) {
		return { ok: false, error: "invalid_response", notFound: false };
	}
	return {
		ok: true,
		status,
		token: typeof result.body.token === "string" ? result.body.token : undefined,
		keyId: typeof result.body.key_id === "string" ? result.body.key_id : undefined,
	};
}

// ── Pending-request state (shared across connector processes) ────────

const RequestRecordSchema = z.object({
	tenant_id: z.string().min(1).max(200),
	iid: z.string().min(1).max(200),
	action_id: z.string().regex(ACTION_ID),
	request_id: z.string().regex(REQUEST_ID),
	artifact_digest: z.string().regex(ARTIFACT_DIGEST),
	tool: z.string().max(MAX_TOOL),
	created_at: z.string().max(64),
	expires_at: z.string().max(64),
});

type RequestRecord = z.infer<typeof RequestRecordSchema>;

export function dashboardApprovalStatePath(options: DashboardApprovalOptions = {}): string {
	return options.statePath ?? join(resolvePath(AIDR_DIR), STATE_FILE);
}

/**
 * Read the remembered requests. This file only says WHICH request to poll; it
 * grants nothing (a token must still verify against the exact binding), so an
 * unreadable or edited file just means a new request is submitted.
 */
async function readRequests(path: string): Promise<RequestRecord[]> {
	try {
		const info = await lstat(path);
		if (info.isSymbolicLink() || !info.isFile() || info.size > MAX_STATE_BYTES) return [];
		const raw: unknown = JSON.parse(await getFileContent(path));
		const list = (raw as { requests?: unknown })?.requests;
		if (!Array.isArray(list)) return [];
		const out: RequestRecord[] = [];
		for (const entry of list) {
			const parsed = RequestRecordSchema.safeParse(entry);
			if (parsed.success) out.push(parsed.data);
		}
		return out;
	} catch {
		return [];
	}
}

async function writeRequests(
	path: string,
	records: RequestRecord[],
	now: number,
	logger: Logger,
): Promise<void> {
	const alive = records
		.filter((r) => (isoMs(r.expires_at) ?? 0) > now)
		.sort((a, b) => (isoMs(b.created_at) ?? 0) - (isoMs(a.created_at) ?? 0))
		.slice(0, MAX_RECORDS);
	try {
		await atomicWriteJson(path, { version: 1, requests: alive }, { mode: 0o600 });
	} catch (error) {
		logger.warn("Dashboard approval request state could not be written", {
			error: error instanceof Error ? error.name : typeof error,
		});
	}
}

function sameCall(record: RequestRecord, binding: DashboardApprovalBinding): boolean {
	return (
		record.tenant_id === binding.tenantId &&
		record.iid === binding.iid &&
		record.action_id === binding.actionId
	);
}

// ── Orchestration ────────────────────────────────────────────────────

export type DashboardApprovalStatus =
	/** A valid token was verified and its nonce spent: release this one call. */
	| "released"
	/** A new request was submitted now. */
	| "requested"
	/** A request exists and has not been decided (or could not be polled). */
	| "pending"
	| "denied"
	| "expired"
	/** The dashboard approved, but the token did not verify or was already spent. */
	| "rejected"
	/** The request could not be submitted. */
	| "request_failed"
	/** Managed dashboard approvals are not usable for this installation. */
	| "unavailable";

export interface DashboardApprovalOutcome {
	status: DashboardApprovalStatus;
	requestId?: string;
	/** Machine-readable cause for a non-release (never secret material). */
	reason?: string;
	approverId?: string;
	/** Set by the guard when `operator_approvals.dashboard_only` is in force. */
	dashboardOnly?: boolean;
}

export interface DashboardApprovalInput {
	actionId: string;
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: readonly Artifact[];
	sessionId: string;
	verdict: Pick<Verdict, "matchedThreatId">;
	connector?: string;
}

function requestSummary(toolName: string, toolInput: Record<string, unknown>): string {
	const redacted = redactTelemetryString(
		toolInputSummaryText(toolName, toolInput).slice(0, 8 * 1024),
		Number.MAX_SAFE_INTEGER,
	);
	return boundTerminalText(redacted, MAX_SUMMARY).text;
}

function threatIds(verdict: Pick<Verdict, "matchedThreatId">): string[] {
	const id = verdict.matchedThreatId;
	return id && KEY_ID.test(id) ? [id].slice(0, MAX_THREAT_IDS) : [];
}

/**
 * Run the dashboard approval step for one `ask`.
 *
 * Returns null outside managed mode (local mode is unchanged). Otherwise it
 * either releases the call (`released`: a verified token whose nonce was spent
 * here, exactly once) or says why the call stays blocked. Never throws.
 */
export async function processDashboardApproval(
	input: DashboardApprovalInput,
	config: Config,
	options: DashboardApprovalOptions = {},
): Promise<DashboardApprovalOutcome | null> {
	if (config.mode !== "managed") return null;
	const logger = options.logger ?? nullLogger;
	try {
		return await runDashboardApproval(input, config, options, logger);
	} catch (error) {
		logger.warn("Dashboard approval step failed; the ask stays blocked", {
			error: error instanceof Error ? error.name : typeof error,
		});
		return { status: "unavailable", reason: "internal_error" };
	}
}

type AuditExtra = { requestId?: string; reason?: string; approverId?: string };

/** Everything one dashboard approval step needs, resolved once. */
interface ApprovalRun {
	input: DashboardApprovalInput;
	context: DashboardApprovalContext;
	binding: DashboardApprovalBinding;
	budget: RequestBudget;
	fetchImpl: typeof fetch;
	options: DashboardApprovalOptions;
	logger: Logger;
	now: () => number;
	audit: (event: string, extra: AuditExtra) => Promise<void>;
	/** Drop a remembered request so the next identical call starts a new one. */
	forget: (requestId: string) => Promise<void>;
	records: RequestRecord[];
	statePath: string;
}

async function runDashboardApproval(
	input: DashboardApprovalInput,
	config: Config,
	options: DashboardApprovalOptions,
	logger: Logger,
): Promise<DashboardApprovalOutcome> {
	const now = options.now ?? Date.now;
	const budget: RequestBudget = {
		deadline: now() + (options.totalBudgetMs ?? DASHBOARD_APPROVAL_TOTAL_BUDGET_MS),
		perRequestMs: options.requestTimeoutMs ?? DASHBOARD_APPROVAL_REQUEST_TIMEOUT_MS,
		now,
	};
	const resolved = await resolveDashboardApprovalContext(config, options);
	if (!resolved.available) return { status: "unavailable", reason: resolved.reason };
	if (!ACTION_ID.test(input.actionId)) {
		return { status: "unavailable", reason: "invalid_action_id" };
	}
	const context = resolved.context;
	const statePath = dashboardApprovalStatePath(options);
	const run: ApprovalRun = {
		input,
		context,
		binding: {
			tenantId: context.tenantId,
			iid: context.iid,
			actionId: input.actionId,
			artifactDigest: dashboardArtifactDigest(input.artifacts),
			tool: dashboardToolName(input.toolName),
		},
		budget,
		fetchImpl: options.fetch ?? globalThis.fetch,
		options,
		logger,
		now,
		audit: (event, extra) =>
			config.logging
				? logDashboardApprovalEvent(config.logging, {
						event,
						sessionId: input.sessionId,
						toolName: input.toolName,
						actionId: input.actionId,
						...extra,
					})
				: Promise.resolve(),
		forget: async (requestId) => {
			run.records = run.records.filter((r) => r.request_id !== requestId);
			await writeRequests(statePath, run.records, now(), logger);
		},
		records: await readRequests(statePath),
		statePath,
	};

	const existing = run.records.find(
		(r) =>
			sameCall(r, run.binding) &&
			r.artifact_digest === run.binding.artifactDigest &&
			r.tool === run.binding.tool &&
			(isoMs(r.expires_at) ?? 0) > now(),
	);
	if (existing) {
		const outcome = await pollExistingRequest(run, existing.request_id);
		if (outcome) return outcome;
	}
	return submitNewRequest(run);
}

/**
 * Poll a remembered request. Returns the outcome, or null when the control plane
 * no longer knows the request (a new one should be submitted).
 */
async function pollExistingRequest(
	run: ApprovalRun,
	requestId: string,
): Promise<DashboardApprovalOutcome | null> {
	const polled = await fetchApprovalStatus(run.context, requestId, run.budget, run.fetchImpl);
	if (!polled.ok) {
		if (polled.notFound) {
			await run.forget(requestId);
			return null;
		}
		run.logger.warn("Dashboard approval status unavailable; the ask stays blocked", {
			error: polled.error,
		});
		return { status: "pending", requestId, reason: polled.error };
	}
	if (polled.status === "pending") return { status: "pending", requestId };
	if (polled.status === "denied" || polled.status === "expired") {
		await run.forget(requestId);
		await run.audit(polled.status, { requestId });
		return { status: polled.status, requestId };
	}
	return consumeApprovedToken(run, polled, requestId);
}

/** Submit an approval request for this exact call (idempotent server side). */
async function submitNewRequest(run: ApprovalRun): Promise<DashboardApprovalOutcome> {
	const { binding, context, input } = run;
	const requestNow = run.now();
	const expiresAt = new Date(requestNow + DASHBOARD_APPROVAL_REQUEST_TTL_MS).toISOString();
	const submitted = await submitApprovalRequest(
		context,
		{
			iid: context.iid,
			agent_runtime: (input.connector ?? "unknown").slice(0, 64),
			action_id: binding.actionId,
			artifact_digest: binding.artifactDigest,
			tool: binding.tool,
			threat_ids: threatIds(input.verdict),
			summary: requestSummary(input.toolName, input.toolInput),
			expires_at: expiresAt,
		},
		run.budget,
		run.fetchImpl,
	);
	if (!submitted.ok) {
		run.logger.warn("Dashboard approval request could not be submitted; the ask stays blocked", {
			error: submitted.error,
		});
		await run.audit("request_failed", { reason: submitted.error });
		return { status: "request_failed", reason: submitted.error };
	}
	run.records = run.records.filter((r) => !sameCall(r, binding));
	run.records.push({
		tenant_id: binding.tenantId,
		iid: binding.iid,
		action_id: binding.actionId,
		request_id: submitted.requestId,
		artifact_digest: binding.artifactDigest,
		tool: binding.tool,
		created_at: new Date(requestNow).toISOString(),
		expires_at: expiresAt,
	});
	await writeRequests(run.statePath, run.records, run.now(), run.logger);
	await run.audit("requested", { requestId: submitted.requestId });
	return { status: "requested", requestId: submitted.requestId };
}

/** Rejections after which polling the same request again cannot succeed. */
const TERMINAL_REJECTIONS = new Set<string>([
	"replayed",
	"expired",
	"not_approved",
	"action_mismatch",
	"digest_mismatch",
	"tool_mismatch",
	"tenant_mismatch",
	"iid_mismatch",
]);

/**
 * Verify an `approved` request's token and spend its nonce. The nonce is spent in
 * the operator-approval consumption ledger, so exactly one call is released even
 * when several connector processes see the same approved request.
 */
async function consumeApprovedToken(
	run: ApprovalRun,
	polled: { token?: string; keyId?: string },
	requestId: string,
): Promise<DashboardApprovalOutcome> {
	const rejected = async (reason: string): Promise<DashboardApprovalOutcome> => {
		run.logger.warn("Dashboard approval token rejected; the ask stays blocked", { reason });
		if (TERMINAL_REJECTIONS.has(reason)) await run.forget(requestId);
		await run.audit("rejected", { requestId, reason });
		return { status: "rejected", requestId, reason };
	};
	if (!polled.token || !polled.keyId) return rejected("missing_token");
	const verified = verifyDashboardApprovalToken({
		token: polled.token,
		keyId: polled.keyId,
		publicKeys: run.context.publicKeys,
		expected: run.binding,
		now: run.now(),
	});
	if (!verified.ok) return rejected(verified.reason);
	const payload = verified.payload;
	const spent = await spendExternalApprovalToken(
		NONCE_LEDGER_DOMAIN,
		`${payload.tenant_id}\n${payload.nonce}`,
		Date.parse(payload.expires_at) + NONCE_LEDGER_MARGIN_MS,
		{ logger: run.logger, ...run.options.ledger },
	);
	if (spent === "already_used") return rejected("replayed");
	if (spent !== "spent") return rejected("ledger_unavailable");
	await run.forget(requestId);
	const approverId = redactTelemetryString(payload.approver_id, 128);
	await run.audit("consumed", { requestId, approverId });
	return { status: "released", requestId, approverId };
}
