import { lstatSync, readFileSync, unlinkSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import {
	assertSecureControlPlaneEndpoint,
	ControlPlaneClient,
	type Config as CoreConfig,
	enrollManagedInstallation,
	enrollmentPending,
	getEffectiveManagedApiKey,
	getInstallationId,
	loadConfig,
	loadManagedState,
	nullLogger,
} from "@singularityrd/aidr-core";
import type { EnrollStartInput, EnrollView, PendingEnrollmentView } from "./types.js";

/**
 * Company connection for the Setup Assistant: the device-code enrollment that
 * session start already implements (device-start, device-poll, then the
 * one-time `enroll` exchange through {@link enrollManagedInstallation}, which
 * keeps the shared `managed.json.enrollment-pending` journal), driven from the
 * wizard so the person sees the code and the approval page.
 *
 * Nothing is written until the control plane has issued the credential: the
 * credential goes to `managed.json` (core), then `config.json` gets
 * `mode: "managed"` and the company address, the two keys a managed install
 * needs. A failed or abandoned attempt leaves the configuration as it was, and
 * local protection is never made to depend on it.
 */

/**
 * Left by the Windows installer's wizard (deploy/installers/windows) in the
 * user's profile: `%USERPROFILE%\.singularity-aidr\pending-enrollment.json`
 * (`~/.singularity-aidr/pending-enrollment.json` on Linux), readable by that
 * user only. Contract (schema_version 1):
 *
 *     { "schema_version": 1,
 *       "control_plane_url": "https://aidr.example.com",
 *       "enrollment_token": "<optional one-time token from the dashboard>" }
 *
 * The assistant pre-fills the company address from it; with a token it
 * exchanges the token directly (no device code). The file is deleted once it
 * has been used, whatever the outcome (a token is single-use).
 */
export const PENDING_ENROLLMENT_FILE = "pending-enrollment.json";
const MAX_PENDING_BYTES = 16 * 1024;

interface PendingEnrollment extends PendingEnrollmentView {
	token?: string;
	path: string;
}

function pendingEnrollmentPath(home: string): string {
	return join(home, ".singularity-aidr", PENDING_ENROLLMENT_FILE);
}

/** Trim trailing slashes; refuse credentials, query and fragment in the address. */
export function normalizeEndpoint(value: string, allowInsecureLoopback = false): string | null {
	const trimmed = value.trim().replace(/\/+$/u, "");
	if (!trimmed || trimmed.length > 2048) return null;
	try {
		const parsed = new URL(trimmed);
		if (parsed.username || parsed.password || parsed.search || parsed.hash) return null;
		assertSecureControlPlaneEndpoint(trimmed, allowInsecureLoopback);
		return trimmed;
	} catch {
		return null;
	}
}

/**
 * Read the installer's pending file. It is used only when it is a regular file
 * (not a link) owned by this user and, on Linux, closed to other users; a file
 * that fails a check is reported as ignored, never used.
 */
export function readPendingEnrollment(
	home: string,
	platform: NodeJS.Platform = process.platform,
	allowInsecureLoopback = false,
): { pending: PendingEnrollment | null; ignored: boolean } {
	const path = pendingEnrollmentPath(home);
	let info: ReturnType<typeof lstatSync>;
	try {
		info = lstatSync(path);
	} catch {
		return { pending: null, ignored: false };
	}
	const ignored = { pending: null, ignored: true };
	if (!info.isFile() || info.size > MAX_PENDING_BYTES) return ignored;
	if (platform !== "win32") {
		const uid = process.getuid?.();
		if ((uid !== undefined && info.uid !== uid) || (info.mode & 0o077) !== 0) return ignored;
	}
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
		if (parsed?.schema_version !== 1 || typeof parsed.control_plane_url !== "string")
			return ignored;
		const endpoint = normalizeEndpoint(parsed.control_plane_url, allowInsecureLoopback);
		if (!endpoint) return ignored;
		const token =
			typeof parsed.enrollment_token === "string" &&
			/^[\x21-\x7e]{8,512}$/u.test(parsed.enrollment_token.trim())
				? parsed.enrollment_token.trim()
				: undefined;
		if (parsed.enrollment_token !== undefined && token === undefined) return ignored;
		return { pending: { endpoint, hasToken: token !== undefined, token, path }, ignored: false };
	} catch {
		return ignored;
	}
}

type DeviceClient = Pick<ControlPlaneClient, "deviceStart" | "devicePoll">;

export interface EnrollmentDeps {
	home: string;
	now?: () => number;
	/** Runtime configuration (tests); default: the hooks' own loader. */
	loadConfig?: () => Promise<CoreConfig>;
	/** Control-plane client for device-start / device-poll (tests). */
	client?: (config: CoreConfig["control_plane"]) => DeviceClient;
	/** One-time exchange (tests); default: core's journaled issuance. */
	enroll?: typeof enrollManagedInstallation;
	/** Record managed mode and the address in config.json once enrolled. */
	persist: (endpoint: string) => Promise<void>;
	installationId?: () => Promise<string | undefined>;
	platform?: NodeJS.Platform;
}

interface DeviceSession {
	endpoint: string;
	deviceCode: string;
	userCode: string;
	verificationUrl: string;
	expiresAt: number;
	interval: number;
	lastPoll: number;
}

/** A hostname the control plane accepts; anything odd is not sent at all. */
function safeHostname(): string | undefined {
	try {
		const name = hostname().trim();
		return /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/u.test(name) ? name : undefined;
	} catch {
		return undefined;
	}
}

function errorView(endpoint: string, code: string | undefined, status?: number): EnrollView {
	const reason = code ?? "unknown";
	if (reason === "request_failed")
		return { phase: "error", endpoint, message: "company.unreachable", code: reason };
	if (status === 404 || reason === "http_error") {
		return { phase: "error", endpoint, message: "company.notAidr", code: reason };
	}
	if (reason === "tenant_not_admitted" || reason === "pilot_not_approved") {
		return { phase: "error", endpoint, message: "company.noSeat", code: reason };
	}
	if (reason === "access_denied" || reason === "device_code_invalid") {
		return { phase: "denied", endpoint, message: "company.denied", code: reason };
	}
	if (reason === "already_exchanged") {
		return { phase: "repair", endpoint, message: "company.repair", code: reason };
	}
	return { phase: "error", endpoint, message: "company.failed", code: reason };
}

export function createEnrollment(deps: EnrollmentDeps) {
	const now = deps.now ?? Date.now;
	const configOf = deps.loadConfig ?? (() => loadConfig());
	const managedPath = join(deps.home, ".singularity-aidr", "managed.json");
	const iid =
		deps.installationId ?? (() => getInstallationId(join(deps.home, ".singularity-aidr")));
	const enroll = deps.enroll ?? enrollManagedInstallation;
	let session: DeviceSession | null = null;
	let view: EnrollView = { phase: "idle" };

	async function settings(): Promise<CoreConfig> {
		return configOf();
	}

	async function managedConfig(endpoint: string): Promise<CoreConfig> {
		const config = await settings();
		return {
			...config,
			mode: "managed",
			control_plane: { ...config.control_plane, enabled: true, endpoint },
		};
	}

	function clientFor(config: CoreConfig): DeviceClient {
		return deps.client
			? deps.client(config.control_plane)
			: new ControlPlaneClient(config.control_plane, "");
	}

	/** The installer's file, read with the configured loopback allowance. */
	async function pending() {
		const config = await settings();
		return readPendingEnrollment(
			deps.home,
			deps.platform,
			config.control_plane.allow_insecure_loopback,
		);
	}

	function consumePending(path: string | undefined): void {
		if (!path) return;
		try {
			unlinkSync(path);
		} catch {
			// Already gone; nothing else reads it.
		}
	}

	/** Exchange a one-time token (device-poll's or the installer's) for the credential. */
	async function exchange(endpoint: string, enrollmentToken: string): Promise<EnrollView> {
		const config = await managedConfig(endpoint);
		const id = await iid();
		if (!id)
			return { phase: "error", endpoint, message: "company.failed", code: "no_installation_id" };
		const outcome = await enroll({
			managedPath,
			enrollmentToken,
			iid: id,
			config,
			logger: nullLogger,
		}).catch(() => ({ outcome: "repair" as const }));
		if (outcome.outcome === "enrolled") {
			try {
				await deps.persist(endpoint);
			} catch {
				// The credential is saved; only the mode switch is missing. Say so.
				return { phase: "error", endpoint, message: "company.failed", code: "config_write_failed" };
			}
			return { phase: "enrolled", endpoint };
		}
		if (outcome.outcome === "retry")
			return { phase: "error", endpoint, message: "company.failed", code: "not_committed" };
		return {
			phase: "repair",
			endpoint,
			message: "company.repair",
			code: "enrollment_repair_required",
		};
	}

	async function start(input: EnrollStartInput): Promise<EnrollView> {
		session = null;
		const config = await settings();
		const endpoint = normalizeEndpoint(
			input.endpoint,
			config.control_plane.allow_insecure_loopback,
		);
		if (!endpoint) {
			view = { phase: "error", message: "company.urlInvalid", code: "invalid_address" };
			return view;
		}
		// An earlier issuance did not settle: only the documented repair clears it.
		if (await enrollmentPending(`${managedPath}.enrollment-pending`)) {
			view = {
				phase: "repair",
				endpoint,
				message: "company.repair",
				code: "enrollment_repair_required",
			};
			return view;
		}
		if (input.useInstallerToken) {
			const found = (await pending()).pending;
			if (!found?.token || found.endpoint !== endpoint) {
				view = { phase: "error", endpoint, message: "company.failed", code: "no_installer_token" };
				return view;
			}
			consumePending(found.path);
			view = await exchange(endpoint, found.token);
			return view;
		}
		const managed = await managedConfig(endpoint);
		let response: Awaited<ReturnType<DeviceClient["deviceStart"]>>;
		try {
			response = await clientFor(managed).deviceStart({
				iid: await iid(),
				os: process.platform,
				hostname: safeHostname(),
			});
		} catch {
			response = { ok: false, error: "request_failed" };
		}
		const body = response.body ?? {};
		const text = (key: string) =>
			typeof body[key] === "string" ? (body[key] as string).trim() : "";
		const deviceCode = text("device_code");
		const userCode = text("user_code");
		const verificationUrl = text("verification_url");
		if (!response.ok || !deviceCode || !userCode || !verificationUrl) {
			view = errorView(
				endpoint,
				response.ok ? "invalid_response" : response.error,
				response.status,
			);
			return view;
		}
		// The page links to it: only an https page (or loopback where allowed).
		if (
			!normalizeEndpoint(
				verificationUrl.split(/[?#]/u)[0],
				managed.control_plane.allow_insecure_loopback,
			)
		) {
			view = {
				phase: "error",
				endpoint,
				message: "company.notAidr",
				code: "insecure_verification_url",
			};
			return view;
		}
		const expires = Date.parse(text("expires_at"));
		const interval = Number(body.interval_seconds);
		session = {
			endpoint,
			deviceCode,
			userCode,
			verificationUrl,
			expiresAt: Number.isFinite(expires) ? expires : now() + 10 * 60_000,
			interval: Number.isFinite(interval) && interval >= 1 ? Math.min(interval, 60) : 5,
			// RFC 8628: wait one interval before the first poll.
			lastPoll: now(),
		};
		view = waitingView(session);
		return view;
	}

	function waitingView(current: DeviceSession): EnrollView {
		return {
			phase: "waiting",
			endpoint: current.endpoint,
			userCode: current.userCode,
			verificationUrl: current.verificationUrl,
			expiresAt: new Date(current.expiresAt).toISOString(),
			interval: current.interval,
		};
	}

	async function poll(): Promise<EnrollView> {
		const current = session;
		if (!current) return view;
		if (now() >= current.expiresAt) {
			session = null;
			view = { phase: "expired", endpoint: current.endpoint, message: "company.expired" };
			return view;
		}
		// The control plane budgets polls per code; never poll faster than it asked.
		if (now() - current.lastPoll < current.interval * 1000) return waitingView(current);
		current.lastPoll = now();
		const managed = await managedConfig(current.endpoint);
		let response: Awaited<ReturnType<DeviceClient["devicePoll"]>>;
		try {
			response = await clientFor(managed).devicePoll({ device_code: current.deviceCode });
		} catch {
			response = { ok: false, error: "request_failed" };
		}
		const body = response.body ?? {};
		const token = typeof body.enrollment_token === "string" ? body.enrollment_token.trim() : "";
		if (response.ok && token) {
			session = null;
			view = await exchange(current.endpoint, token);
			return view;
		}
		const raised = Number(body.interval_seconds);
		if (Number.isFinite(raised) && raised >= 1) current.interval = Math.min(raised, 60);
		if (
			(response.ok && !token) ||
			response.error === "authorization_pending" ||
			response.error === "slow_down" ||
			response.error === "rate_limited" ||
			response.error === "request_failed"
		) {
			if (response.error === "slow_down" && !(raised >= 1)) current.interval += 5;
			return waitingView(current);
		}
		if (response.error === "device_code_expired" || response.error === "expired_token") {
			session = null;
			view = { phase: "expired", endpoint: current.endpoint, message: "company.expired" };
			return view;
		}
		session = null;
		view = errorView(current.endpoint, response.error, response.status);
		return view;
	}

	async function cancel(): Promise<EnrollView> {
		session = null;
		view = { phase: "idle" };
		return view;
	}

	/** The company address in use and whether a credential is already saved. */
	async function current(): Promise<{ endpoint: string; enrolled: boolean } | null> {
		const config = await settings();
		if (config.mode !== "managed" || !config.control_plane.endpoint) return null;
		try {
			const state = await loadManagedState(managedPath, {
				publicKeysPem: config.licensing.public_keys_pem,
			});
			return {
				endpoint: config.control_plane.endpoint,
				enrolled: getEffectiveManagedApiKey(config.auth.api_key, state) !== "",
			};
		} catch {
			return { endpoint: config.control_plane.endpoint, enrolled: false };
		}
	}

	return { start, poll, cancel, pending, current };
}
