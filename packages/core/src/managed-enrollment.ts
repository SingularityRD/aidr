import { randomUUID } from "node:crypto";
import { lstat, open, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { ControlPlaneClient } from "./clients/control-plane.js";
import { getFileContent } from "./file-utils.js";
import {
	applyIngestResult,
	getAuthToken,
	loadManagedState,
	type ManagedState,
	saveEntitlementKeyringFromState,
	saveManagedState,
} from "./managed.js";
import { preparePrivateLocalDirectory, preparePrivateLocalFile } from "./private-local-file.js";
import type { AgentRuntime, Config, Logger } from "./types.js";

// An issuance journal, not a timed lock. A crash/timeout can hide a committed
// hash-only key; expiry and configuration changes must never clear this file.
export async function enrollmentPending(path: string): Promise<boolean> {
	try {
		await lstat(path);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code !== "ENOENT";
	}
}

export async function beginEnrollment(path: string, iid: string): Promise<string | undefined> {
	try {
		preparePrivateLocalDirectory(dirname(path));
		const handle = await open(path, "wx", 0o600);
		const attempt = randomUUID();
		try {
			preparePrivateLocalFile(path);
			await handle.writeFile(
				JSON.stringify({ attempt, iid, started_at: new Date().toISOString() }),
			);
			await handle.sync();
		} finally {
			await handle.close();
		}
		if (process.platform !== "win32") {
			const directory = await open(dirname(path), "r");
			try {
				await directory.sync();
			} finally {
				await directory.close();
			}
		}
		return attempt;
	} catch {
		// Existing, unwritable and unsafe paths all prevent a new issuance.
		return undefined;
	}
}

async function ownsEnrollment(path: string, attempt: string): Promise<boolean> {
	try {
		const info = await lstat(path);
		if (info.isSymbolicLink() || !info.isFile()) return false;
		return JSON.parse(await getFileContent(path)).attempt === attempt;
	} catch {
		return false;
	}
}

export async function clearEnrollment(path: string, attempt: string): Promise<void> {
	if (!(await ownsEnrollment(path, attempt))) throw new Error("enrollment_attempt_changed");
	await unlink(path);
}

type EnrollmentResult =
	| { outcome: "enrolled"; state: ManagedState; apiKey: string }
	| { outcome: "retry" | "repair" };

/** Both startup and tool evaluation must serialize the same one-time issuance. */
export async function enrollManagedInstallation(options: {
	managedPath: string;
	enrollmentToken: string;
	iid: string;
	config: Config;
	logger: Logger;
	agentRuntime?: AgentRuntime;
	agentRuntimeVersion?: string;
}): Promise<EnrollmentResult> {
	const { managedPath, iid, config, logger } = options;
	const pendingPath = `${managedPath}.enrollment-pending`;
	const attempt = await beginEnrollment(pendingPath, iid);
	if (!attempt) return { outcome: "repair" };
	try {
		// A slower caller must not overwrite another caller's durable credential.
		const current = await loadManagedState(managedPath, {
			authToken: getAuthToken(config.auth),
			publicKeysPem: config.licensing.public_keys_pem,
		});
		if (current.api_key?.trim()) {
			await clearEnrollment(pendingPath, attempt);
			return { outcome: "enrolled", state: current, apiKey: current.api_key.trim() };
		}
		const client = new ControlPlaneClient(config.control_plane, options.enrollmentToken, logger);
		const res = await client.enroll({
			iid,
			agent_runtime: options.agentRuntime,
			agent_runtime_version: options.agentRuntimeVersion,
		});
		if (!(await ownsEnrollment(pendingPath, attempt))) return { outcome: "repair" };
		const issued = typeof res.body?.api_key === "string" ? res.body.api_key.trim() : "";
		if (res.ok && issued) {
			const next = applyIngestResult(
				current,
				{ ok: true, status: res.status, body: res.body },
				config.control_plane.grace_period_hours,
				{ authToken: issued, publicKeysPem: config.licensing.public_keys_pem },
			);
			next.api_key = issued;
			next.device_code = undefined;
			next.user_code = undefined;
			next.verification_url = undefined;
			next.device_expires_at = undefined;
			next.device_started_at = undefined;
			await saveManagedState(managedPath, next, undefined, { requirePersistence: true });
			await saveEntitlementKeyringFromState(next);
			await clearEnrollment(pendingPath, attempt);
			return { outcome: "enrolled", state: next, apiKey: issued };
		}
		if (res.enrollment_outcome === "not_committed") {
			await clearEnrollment(pendingPath, attempt);
			return { outcome: "retry" };
		}
	} catch {
		// Leave evidence pending if issuance, storage or cleanup was uncertain.
	}
	return { outcome: "repair" };
}
