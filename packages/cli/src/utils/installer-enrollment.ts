/**
 * The company connection the Windows installer's wizard collected (control-plane
 * address and, optionally, a one-time enrollment code).
 *
 * The MSI's custom action (deploy/installers/windows/ca/EnrollmentActions.cs)
 * writes it, as the installing user, to `~/.singularity-aidr/installer-enrollment.json`
 * with an ACL that only that user can open; `aidr setup` reads it, applies it
 * after operator confirmation and deletes it. The enrollment code is never on a
 * command line or in the msiexec log.
 *
 * The format rules below are the installer's too: installers.test.mjs fails
 * when the C# copy differs.
 */
import { lstatSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";

const INSTALLER_ENROLLMENT_URL_PATTERN =
	/^https:\/\/[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?(?:\/[A-Za-z0-9._~%/-]*)?$/;
const INSTALLER_ENROLLMENT_CODE_PATTERN = /^aidr_enroll_[A-Za-z0-9_-]{43}$/;
const MAX_URL_LENGTH = 512;
const MAX_FILE_BYTES = 4096;
const FORMAT = "aidr-installer-enrollment/1";
/** An enrollment code is short-lived; an old handoff is discarded, never applied. */
export const INSTALLER_ENROLLMENT_MAX_AGE_MS = 72 * 60 * 60 * 1000;

export function installerEnrollmentPath(home: string): string {
	return join(home, ".singularity-aidr", "installer-enrollment.json");
}

export interface InstallerEnrollment {
	/** Empty: the default (SaaS) control plane. */
	controlPlaneUrl: string;
	/** Empty: no code; the device is approved in the console instead. */
	enrollmentCode: string;
}

export type InstallerEnrollmentRead =
	| { state: "none" }
	| { state: "invalid"; reason: string }
	| { state: "expired" }
	| { state: "ready"; enrollment: InstallerEnrollment };

/** The installer's own check: "" when acceptable, else which field is wrong. */
export function enrollmentProblem(url: string, code: string): "" | "url" | "code" {
	if (url === "" && code === "") return "url";
	if (url !== "" && (url.length > MAX_URL_LENGTH || !INSTALLER_ENROLLMENT_URL_PATTERN.test(url))) {
		return "url";
	}
	if (code !== "" && !INSTALLER_ENROLLMENT_CODE_PATTERN.test(code)) return "code";
	return "";
}

/** The parsed handoff document, or why it cannot be read. */
function readDocument(
	path: string,
): { document: Record<string, unknown> } | InstallerEnrollmentRead {
	try {
		const info = lstatSync(path);
		if (!info.isFile()) return { state: "invalid", reason: "not a regular file" };
		if (info.size > MAX_FILE_BYTES) return { state: "invalid", reason: "too large" };
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: "none" };
		return { state: "invalid", reason: "unreadable" };
	}
	try {
		const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return { document: parsed as Record<string, unknown> };
		}
	} catch {
		// Never echo the content: it may hold the code.
	}
	return { state: "invalid", reason: "not valid JSON" };
}

const text = (value: unknown): string => (typeof value === "string" ? value : "");

export function readInstallerEnrollment(home: string, now = Date.now()): InstallerEnrollmentRead {
	const read = readDocument(installerEnrollmentPath(home));
	if (!("document" in read)) return read;
	const { document } = read;
	if (document.format !== FORMAT) return { state: "invalid", reason: "unknown format" };
	const url = text(document.control_plane_url);
	const code = text(document.enrollment_code);
	const problem = enrollmentProblem(url, code);
	if (problem === "url") return { state: "invalid", reason: "the company address is not https" };
	if (problem === "code") return { state: "invalid", reason: "the enrollment code is malformed" };
	const created = Date.parse(text(document.created_at));
	if (!Number.isFinite(created) || created > now + 5 * 60 * 1000) {
		return { state: "invalid", reason: "no valid creation time" };
	}
	if (now - created > INSTALLER_ENROLLMENT_MAX_AGE_MS) return { state: "expired" };
	return { state: "ready", enrollment: { controlPlaneUrl: url, enrollmentCode: code } };
}

/** Delete the handoff file; a missing file is fine. */
export function discardInstallerEnrollment(home: string): void {
	try {
		unlinkSync(installerEnrollmentPath(home));
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
}
