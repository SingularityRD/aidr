import { supabase } from "./supabase";
import { errorCode } from "./workspace-settings";

/**
 * Client for the `installer-download` Edge Function (docs/installation/download-portal.md).
 * Every answer is validated; anything unexpected is an error, never a partial list.
 * The function verifies the signed installer catalog before answering; this module
 * only refuses shapes it does not understand.
 */

type InstallerOs = "windows" | "linux";

export interface InstallerFile {
	platform: string;
	os: InstallerOs;
	arch: string;
	file: string;
	size: number;
	sha256: string;
	minimumOs: string;
	format: string;
}

export interface InstallerCatalog {
	version: string;
	publishedAt: string;
	releaseNotesUrl: string | null;
	files: InstallerFile[];
	/** Set only when this control plane offers managed enrollment to the caller. */
	controlPlaneUrl: string | null;
}

export type InstallerResult<T> = { ok: true; value: T } | { ok: false; error: string };

export interface InstallerDownload {
	url: string;
	expiresAt: string;
	file: string;
	sha256: string;
}

const PLATFORM = /^(windows|linux)-(x64|arm64)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const FILE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** An https URL without credentials, or null. */
export function safeHttpsUrl(value: unknown): string | null {
	if (typeof value !== "string" || !value.trim()) return null;
	try {
		const url = new URL(value.trim());
		return url.protocol === "https:" && !url.username && !url.password ? url.toString() : null;
	} catch {
		return null;
	}
}

function readFile(value: unknown): InstallerFile | null {
	if (!isRecord(value) || typeof value.platform !== "string") return null;
	const match = PLATFORM.exec(value.platform);
	if (
		!match ||
		value.os !== match[1] ||
		value.arch !== match[2] ||
		typeof value.file !== "string" ||
		!FILE.test(value.file) ||
		typeof value.size !== "number" ||
		!Number.isSafeInteger(value.size) ||
		value.size < 1 ||
		typeof value.sha256 !== "string" ||
		!SHA256.test(value.sha256) ||
		typeof value.minimum_os !== "string" ||
		typeof value.format !== "string"
	)
		return null;
	return {
		platform: value.platform,
		os: match[1] as InstallerOs,
		arch: match[2] as string,
		file: value.file,
		size: value.size,
		sha256: value.sha256,
		minimumOs: value.minimum_os,
		format: value.format,
	};
}

export function readInstallerCatalog(value: unknown): InstallerCatalog | null {
	if (!isRecord(value) || value.ok !== true || !isRecord(value.catalog)) return null;
	const catalog = value.catalog;
	if (
		typeof catalog.version !== "string" ||
		typeof catalog.published_at !== "string" ||
		!Array.isArray(catalog.files)
	)
		return null;
	const files: InstallerFile[] = [];
	for (const entry of catalog.files) {
		// A platform this dashboard does not know yet is skipped, not trusted.
		if (isRecord(entry) && typeof entry.platform === "string" && !PLATFORM.test(entry.platform))
			continue;
		const file = readFile(entry);
		if (!file) return null;
		files.push(file);
	}
	const enrollment = isRecord(value.managed_enrollment) ? value.managed_enrollment : null;
	const controlPlane =
		enrollment?.available === true ? safeHttpsUrl(enrollment.control_plane_url) : null;
	return {
		version: catalog.version,
		publishedAt: catalog.published_at,
		releaseNotesUrl: safeHttpsUrl(catalog.release_notes_url),
		files,
		controlPlaneUrl: controlPlane ? new URL(controlPlane).origin : null,
	};
}

async function failure(error: unknown, fallback: string): Promise<{ ok: false; error: string }> {
	return { ok: false, error: (await errorCode(error)) ?? fallback };
}

export async function loadInstallerCatalog(
	tenantId: string,
): Promise<InstallerResult<InstallerCatalog>> {
	try {
		const res = await supabase.functions.invoke("installer-download", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": tenantId },
		});
		if (res.error) return failure(res.error, "catalog_unavailable");
		const catalog = readInstallerCatalog(res.data);
		return catalog ? { ok: true, value: catalog } : { ok: false, error: "catalog_unavailable" };
	} catch {
		return { ok: false, error: "catalog_unavailable" };
	}
}

export async function requestInstallerDownload(
	tenantId: string,
	version: string,
	platform: string,
): Promise<InstallerResult<InstallerDownload>> {
	try {
		const res = await supabase.functions.invoke("installer-download", {
			method: "POST",
			body: { tenant_id: tenantId, version, platform },
		});
		if (res.error) return failure(res.error, "download_unavailable");
		const data = res.data as Record<string, unknown> | null;
		const url = safeHttpsUrl(data?.url);
		if (
			!isRecord(data) ||
			data.ok !== true ||
			!url ||
			typeof data.expires_at !== "string" ||
			typeof data.file !== "string" ||
			typeof data.sha256 !== "string" ||
			!SHA256.test(data.sha256)
		)
			return { ok: false, error: "download_unavailable" };
		return {
			ok: true,
			value: { url, expiresAt: data.expires_at, file: data.file, sha256: data.sha256 },
		};
	} catch {
		return { ok: false, error: "download_unavailable" };
	}
}

export type VisitorOs = InstallerOs | "macos" | "unknown";

/** The visitor's OS and CPU family from the browser; arm64 only when the browser says so. */
export function detectVisitorPlatform(
	nav: Pick<Navigator, "userAgent"> & { userAgentData?: { platform?: string } } = navigator,
): { os: VisitorOs; arch: "x64" | "arm64" } {
	const hint = `${nav.userAgentData?.platform ?? ""} ${nav.userAgent ?? ""}`;
	const arch = /\b(aarch64|arm64|armv8)\b/i.test(hint) ? "arm64" : "x64";
	if (/android|iphone|ipad/i.test(hint)) return { os: "unknown", arch };
	if (/windows|win32|win64/i.test(hint)) return { os: "windows", arch };
	if (/mac ?os|macintosh/i.test(hint)) return { os: "macos", arch };
	if (/linux|x11|cros/i.test(hint)) return { os: "linux", arch };
	return { os: "unknown", arch };
}

/** The installer to highlight for the visitor, or null when none matches their OS. */
export function recommendedInstaller(
	files: InstallerFile[],
	visitor: { os: VisitorOs; arch: string },
): InstallerFile | null {
	const sameOs = files.filter((file) => file.os === visitor.os);
	return sameOs.find((file) => file.arch === visitor.arch) ?? sameOs[0] ?? null;
}

/** A command that checks the downloaded file against the published SHA-256. */
export function checksumCommand(file: Pick<InstallerFile, "os" | "file" | "sha256">): string {
	return file.os === "windows"
		? `(Get-FileHash -Algorithm SHA256 ".\\${file.file}").Hash.ToLower() -eq "${file.sha256}"`
		: `echo "${file.sha256}  ${file.file}" | sha256sum --check -`;
}
