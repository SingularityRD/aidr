/**
 * First-run privacy notice (KVKK aydınlatma) for the developer.
 *
 * Every connector shows it once per connector at session start, also on an
 * MDM / silent install where nobody ran the welcome flow, and again whenever
 * what is recorded or sent changes (mode, console, redaction, log settings,
 * the organisation's privacy notice link). `aidr privacy notice` prints it at
 * any time. The notice says what is guarded, what is NOT guarded, what is
 * recorded locally and what leaves the computer, computed from the effective
 * configuration rather than written as a generic promise.
 *
 * Display only: nothing here changes enforcement, and a failure to record that
 * the notice was shown just means it is shown again next time.
 */

import { createHash } from "node:crypto";
import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { AIDR_DIR, resolvePath } from "./config.js";
import { safeDisplayUrl } from "./display-settings.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import { type Locale, t } from "./i18n/index.js";
import type { Config } from "./types.js";

/** Bump when the notice text changes in substance, so everyone sees it again. */
const PRIVACY_NOTICE_REVISION = 1;
const STATE_FILE = "privacy-notice-state.json";
const MAX_STATE_BYTES = 64 * 1024;
const CONNECTOR = /^[a-z][a-z0-9-]{0,31}$/;

/** The host of the control-plane endpoint, or a placeholder when none is set. */
function consoleHost(config: Pick<Config, "control_plane">): string {
	try {
		return new URL(config.control_plane?.endpoint ?? "").host || t("common.unknown");
	} catch {
		return t("common.unknown");
	}
}

type NoticeConfig = Pick<
	Config,
	"mode" | "control_plane" | "logging" | "version_check" | "organization"
>;

/** The facts the notice states; a change to any of them shows the notice again. */
export function privacyNoticeFacts(config: NoticeConfig): Record<string, unknown> {
	const managed = config.mode === "managed";
	return {
		revision: PRIVACY_NOTICE_REVISION,
		mode: config.mode,
		log_enabled: config.logging?.enabled !== false,
		log_clean: config.logging?.log_clean === true,
		log_path: config.logging?.path ?? null,
		version_check: config.version_check?.enabled === true,
		console_host: managed ? consoleHost(config) : null,
		send_audit_logs: managed ? config.control_plane?.send_audit_logs !== false : null,
		send_clean_verdicts: managed ? config.control_plane?.send_clean_verdicts === true : null,
		redact_mode: managed ? (config.control_plane?.redact_mode ?? "hash") : null,
		privacy_notice_url: safeDisplayUrl(config.organization?.privacy_notice_url),
		support_contact_url: safeDisplayUrl(config.organization?.support_contact_url),
	};
}

export function privacyNoticeDigest(config: NoticeConfig): string {
	return createHash("sha256")
		.update(JSON.stringify(privacyNoticeFacts(config)))
		.digest("hex");
}

const REDACTION_KEYS = {
	hash: "notice.redaction.hash",
	full: "notice.redaction.full",
	none: "notice.redaction.none",
} as const;

export interface PrivacyNoticeOptions {
	/** Labels of AI tools found without AIDR protection (unprotected-agents.ts). */
	unprotectedTools?: readonly string[];
	locale?: Locale;
}

/** The notice in the display locale, one line per fact. */
export function formatPrivacyNotice(
	config: NoticeConfig,
	options: PrivacyNoticeOptions = {},
): string {
	const locale = options.locale;
	const tr = (key: Parameters<typeof t>[0], params?: Parameters<typeof t>[1]) =>
		t(key, params, locale);
	const lines = [tr("notice.title"), tr("notice.guards"), tr("notice.notGuarded")];
	if (options.unprotectedTools && options.unprotectedTools.length > 0) {
		lines.push(tr("notice.unprotected", { tools: options.unprotectedTools.join(", ") }));
	}
	const logPath = config.logging?.path ?? "~/.singularity-aidr/audit.jsonl";
	if (config.logging?.enabled === false) lines.push(tr("notice.localLogOff"));
	else if (config.logging?.log_clean) lines.push(tr("notice.localLogClean", { path: logPath }));
	else lines.push(tr("notice.localLog", { path: logPath }));

	if (config.mode === "managed") {
		const host = consoleHost(config);
		if (config.control_plane?.send_audit_logs === false) {
			lines.push(tr("notice.sent.managedNoAudit", { host }));
		} else {
			const redact = config.control_plane?.redact_mode ?? "hash";
			lines.push(
				tr("notice.sent.managed", {
					host,
					clean: config.control_plane?.send_clean_verdicts ? tr("notice.sent.managedClean") : "",
					redaction: tr(REDACTION_KEYS[redact]),
				}),
			);
		}
	} else {
		lines.push(
			tr("notice.sent.local", {
				versionCheck: config.version_check?.enabled
					? tr("notice.sent.versionCheck")
					: tr("notice.sent.noVersionCheck"),
			}),
		);
	}
	const privacyUrl = safeDisplayUrl(config.organization?.privacy_notice_url);
	lines.push(privacyUrl ? tr("notice.privacyUrl", { url: privacyUrl }) : tr("notice.privacyAsk"));
	const supportUrl = safeDisplayUrl(config.organization?.support_contact_url);
	if (supportUrl) lines.push(tr("notice.support", { url: supportUrl }));
	lines.push(tr("notice.again"));
	return lines.join("\n");
}

interface NoticeState {
	version: 1;
	shown: Record<string, { digest: string; shown_at: string }>;
}

function noticeStatePath(aidrDir?: string): string {
	return join(aidrDir ?? resolvePath(AIDR_DIR), STATE_FILE);
}

async function readNoticeState(path: string): Promise<NoticeState> {
	try {
		const info = await lstat(path);
		if (info.isSymbolicLink() || !info.isFile() || info.size > MAX_STATE_BYTES) {
			return { version: 1, shown: {} };
		}
		const raw = JSON.parse(await getFileContent(path)) as { shown?: unknown };
		const shown: NoticeState["shown"] = {};
		if (raw?.shown && typeof raw.shown === "object" && !Array.isArray(raw.shown)) {
			for (const [connector, entry] of Object.entries(raw.shown as Record<string, unknown>)) {
				const record = entry as { digest?: unknown; shown_at?: unknown } | null;
				if (
					CONNECTOR.test(connector) &&
					typeof record?.digest === "string" &&
					typeof record.shown_at === "string"
				) {
					shown[connector] = { digest: record.digest, shown_at: record.shown_at };
				}
			}
		}
		return { version: 1, shown };
	} catch {
		return { version: 1, shown: {} };
	}
}

export interface FirstRunNoticeOptions extends PrivacyNoticeOptions {
	/** Directory holding the shown-state file; defaults to `~/.singularity-aidr`. */
	aidrDir?: string;
	now?: () => Date;
}

/**
 * The notice when this connector has not shown the current one yet, else null.
 * Records that it was shown. Never throws.
 */
export async function takeFirstRunPrivacyNotice(
	config: NoticeConfig,
	connector: string,
	options: FirstRunNoticeOptions = {},
): Promise<string | null> {
	try {
		const key = CONNECTOR.test(connector) ? connector : "unknown";
		const path = noticeStatePath(options.aidrDir);
		const digest = privacyNoticeDigest(config);
		const state = await readNoticeState(path);
		if (state.shown[key]?.digest === digest) return null;
		state.shown[key] = { digest, shown_at: (options.now?.() ?? new Date()).toISOString() };
		await atomicWriteJson(path, state, { mode: 0o600 }).catch(() => undefined);
		return formatPrivacyNotice(config, options);
	} catch {
		return null;
	}
}
