/**
 * AI acceptable-use notice in the page (managed policy key `acceptableUse`).
 *
 * On the first visit to a protected AI site after a notice version is published, the
 * notice is shown in the guard's closed-shadow-root dialog (role=alertdialog, focus moved
 * to "I understand", Tab loop, Escape to dismiss, focus restored). Pressing "I understand"
 * asks the background worker to record the acknowledgement; the worker keeps it per
 * browser profile and reports only the notice id and version (counts only). Dismissing or
 * choosing "Remind me later" shows it again on the next page load.
 *
 * The notice never blocks sending: it informs (AI literacy), it is not a control. The
 * administrator's title and text are rendered as plain text, never as markup.
 */
import type { AcceptableUseNotice, GuardMessage, GuardPolicy } from "../types.js";
import type { Strings } from "./strings.js";
import type { GuardUi } from "./ui.js";

const NOTICE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const ACKNOWLEDGE = "aup-acknowledge";
const LATER = "aup-later";

type AcceptableUseOutcome =
	| "none"
	| "acknowledged"
	| "recorded"
	| "dismissed"
	| "failed"
	| "busy";

export interface AcceptableUseDeps {
	readonly ui: GuardUi;
	send(message: GuardMessage): Promise<unknown>;
	strings(): Strings;
}

export interface AcceptableUseController {
	/** Asks the worker for the notice in force and shows it unless this version was acknowledged. */
	check(): Promise<AcceptableUseOutcome>;
	/**
	 * Called for every applied policy: checks on the first one (and after a failed check),
	 * then again only when a policy change publishes a different notice id or version.
	 */
	policyChanged(policy: GuardPolicy): void;
}

/** A notice from a worker reply, or null when the reply is not a well-formed notice. */
export function extractNotice(raw: unknown): AcceptableUseNotice | null {
	if (!raw || typeof raw !== "object") return null;
	const n = raw as Record<string, unknown>;
	if (typeof n.id !== "string" || !NOTICE_ID.test(n.id)) return null;
	if (!Number.isSafeInteger(n.version) || (n.version as number) < 1) return null;
	if (typeof n.title !== "string" || n.title.trim() === "") return null;
	if (typeof n.text !== "string" || n.text.trim() === "") return null;
	const url = typeof n.url === "string" && n.url.startsWith("https://") ? n.url : undefined;
	return {
		id: n.id,
		version: n.version as number,
		title: n.title,
		text: n.text,
		...(url ? { url } : {}),
	};
}

/** Paragraphs of the notice text (blank lines separate them). */
export function noticeParagraphs(text: string): string[] {
	return text
		.split(/\n\s*\n/)
		.map((part) => part.trim())
		.filter((part) => part.length > 0);
}

const noticeKey = (notice: Pick<AcceptableUseNotice, "id" | "version"> | null | undefined) =>
	notice ? `${notice.id}\u0000${notice.version}` : "";

export function createAcceptableUseNotice(deps: AcceptableUseDeps): AcceptableUseController {
	let running: Promise<AcceptableUseOutcome> | null = null;
	let lastKey: string | null = null;

	async function show(notice: AcceptableUseNotice): Promise<AcceptableUseOutcome> {
		const strings = deps.strings();
		const choice = await deps.ui.bubble({
			title: notice.title,
			caption: strings.aupVersion(notice.version),
			lines: noticeParagraphs(notice.text),
			actions: [
				{ id: LATER, label: strings.aupLater },
				{ id: ACKNOWLEDGE, label: strings.aupAcknowledge, primary: true },
			],
			tone: "info",
			initialFocus: ACKNOWLEDGE,
			...(notice.url ? { link: { href: notice.url, label: strings.aupPolicyLink } } : {}),
		});
		if (choice !== ACKNOWLEDGE) return "dismissed";
		let reply: unknown;
		try {
			reply = await deps.send({
				type: "AUP_ACKNOWLEDGE",
				noticeId: notice.id,
				version: notice.version,
			});
		} catch {
			reply = null;
		}
		if ((reply as { ok?: unknown } | null)?.ok !== true) {
			deps.ui.toast(strings.aupRecordFailed, "warn");
			return "failed";
		}
		deps.ui.toast(strings.aupRecorded);
		return "recorded";
	}

	async function run(): Promise<AcceptableUseOutcome> {
		let reply: unknown;
		try {
			reply = await deps.send({ type: "AUP_STATUS" });
		} catch {
			return "failed";
		}
		const status = reply as { ok?: unknown; notice?: unknown; acknowledged?: unknown } | null;
		if (status?.ok !== true || typeof status.acknowledged !== "boolean") return "failed";
		const notice = extractNotice(status.notice);
		lastKey = noticeKey(notice);
		if (!notice) return "none";
		if (status.acknowledged) return "acknowledged";
		// Never interrupt a send decision the user is making.
		if (deps.ui.bubbleOpen) return "busy";
		return show(notice);
	}

	function check(): Promise<AcceptableUseOutcome> {
		if (running) return running;
		running = run().finally(() => {
			running = null;
		});
		return running;
	}

	return {
		check,
		policyChanged(policy) {
			if (lastKey !== null && noticeKey(policy.acceptableUse) === lastKey) return;
			void check();
		},
	};
}
