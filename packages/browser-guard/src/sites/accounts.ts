/**
 * Personal vs company AI accounts: which account the user is signed in with on a supported
 * AI site, read passively from what the page itself exposes (its URL, its non-HttpOnly
 * cookies and its DOM), and whether that account is one the organisation allows (managed key
 * `workAccounts`, see WorkAccountPolicy in ../types.ts).
 *
 * What each site exposes, what is read and what cannot be detected is documented in
 * docs/work-accounts.md; keep the two in step. None of these signals is a vendor API: they
 * are observed markup and cookies, modelled in the e2e fixtures (e2e/fixtures/gemini-account-*.html,
 * m365-copilot-chat.html; cookies in e2e/scenarios/work-accounts.mjs)
 * and unverified against live tenants (BG-LIVE). When a site stops exposing a signal the result
 * is `unverified`, which `workAccounts.unverified: "enforce"` (the default) treats like a
 * personal account: a markup change can over-warn, never silently let a personal account pass.
 *
 * Privacy: the email local part is discarded as soon as the domain is read; the workspace id
 * and domain stay in the content script, are compared with the policy and are never stored,
 * logged or sent (telemetry carries only the AccountType enum).
 *
 * Pure functions over an injected probe (no extension APIs): unit-tested with jsdom.
 */
import type {
	AccountSiteId,
	AccountType,
	SiteId,
	WorkAccountPolicy,
	WorkAccountSiteRule,
} from "../types.js";
import { M365_COPILOT_HOSTS } from "./frames.js";

/** What the page says about the signed-in account (before the policy is applied). */
type AccountKind = "work" | "personal" | "unknown";

export interface AccountContext {
	readonly kind: AccountKind;
	/** ChatGPT workspace account id / Claude organisation UUID, lowercase; null when not exposed. */
	readonly workspaceId: string | null;
	/** Domain of the signed-in account's email, lowercase; null when not exposed. */
	readonly emailDomain: string | null;
	/** Ids of the signals that contributed (tests and docs; never telemetry). */
	readonly signals: readonly string[];
}

/** The page surface the detectors read. */
export interface AccountProbe {
	readonly url: string;
	/** `document.cookie` of the page (HttpOnly cookies are not visible to a content script). */
	readonly cookie: string;
	readonly root: ParentNode;
}

const UNKNOWN: AccountContext = Object.freeze({
	kind: "unknown",
	workspaceId: null,
	emailDomain: null,
	signals: Object.freeze([]) as readonly string[],
});

/** Workspace / organisation identifier syntax (ids, UUIDs); also the policy's syntax. */
export const WORKSPACE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** Values that name no workspace (a personal account or an unset cookie). */
const NO_WORKSPACE = new Set(["personal", "default", "none", "null", "undefined", "0"]);
/** Consumer Google mail domains: a Google account on them is a personal account. */
const CONSUMER_GOOGLE_DOMAINS: ReadonlySet<string> = new Set(["gmail.com", "googlemail.com"]);
/** Consumer Microsoft account domains. */
const CONSUMER_MICROSOFT_DOMAINS: ReadonlySet<string> = new Set([
	"outlook.com",
	"hotmail.com",
	"live.com",
	"msn.com",
	"passport.com",
]);
const EMAIL_DOMAIN = /[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/;
const MAX_TEXT = 512;

/** The value of cookie `name` in a `document.cookie` string, or null. */
export function cookieValue(cookie: string, name: string): string | null {
	if (typeof cookie !== "string" || cookie.length > 16_384) return null;
	for (const part of cookie.split(";")) {
		const eq = part.indexOf("=");
		if (eq < 0 || part.slice(0, eq).trim() !== name) continue;
		let value = part.slice(eq + 1).trim();
		try {
			value = decodeURIComponent(value);
		} catch {
			// Keep the raw value.
		}
		return value.replace(/^"|"$/g, "");
	}
	return null;
}

/** A workspace id from a cookie value, or null for an absent / personal / malformed one. */
function workspaceIdOf(value: string | null): string | null {
	if (value === null) return null;
	const id = value.trim().toLowerCase();
	if (NO_WORKSPACE.has(id) || !WORKSPACE_ID_PATTERN.test(id)) return null;
	return id;
}

/** The email domain inside `text` (lowercase), or null. The local part is never returned. */
export function emailDomainIn(text: string | null | undefined): string | null {
	if (typeof text !== "string") return null;
	const match = EMAIL_DOMAIN.exec(text.slice(0, MAX_TEXT));
	return match?.[1] ? match[1].toLowerCase() : null;
}

function first(root: ParentNode, selector: string): Element | null {
	try {
		return root.querySelector(selector);
	} catch {
		return null;
	}
}

function hostOf(url: string): string | null {
	try {
		return new URL(url).hostname;
	} catch {
		return null;
	}
}

/**
 * ChatGPT. Signal `chatgpt.cookie-account`: the `_account` cookie holds the id of the active
 * workspace once the user picks a Team/Enterprise/Edu workspace (the web app sends it as the
 * `ChatGPT-Account-Id` request header); `personal` (or no cookie) is the personal account.
 */
function chatgptAccount(probe: AccountProbe): AccountContext {
	const raw = cookieValue(probe.cookie, "_account");
	const workspaceId = workspaceIdOf(raw);
	if (workspaceId)
		return { ...UNKNOWN, kind: "work", workspaceId, signals: ["chatgpt.cookie-account"] };
	if (raw !== null && raw.trim().toLowerCase() === "personal")
		return { ...UNKNOWN, kind: "personal", signals: ["chatgpt.cookie-account"] };
	return UNKNOWN;
}

/**
 * Claude. Signal `claude.cookie-org`: the `lastActiveOrg` cookie holds the UUID of the active
 * organisation. Every claude.ai account has one (a personal account has a personal
 * organisation), so the id alone does not say "work": only the policy's list does.
 */
function claudeAccount(probe: AccountProbe): AccountContext {
	const workspaceId = workspaceIdOf(cookieValue(probe.cookie, "lastActiveOrg"));
	return workspaceId ? { ...UNKNOWN, workspaceId, signals: ["claude.cookie-org"] } : UNKNOWN;
}

/**
 * Gemini. Signal `google.account-button`: the Google bar's account button links to
 * `accounts.google.com/SignOutOptions` and its accessible name carries the signed-in email
 * ("Google Account: Name (user@example.com)", in every UI language). gmail.com / googlemail.com
 * is a personal account, any other domain a Google Workspace (or custom-domain) account.
 */
function geminiAccount(probe: AccountProbe): AccountContext {
	// No literal remote URL in the bundle (the build's remote-URL scan refuses one).
	const button = first(
		probe.root,
		'a[href^="https:"][href*="//accounts.google.com/SignOutOptions"]',
	);
	const domain = emailDomainIn(button?.getAttribute("aria-label") ?? null);
	if (!domain) return UNKNOWN;
	return {
		...UNKNOWN,
		kind: CONSUMER_GOOGLE_DOMAINS.has(domain) ? "personal" : "work",
		emailDomain: domain,
		signals: ["google.account-button"],
	};
}

/**
 * Microsoft Copilot. Signal `copilot.host`: consumer Copilot (`copilot.microsoft.com`, a
 * Microsoft account) and Microsoft 365 Copilot Chat (`m365.cloud.microsoft`,
 * `copilot.cloud.microsoft`, an Entra ID work account only) are separate hosts. Signal
 * `m365.me-control`: the Microsoft 365 header's account manager shows the signed-in user
 * principal name in `#mectrl_currentAccount_secondary`.
 */
function copilotAccount(probe: AccountProbe): AccountContext {
	const host = hostOf(probe.url);
	if (host === null) return UNKNOWN;
	const work = M365_COPILOT_HOSTS.includes(host);
	if (!work && host !== "copilot.microsoft.com") return UNKNOWN;
	const signals = ["copilot.host"];
	const upn = first(probe.root, "#mectrl_currentAccount_secondary");
	const domain = emailDomainIn(upn?.textContent ?? null);
	if (domain) signals.push("m365.me-control");
	const consumerDomain = domain !== null && CONSUMER_MICROSOFT_DOMAINS.has(domain);
	return {
		...UNKNOWN,
		kind: work && !consumerDomain ? "work" : "personal",
		emailDomain: domain,
		signals,
	};
}

const DETECTORS: Readonly<Record<AccountSiteId, (probe: AccountProbe) => AccountContext>> = {
	chatgpt: chatgptAccount,
	claude: claudeAccount,
	gemini: geminiAccount,
	copilot: copilotAccount,
};

/** True for a site with an account detector. */
function isAccountSite(site: SiteId): site is AccountSiteId {
	return Object.hasOwn(DETECTORS, site);
}

/** The account the page exposes; `unknown` when the site has no detector or nothing is visible. */
export function detectAccount(site: SiteId, probe: AccountProbe): AccountContext {
	if (!isAccountSite(site)) return UNKNOWN;
	try {
		return DETECTORS[site](probe);
	} catch {
		return UNKNOWN;
	}
}

/** `domain` is `listed` or a subdomain of it. */
function domainMatches(domain: string, listed: string): boolean {
	return domain === listed || domain.endsWith(`.${listed}`);
}

/** The account type of `context` under one site's rule. */
export function classifyAccount(rule: WorkAccountSiteRule, context: AccountContext): AccountType {
	// First: a consumer Microsoft account may use a company email address, and it is still
	// a personal account (consumer Copilot host).
	if (context.kind === "personal") return "personal";
	const id = context.workspaceId;
	if (id !== null && rule.workspaceIds.some((allowed) => allowed.toLowerCase() === id))
		return "company";
	const domain = context.emailDomain;
	if (domain !== null && rule.emailDomains.some((listed) => domainMatches(domain, listed)))
		return "company";
	const anyWorkAccount = rule.workspaceIds.length === 0 && rule.emailDomains.length === 0;
	if (context.kind === "work" && anyWorkAccount) return "company";
	if (context.kind === "work" || id !== null || domain !== null) return "other";
	return "unverified";
}

/** The result of the account check on one page. */
export interface AccountVerdict {
	readonly type: AccountType;
	/** The configured action applies (the account is not confirmed as the organisation's). */
	readonly enforce: boolean;
	readonly action: WorkAccountPolicy["action"];
	/** Changes when the user switches account; keys a "warn" acknowledgement. */
	readonly key: string;
}

/**
 * The account check for `site` under `policy`, or null when the site is not account-checked
 * (no `workAccounts`, or the site is not listed in it).
 */
export function accountVerdict(
	policy: WorkAccountPolicy | null | undefined,
	site: SiteId,
	probe: AccountProbe,
): AccountVerdict | null {
	if (!policy || !isAccountSite(site)) return null;
	const rule = policy.sites[site];
	if (!rule) return null;
	const context = detectAccount(site, probe);
	const type = classifyAccount(rule, context);
	const enforce = type !== "company" && !(type === "unverified" && policy.unverified === "allow");
	return {
		type,
		enforce,
		action: policy.action,
		key: `${type}:${context.workspaceId ?? ""}:${context.emailDomain ?? ""}`,
	};
}
