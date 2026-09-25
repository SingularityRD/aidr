/**
 * Toxic-flow classification: which session capabilities a single tool call
 * contributes.
 *
 * The session-level model (see `toxic-flow.ts` and docs/toxic-flow.md) tracks
 * three capabilities that are harmless alone and dangerous together:
 *
 *   - `private_data`       reading secrets, credential stores, DB dumps, PII
 *   - `untrusted_content`  web pages, search results, MCP output, downloads
 *   - `external_comm`      sending anything to a destination the user does not own
 *
 * This module is pure: it only looks at the call (tool name, input, artifacts)
 * and the options it is handed. It never touches the filesystem, so it can run
 * on every call without cost, and the state layer is only consulted when a call
 * actually contributes something.
 *
 * Summaries produced here are the only text the state file and verdict reasons
 * ever contain about a step. They name a tool and a target (a path, a host, a
 * remote name), never a request body, query string or command argument that
 * could carry the data itself, and they are passed through the telemetry
 * redactor and bounded before they leave this module.
 */

import { redactTelemetryString } from "./telemetry-redaction.js";
import type { Artifact } from "./types.js";

export type FlowCapability = "private_data" | "untrusted_content" | "external_comm";

export type FlowKind =
	// private_data
	| "sensitive_file"
	| "credential_command"
	| "database_dump"
	| "secret_in_output"
	| "pii_in_output"
	// untrusted_content
	| "web_content"
	| "web_search"
	| "mcp_output"
	| "downloaded_file"
	| "injection_in_output"
	// external_comm
	| "network_egress"
	| "data_upload"
	| "paste_service"
	| "git_push_remote"
	| "email_send"
	| "mcp_send"
	// synthetic, written after a failed integrity check
	| "integrity_lost";

export interface FlowObservation {
	cap: FlowCapability;
	kind: FlowKind;
	/** Redacted, bounded description of the target (path, host, remote). */
	summary: string;
	/** Normalized identity of the target; hashed before it is stored. */
	target: string;
	/** `private_data` only: credential/secret-grade material (not generic PII). */
	secret?: boolean;
	/** `external_comm` only: the egress carries a payload (body, upload, piped data). */
	carriesData?: boolean;
}

export interface FlowClassification {
	observations: FlowObservation[];
	/** Summary of a destructive command in this call, or null. */
	destructive: string | null;
	/** Paths this call downloads content into (tracked as untrusted for the session). */
	downloads: string[];
	/** File paths this call reads, checked against earlier downloads by the caller. */
	reads: string[];
}

export interface FlowClassifierOptions {
	/** Destination domains that are not "external" for plain requests (suffix match). */
	trustedDomains: readonly string[];
	/** MCP server ids whose output is not treated as untrusted content. */
	trustedMcpServers: readonly string[];
	/** Git remote names a push to is not external communication. */
	trustedGitRemotes: readonly string[];
}

export interface FlowToolCall {
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: readonly Artifact[];
}

const MAX_SUMMARY_CHARS = 96;
const MAX_OBSERVATIONS = 24;
const MAX_DOWNLOADS_PER_CALL = 8;

/**
 * Package registries, language docs and source hosts. A plain request to one of
 * them is not external communication; a request that carries a payload still is
 * (an issue or gist body is readable by whoever owns the target).
 */
export const DEFAULT_TOXIC_FLOW_TRUSTED_DOMAINS: readonly string[] = [
	"registry.npmjs.org",
	"npmjs.com",
	"registry.yarnpkg.com",
	"yarnpkg.com",
	"pypi.org",
	"files.pythonhosted.org",
	"pythonhosted.org",
	"crates.io",
	"docs.rs",
	"rust-lang.org",
	"proxy.golang.org",
	"sum.golang.org",
	"pkg.go.dev",
	"go.dev",
	"golang.org",
	"rubygems.org",
	"repo.maven.apache.org",
	"repo1.maven.org",
	"plugins.gradle.org",
	"services.gradle.org",
	"nuget.org",
	"packagist.org",
	"jsr.io",
	"deno.land",
	"nodejs.org",
	"python.org",
	"developer.mozilla.org",
	"conda.anaconda.org",
	"repo.anaconda.com",
	"deb.debian.org",
	"archive.ubuntu.com",
	"security.ubuntu.com",
	"dl-cdn.alpinelinux.org",
	"registry-1.docker.io",
	"registry.hub.docker.com",
	"ghcr.io",
	"github.com",
	"codeload.github.com",
	"objects.githubusercontent.com",
	"gitlab.com",
	"bitbucket.org",
];

/**
 * Paste, file-drop, request-capture and chat-webhook services: an egress to one
 * of these is always external communication that carries data, whatever the
 * method, because the owner of the bin reads every request.
 */
const EXFIL_SINK_DOMAINS: readonly string[] = [
	"pastebin.com",
	"paste.ee",
	"pastes.io",
	"paste.rs",
	"paste.debian.net",
	"hastebin.com",
	"hastebin.skyra.pw",
	"ghostbin.co",
	"dpaste.org",
	"dpaste.com",
	"bpa.st",
	"ix.io",
	"sprunge.us",
	"termbin.com",
	"0x0.st",
	"transfer.sh",
	"file.io",
	"tmpfiles.org",
	"catbox.moe",
	"gofile.io",
	"anonfiles.com",
	"rentry.co",
	"privatebin.net",
	"justpaste.it",
	"controlc.com",
	"gist.github.com",
	"gist.githubusercontent.com",
	"webhook.site",
	"requestbin.net",
	"requestcatcher.com",
	"pipedream.net",
	"beeceptor.com",
	"hookbin.com",
	"ngrok.io",
	"ngrok-free.app",
	"ngrok.app",
	"trycloudflare.com",
	"interact.sh",
	"oast.fun",
	"oast.pro",
	"oast.live",
	"oast.site",
	"oast.online",
	"oast.me",
	"burpcollaborator.net",
	"hooks.slack.com",
	"api.telegram.org",
	"discord.com/api/webhooks",
	"discordapp.com/api/webhooks",
];

// ── Sensitive material ─────────────────────────────────────────────

interface SensitivePathRule {
	pattern: RegExp;
	label: string;
	kind: "sensitive_file" | "database_dump";
	secret: boolean;
}

const SEP = String.raw`[\\/]`;
const START = String.raw`(?:^|[\\/])`;

/** Credential stores, key material and data dumps, matched on a path or path-like token. */
const SENSITIVE_PATH_RULES: readonly SensitivePathRule[] = [
	{
		pattern: new RegExp(`${START}\\.ssh${SEP}(?:id_[a-z0-9_-]+|identity)(?!\\.pub)$`, "i"),
		label: "SSH private key",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(`${START}\\.aws${SEP}(?:credentials|config|sso${SEP}cache${SEP}.+)$`, "i"),
		label: "cloud credentials",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`${START}\\.config${SEP}gcloud${SEP}.*(?:credential|token|\\.json$|\\.db$)`,
			"i",
		),
		label: "cloud credentials",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`${START}\\.azure${SEP}(?:accessTokens\\.json|msal_token_cache.*|azureProfile\\.json)$`,
			"i",
		),
		label: "cloud credentials",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`${START}\\.env(?:\\.(?!example$|sample$|template$|dist$|defaults?$)[\\w-]{1,40})?$`,
			"i",
		),
		label: "environment secrets file",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`${START}\\.(?:netrc|pgpass|npmrc|pypirc|git-credentials|my\\.cnf|vault-token|boto)$`,
			"i",
		),
		label: "credential file",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(`${START}\\.docker${SEP}config\\.json$`, "i"),
		label: "registry credentials",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(`(?:${START}\\.kube${SEP}config|${START}kubeconfig(?:\\.ya?ml)?)$`, "i"),
		label: "cluster credentials",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(`${START}\\.config${SEP}gh${SEP}hosts\\.ya?ml$`, "i"),
		label: "GitHub CLI token",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(`${START}\\.gnupg${SEP}(?:private-keys-v1\\.d|secring\\.gpg)`, "i"),
		label: "private keyring",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: /\.(?:pem|key|p12|pfx|jks|keystore|ppk|kdbx|ovpn)$/i,
		label: "key material",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`${START}(?:credentials|secrets?|service[-_]?account(?:[-_][\\w-]{0,40})?)\\.(?:json|ya?ml|toml|ini|txt)$`,
			"i",
		),
		label: "credential file",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`${START}(?:master\\.key|credentials\\.yml\\.enc|terraform\\.tfstate(?:\\.backup)?)$`,
			"i",
		),
		label: "secret store",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(`${START}etc${SEP}(?:shadow|gshadow|sudoers|master\\.passwd)$`, "i"),
		label: "system password store",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`${START}(?:Login Data|Cookies|Local State|key[34]\\.db|logins\\.json|cookies\\.sqlite)$`,
			"i",
		),
		label: "browser credential store",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`${START}(?:Library${SEP}Keychains|\\.local${SEP}share${SEP}keyrings)(?:${SEP}|$)`,
			"i",
		),
		label: "OS keychain",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(
			`(?:${START}wallet\\.dat|${START}\\.(?:bitcoin|ethereum)${SEP}keystore)`,
			"i",
		),
		label: "crypto wallet",
		kind: "sensitive_file",
		secret: true,
	},
	{
		pattern: new RegExp(`${START}\\.(?:bash|zsh|sh|psql|mysql|python)_history$`, "i"),
		label: "shell history",
		kind: "sensitive_file",
		secret: false,
	},
	{
		pattern: new RegExp(
			`${START}[^\\\\/]*(?:dump|backup)[^\\\\/]*\\.(?:sql|dump|bak|gz|tar|zip)$|\\.dump$`,
			"i",
		),
		label: "database dump",
		kind: "database_dump",
		secret: true,
	},
];

interface CommandRule {
	pattern: RegExp;
	label: string;
	kind: "credential_command" | "database_dump";
}

/** Commands that print credentials or dump a database. */
const CREDENTIAL_COMMAND_RULES: readonly CommandRule[] = [
	{
		pattern: /(?:^|[;&|(]\s*)(?:printenv|env|set)\s*(?:$|[;&|>)])/,
		label: "environment dump",
		kind: "credential_command",
	},
	{
		pattern: /\/proc\/(?:self|\d+)\/environ\b/,
		label: "process environment",
		kind: "credential_command",
	},
	{
		pattern: /\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain)\b/,
		label: "keychain read",
		kind: "credential_command",
	},
	{
		pattern: /\bgpg2?\b[^\n]{0,200}--export-secret-(?:sub)?keys\b/,
		label: "private key export",
		kind: "credential_command",
	},
	{
		pattern:
			/\baws\s+(?:configure\s+(?:get|export-credentials)|sts\s+get-session-token|secretsmanager\s+get-secret-value|ssm\s+get-parameters?\b[^\n]{0,200}--with-decryption)/,
		label: "cloud secret read",
		kind: "credential_command",
	},
	{
		pattern: /\bgcloud\s+auth\s+(?:application-default\s+)?print-(?:access|identity)-token\b/,
		label: "cloud token read",
		kind: "credential_command",
	},
	{
		pattern: /\baz\s+account\s+get-access-token\b/,
		label: "cloud token read",
		kind: "credential_command",
	},
	{
		pattern: /\bgh\s+auth\s+(?:token|status\s+[^\n]{0,40}--show-token)\b/,
		label: "GitHub token read",
		kind: "credential_command",
	},
	{
		pattern: /\bgit\s+credential\s+fill\b/,
		label: "git credential read",
		kind: "credential_command",
	},
	{
		pattern: /\bkubectl\s+get\s+secrets?\b/,
		label: "cluster secret read",
		kind: "credential_command",
	},
	{
		pattern: /\bvault\s+(?:kv\s+get|read)\b/,
		label: "vault secret read",
		kind: "credential_command",
	},
	{
		pattern: /\bop\s+(?:read|item\s+get)\b/,
		label: "password manager read",
		kind: "credential_command",
	},
	{
		pattern:
			/\b(?:pg_dump|pg_dumpall|mysqldump|mariadb-dump|mongodump|mongoexport)\b|\bsqlite3\b[^\n]{0,200}\.dump\b/,
		label: "database dump",
		kind: "database_dump",
	},
];

// ── Destructive commands ───────────────────────────────────────────

const DESTRUCTIVE_COMMAND_RULES: ReadonlyArray<{ pattern: RegExp; label: string }> = [
	{
		pattern:
			/\bgit\s+(?:-[Cc]\s+\S+\s+)*push\b[^\n;&|]{0,300}?(?:\s--force(?:-with-lease)?\b|\s-f\b|\s--mirror\b|\s\+\S)/,
		label: "git force push",
	},
	{ pattern: /\bgit\s+reset\s+[^\n;&|]{0,100}--hard\b/, label: "git reset --hard" },
	{ pattern: /\bgit\s+clean\s+-[a-zA-Z]*f/, label: "git clean -f" },
	{ pattern: /\bfind\b[^\n;&|]{0,300}\s(?:-delete\b|-exec\s+rm\b)/, label: "find -delete" },
	{ pattern: /\b(?:mkfs(?:\.\w+)?|wipefs|shred)\b/, label: "disk/file wipe" },
	{ pattern: /\bdd\b[^\n;&|]{0,200}\bof=\/dev\//, label: "raw device write" },
	{
		pattern: /\bch(?:mod|own)\s+-R\b[^\n;&|]{0,200}\s(?:\/|~|\$HOME|\$\{HOME\})(?:\s|$)/,
		label: "recursive permission change on home or root",
	},
	{
		pattern: /\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b/i,
		label: "SQL drop/truncate",
	},
	{ pattern: /\bdelete\s+from\s+[\w."`]+\s*(?:;|$|["'])/i, label: "SQL delete without WHERE" },
	{
		pattern: /\bterraform\s+(?:destroy\b|apply\b[^\n;&|]{0,200}-destroy\b)/,
		label: "terraform destroy",
	},
	{ pattern: /\bpulumi\s+destroy\b/, label: "pulumi destroy" },
	{ pattern: /\bkubectl\s+delete\b/, label: "kubectl delete" },
	{ pattern: /\bhelm\s+(?:uninstall|delete)\b/, label: "helm uninstall" },
	{ pattern: /\baws\s+s3\s+(?:rm\b[^\n;&|]{0,300}--recursive|rb\b)/, label: "S3 recursive delete" },
	{ pattern: /\bgsutil\s+(?:-m\s+)?rm\s+-r\b/, label: "bucket recursive delete" },
	{ pattern: /\bdocker\s+(?:system\s+prune\b|volume\s+(?:rm|prune)\b)/, label: "docker prune" },
	{ pattern: /\bcrontab\s+-r\b/, label: "crontab removal" },
	{ pattern: /\bRemove-Item\b[^\n;&|]{0,300}-Recurse\b/i, label: "recursive delete" },
	{ pattern: /\b(?:rd|rmdir)\s+\/s\b/i, label: "recursive delete" },
];

// ── Helpers ────────────────────────────────────────────────────────

function bound(text: string): string {
	const single = text.replace(/[\r\n\t]+/g, " ").replace(/[\u0000-\u001f\u007f]/g, "");
	const redacted = redactTelemetryString(single, MAX_SUMMARY_CHARS);
	return redacted;
}

/** Collapse home-directory spellings so `~/.aws/x`, `$HOME/.aws/x` and `/home/u/.aws/x` agree. */
export function normalizeFlowPath(raw: string): string {
	let path = raw.trim().replace(/^["'`]+|["'`]+$/g, "");
	path = path.replace(/^(?:\$HOME|\$\{HOME\}|%USERPROFILE%)(?=[\\/]|$)/i, "~");
	path = path.replace(/^\/(?:home|Users)\/[^\\/]+(?=[\\/]|$)/, "~");
	path = path.replace(/^[A-Za-z]:\\Users\\[^\\]+(?=\\|$)/, "~");
	path = path.replace(/\\/g, "/");
	path = path.replace(/^\.\/+/, "");
	path = path.replace(/\/+$/, "");
	return path;
}

function sensitivePathRule(path: string): SensitivePathRule | null {
	const normalized = normalizeFlowPath(path);
	if (!normalized || normalized.length > 1024) return null;
	for (const rule of SENSITIVE_PATH_RULES) {
		if (rule.pattern.test(normalized)) return rule;
	}
	return null;
}

function hostOf(url: string): string | null {
	try {
		const parsed = new URL(url);
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:" && parsed.protocol !== "ftp:") {
			return null;
		}
		return parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
	} catch {
		return null;
	}
}

function domainMatches(host: string, domain: string): boolean {
	const d = domain.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
	if (!d) return false;
	return host === d || host.endsWith(`.${d}`);
}

function isLocalHost(host: string): boolean {
	if (
		host === "localhost" ||
		host.endsWith(".localhost") ||
		host.endsWith(".local") ||
		host.endsWith(".internal") ||
		host === "::1" ||
		host === "0.0.0.0"
	) {
		return true;
	}
	const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
	if (v4) {
		const a = Number(v4[1]);
		const b = Number(v4[2]);
		return (
			a === 127 ||
			a === 10 ||
			(a === 192 && b === 168) ||
			(a === 172 && b >= 16 && b <= 31) ||
			(a === 169 && b === 254)
		);
	}
	return /^f[cd][0-9a-f]{2}:/i.test(host) || /^fe80:/i.test(host);
}

function isExfilSink(url: string, host: string): boolean {
	const lowered = url.toLowerCase();
	for (const sink of EXFIL_SINK_DOMAINS) {
		const slash = sink.indexOf("/");
		if (slash === -1) {
			if (domainMatches(host, sink)) return true;
		} else if (domainMatches(host, sink.slice(0, slash)) && lowered.includes(sink.slice(slash))) {
			return true;
		}
	}
	return false;
}

/**
 * Whether a URL itself carries a payload: a long query/fragment, or a long
 * unbroken token in it. Documentation links (`?q=foo`) do not; `?k=<base64>` does.
 */
export function urlCarriesData(url: string): boolean {
	try {
		const parsed = new URL(url);
		const tail = `${parsed.search}${parsed.hash}`;
		if (tail.length > 128) return true;
		return /[A-Za-z0-9+/_=%-]{24,}/.test(tail);
	} catch {
		return false;
	}
}

interface Destination {
	host: string;
	local: boolean;
	sink: boolean;
	trusted: boolean;
}

function classifyDestination(url: string, options: FlowClassifierOptions): Destination | null {
	const host = hostOf(url);
	if (!host) return null;
	return {
		host,
		local: isLocalHost(host),
		sink: isExfilSink(url, host),
		trusted: options.trustedDomains.some((domain) => domainMatches(host, domain)),
	};
}

const URL_IN_TEXT = /\b(?:https?|ftp):\/\/[^\s"'`<>|;)]+/gi;

function urlsIn(text: string): string[] {
	return [...text.matchAll(URL_IN_TEXT)].map((match) => match[0]).slice(0, 16);
}

// ── Shell parsing (quote-aware, deliberately small) ────────────────

interface ShellStage {
	text: string;
	words: string[];
	/** Words that follow an output redirect (`>`, `>>`, `2>`, `&>`). */
	redirectTargets: Set<number>;
	/** Stage reads from a pipe or an input redirect. */
	hasInput: boolean;
}

function splitPipelines(command: string): string[][] {
	const pipelines: string[][] = [];
	let stages: string[] = [];
	let current = "";
	let quote: '"' | "'" | null = null;
	for (let i = 0; i < command.length; i += 1) {
		const ch = command[i] as string;
		if (quote) {
			if (ch === quote) quote = null;
			else if (ch === "\\" && quote === '"' && i + 1 < command.length) {
				current += ch + (command[i + 1] as string);
				i += 1;
				continue;
			}
			current += ch;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			current += ch;
			continue;
		}
		if (ch === "\\" && i + 1 < command.length) {
			current += ch + (command[i + 1] as string);
			i += 1;
			continue;
		}
		const next = command[i + 1];
		if (ch === ";" || ch === "\n" || (ch === "&" && next === "&") || (ch === "|" && next === "|")) {
			stages.push(current);
			pipelines.push(stages);
			stages = [];
			current = "";
			if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) i += 1;
			continue;
		}
		if (ch === "|") {
			stages.push(current);
			current = "";
			if (next === "&") i += 1;
			continue;
		}
		current += ch;
	}
	stages.push(current);
	pipelines.push(stages);
	return pipelines
		.map((pipeline) => pipeline.map((stage) => stage.trim()))
		.filter((pipeline) => pipeline.some((stage) => stage.length > 0));
}

function shellWords(stage: string): {
	words: string[];
	redirectTargets: Set<number>;
	inputRedirect: boolean;
} {
	const words: string[] = [];
	const redirectTargets = new Set<number>();
	let inputRedirect = false;
	let current = "";
	let hasCurrent = false;
	let quote: '"' | "'" | null = null;
	let pendingRedirect = false;
	const push = () => {
		if (!hasCurrent) return;
		if (pendingRedirect) {
			redirectTargets.add(words.length);
			pendingRedirect = false;
		}
		words.push(current);
		current = "";
		hasCurrent = false;
	};
	for (let i = 0; i < stage.length; i += 1) {
		const ch = stage[i] as string;
		if (quote) {
			if (ch === quote) quote = null;
			else current += ch;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			hasCurrent = true;
			continue;
		}
		if (ch === "\\" && i + 1 < stage.length) {
			current += stage[i + 1] as string;
			hasCurrent = true;
			i += 1;
			continue;
		}
		if (/\s/.test(ch)) {
			push();
			continue;
		}
		if (ch === ">") {
			// `2>`, `&>` and `>>` all redirect output; the operand is the next word.
			if (hasCurrent && /^(?:\d|&)$/.test(current)) {
				current = "";
				hasCurrent = false;
			} else push();
			if (stage[i + 1] === ">") i += 1;
			if (stage[i + 1] === "&") {
				// `2>&1`: fd duplication, no file operand.
				i += 1;
				while (i + 1 < stage.length && /\d/.test(stage[i + 1] as string)) i += 1;
				continue;
			}
			pendingRedirect = true;
			continue;
		}
		if (ch === "<" && stage[i + 1] !== "(") {
			push();
			inputRedirect = true;
			continue;
		}
		current += ch;
		hasCurrent = true;
	}
	push();
	return { words, redirectTargets, inputRedirect };
}

const COMMAND_PREFIXES = new Set([
	"sudo",
	"doas",
	"command",
	"exec",
	"time",
	"nohup",
	"nice",
	"ionice",
	"stdbuf",
	"timeout",
	"env",
	"builtin",
]);

/** Index of the executable word, skipping `sudo`, `env A=B`, `timeout 5` and the like. */
function commandIndex(words: string[]): number {
	let i = 0;
	while (i < words.length) {
		const word = words[i] as string;
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) {
			i += 1;
			continue;
		}
		const base = basename(word);
		if (COMMAND_PREFIXES.has(base)) {
			i += 1;
			// Skip the prefix's own flags and a numeric argument (`timeout 5`).
			while (
				i < words.length &&
				(/^-/.test(words[i] as string) || /^\d+[smhd]?$/.test(words[i] as string))
			) {
				i += 1;
			}
			continue;
		}
		return i;
	}
	return -1;
}

function basename(word: string): string {
	const parts = word.split(/[\\/]/);
	return (parts[parts.length - 1] ?? word).toLowerCase().replace(/\.exe$/, "");
}

function parseStages(command: string): ShellStage[][] {
	return splitPipelines(command).map((pipeline) =>
		pipeline.map((text, index) => {
			const { words, redirectTargets, inputRedirect } = shellWords(text);
			return { text, words, redirectTargets, hasInput: index > 0 || inputRedirect };
		}),
	);
}

// ── Classification ─────────────────────────────────────────────────

class ObservationSet {
	readonly items: FlowObservation[] = [];
	private readonly seen = new Set<string>();

	add(observation: FlowObservation): void {
		if (this.items.length >= MAX_OBSERVATIONS) return;
		const key = `${observation.cap}|${observation.kind}|${observation.target}`;
		if (this.seen.has(key)) {
			// Keep the strongest egress description for the same target.
			const existing = this.items.find((item) => `${item.cap}|${item.kind}|${item.target}` === key);
			if (existing && observation.carriesData) existing.carriesData = true;
			return;
		}
		this.seen.add(key);
		this.items.push({ ...observation, summary: bound(observation.summary) });
	}
}

function addSensitivePath(set: ObservationSet, path: string, verb: string): void {
	const rule = sensitivePathRule(path);
	if (!rule) return;
	const normalized = normalizeFlowPath(path);
	set.add({
		cap: "private_data",
		kind: rule.kind,
		summary: `${verb} ${normalized} (${rule.label})`,
		target: `path:${normalized}`,
		secret: rule.secret,
	});
}

function addEgress(
	set: ObservationSet,
	url: string,
	options: FlowClassifierOptions,
	via: string,
	carriesData: boolean,
): void {
	const destination = classifyDestination(url, options);
	if (!destination || destination.local) return;
	if (destination.sink) {
		set.add({
			cap: "external_comm",
			kind: "paste_service",
			summary: `${via} → ${destination.host} (paste/exfil sink)`,
			target: `host:${destination.host}`,
			carriesData: true,
		});
		return;
	}
	if (destination.trusted && !carriesData) return;
	set.add({
		cap: "external_comm",
		kind: carriesData ? "data_upload" : "network_egress",
		summary: `${via} → ${destination.host}${carriesData ? " (carries data)" : ""}`,
		target: `host:${destination.host}`,
		carriesData,
	});
}

function addUntrustedFetch(
	set: ObservationSet,
	url: string,
	via: string,
	options: FlowClassifierOptions,
): void {
	const destination = classifyDestination(url, options);
	if (!destination || destination.local) return;
	set.add({
		cap: "untrusted_content",
		kind: "web_content",
		summary: `${via} ← ${destination.host}`,
		target: `host:${destination.host}`,
	});
}

const HTTP_CLIENTS = new Set([
	"curl",
	"wget",
	"http",
	"https",
	"xh",
	"xhs",
	"httpie",
	"aria2c",
	"invoke-webrequest",
	"iwr",
	"invoke-restmethod",
	"irm",
	"lwp-request",
	"fetch",
]);
const RAW_SOCKET_CLIENTS = new Set(["nc", "ncat", "netcat", "socat", "telnet"]);
const COPY_CLIENTS = new Set(["scp", "rsync", "sftp"]);
const MAIL_CLIENTS = new Set(["sendmail", "mail", "mailx", "mutt", "swaks", "msmtp", "s-nail"]);
const DNS_CLIENTS = new Set(["dig", "nslookup", "host", "drill"]);
const INTERPRETERS = new Set([
	"python",
	"python3",
	"python2",
	"node",
	"nodejs",
	"ruby",
	"perl",
	"php",
	"deno",
	"bun",
]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);

function curlCarriesData(words: string[]): boolean {
	for (let i = 0; i < words.length; i += 1) {
		const word = words[i] as string;
		if (
			/^--(?:data(?:-[a-z]+)?|form(?:-string)?|upload-file|json|post-data|post-file|body-data|body-file)(?:=|$)/.test(
				word,
			)
		) {
			return true;
		}
		if (/^--(?:request|method)(?:=|$)/.test(word)) {
			const value = word.includes("=") ? word.split("=")[1] : words[i + 1];
			if (value && /^(?:post|put|patch)$/i.test(value)) return true;
		}
		if (/^-X(?:POST|PUT|PATCH)?$/i.test(word)) {
			const value = word.length > 2 ? word.slice(2) : words[i + 1];
			if (value && /^(?:post|put|patch)$/i.test(value)) return true;
		}
		// Short option clusters: `-d`, `-sd`, `-F`, `-T`, `-d@file`.
		if (/^-[a-zA-Z]*[dFT]/.test(word) && !word.startsWith("--")) {
			const cluster = /^-([a-zA-Z]+)/.exec(word)?.[1] ?? "";
			for (const flag of cluster) {
				if (flag === "d" || flag === "F" || flag === "T") return true;
				// Flags that take an argument end the cluster.
				if ("oOHAeEuUxXwKmrCyYzbc".includes(flag)) break;
			}
		}
		// PowerShell.
		if (/^-(?:Body|InFile)$/i.test(word)) return true;
		if (/^-Method$/i.test(word) && /^(?:post|put|patch)$/i.test(words[i + 1] ?? "")) return true;
		// HTTPie / xh request items: `field=value`, `field:=json`, `@file`.
		if (i > 0 && /^[A-Za-z_][\w-]*:?=|^@/.test(word) && !word.includes("://")) return true;
	}
	return false;
}

/** Where an HTTP download lands: a file (tracked) or stdout (content enters context). */
function httpDownloadTarget(
	client: string,
	words: string[],
	url: string | undefined,
): string | "stdout" {
	for (let i = 0; i < words.length; i += 1) {
		const word = words[i] as string;
		if (client === "curl") {
			if (word === "-o" || word === "--output") return words[i + 1] ?? "stdout";
			if (/^-o.+/.test(word)) return word.slice(2);
			if (/^--output=/.test(word)) return word.slice("--output=".length);
			if (word === "-O" || word === "--remote-name" || /^-[a-zA-Z]*O[a-zA-Z]*$/.test(word)) {
				return urlBasename(url);
			}
		}
		if (client === "wget") {
			if (word === "-O" || word === "--output-document") {
				const target = words[i + 1];
				return !target || target === "-" ? "stdout" : target;
			}
			if (/^-[a-zA-Z]*O-?$/.test(word)) {
				if (word.endsWith("-")) return "stdout";
				const target = words[i + 1];
				return !target || target === "-" ? "stdout" : target;
			}
			if (/^--output-document=/.test(word)) {
				const target = word.slice("--output-document=".length);
				return target === "-" ? "stdout" : target;
			}
			if (word === "-P" || word === "--directory-prefix") return words[i + 1] ?? urlBasename(url);
		}
	}
	return client === "wget" ? urlBasename(url) : "stdout";
}

function urlBasename(url: string | undefined): string {
	if (!url) return "index.html";
	try {
		const segment = new URL(url).pathname.split("/").filter(Boolean).pop();
		return segment && segment.length > 0 ? decodeURIComponent(segment) : "index.html";
	} catch {
		return "index.html";
	}
}

function gitRemoteName(words: string[], pushIndex: number): string | null {
	for (let i = pushIndex + 1; i < words.length; i += 1) {
		const word = words[i] as string;
		if (/^--repo=/.test(word)) return word.slice("--repo=".length);
		if (word === "--repo") return words[i + 1] ?? null;
		if (
			word === "-o" ||
			word === "--push-option" ||
			word === "--receive-pack" ||
			word === "--exec"
		) {
			i += 1;
			continue;
		}
		if (word.startsWith("-")) continue;
		return word;
	}
	return null;
}

function remoteSummary(remote: string): string {
	const host = hostOf(remote);
	if (host) return host;
	const scp = /^(?:[\w.-]+@)?([\w.-]+):/.exec(remote);
	if (scp) return scp[1] as string;
	return remote;
}

/** Everything a per-executable handler needs; handlers return true for transfer stages. */
interface StageContext {
	stage: ShellStage;
	exe: string;
	args: string[];
	set: ObservationSet;
	downloads: string[];
	reads: string[];
	options: FlowClassifierOptions;
	depth: number;
}

const HAS_SUBSTITUTION = /\$\(|`/;

function firstOperand(args: string[]): string | undefined {
	return args.find((arg) => !arg.startsWith("-"));
}

function addRemoteUpload(set: ObservationSet, via: string, remote: string, note: string): void {
	const host = remoteSummary(remote);
	if (isLocalHost(host.toLowerCase())) return;
	set.add({
		cap: "external_comm",
		kind: "data_upload",
		summary: `${via} → ${host} (${note})`,
		target: `host:${host.toLowerCase()}`,
		carriesData: true,
	});
}

/** Nested shells and eval: classify the inner command once. */
function handleNestedShell(ctx: StageContext): boolean {
	const { exe, args } = ctx;
	const inlineIndex = args.findIndex((arg) => /^-[a-z]*c$/.test(arg));
	const inner = exe === "eval" ? args.join(" ") : args[inlineIndex + 1];
	if (inner && (exe === "eval" || inlineIndex >= 0)) {
		classifyShellCommand(inner, ctx.set, ctx.downloads, ctx.reads, ctx.options, ctx.depth + 1);
		return false;
	}
	// `bash script.sh` executes a file: treat it as a read of that file.
	const script = firstOperand(args);
	if (script) ctx.reads.push(script);
	return false;
}

function handleHttpClient(ctx: StageContext): boolean {
	const { exe, args, stage, set, options } = ctx;
	const carries = curlCarriesData(args) || stage.hasInput || HAS_SUBSTITUTION.test(stage.text);
	let urls = urlsIn(stage.text);
	if (urls.length === 0) {
		const bare = args.find(
			(arg) => !arg.startsWith("-") && /^[\w-]+(?:\.[\w-]+)+(?::\d+)?(?:\/|$)/.test(arg),
		);
		if (bare) urls = [`https://${bare}`];
	}
	for (const url of urls) {
		addEgress(set, url, options, exe, carries || urlCarriesData(url));
		const target = exe === "curl" || exe === "wget" ? httpDownloadTarget(exe, args, url) : "stdout";
		if (target === "stdout") addUntrustedFetch(set, url, exe, options);
		else if (!classifyDestination(url, options)?.local) ctx.downloads.push(target);
	}
	return true;
}

function handleRawSocket(ctx: StageContext): boolean {
	const host = ctx.args.find(
		(arg) => !arg.startsWith("-") && !/^\d+$/.test(arg) && /[A-Za-z0-9]/.test(arg),
	);
	if (host) {
		const url = `http://${host.replace(/^[a-z]+:/i, "")}`;
		const carries = ctx.stage.hasInput || /\s-[ec]\b/.test(ctx.stage.text);
		addEgress(ctx.set, url, ctx.options, ctx.exe, carries);
	}
	return false;
}

function isRemoteCopyOperand(arg: string): boolean {
	return (
		!/^[A-Za-z]:[\\/]/.test(arg) && !/^[a-z]+:\/\//i.test(arg) && /^(?:[\w.-]+@)?[\w.-]+:/.test(arg)
	);
}

function handleCopyClient(ctx: StageContext): boolean {
	const operands = ctx.args.filter((arg) => !arg.startsWith("-"));
	const last = operands[operands.length - 1];
	if (!last) return true;
	if (isRemoteCopyOperand(last)) {
		addRemoteUpload(ctx.set, ctx.exe, last, "copies files out");
		for (const source of operands.slice(0, -1)) addSensitivePath(ctx.set, source, ctx.exe);
	} else if (operands.slice(0, -1).some(isRemoteCopyOperand)) {
		ctx.downloads.push(last);
	}
	return true;
}

function handleSsh(ctx: StageContext): boolean {
	const host = firstOperand(ctx.args);
	if (host && ctx.stage.hasInput) addRemoteUpload(ctx.set, "ssh", host, "piped data");
	return false;
}

function handleMail(ctx: StageContext): boolean {
	ctx.set.add({
		cap: "external_comm",
		kind: "email_send",
		summary: `${ctx.exe} (sends email)`,
		target: `mail:${ctx.exe}`,
		carriesData: true,
	});
	return false;
}

function handleDns(ctx: StageContext): boolean {
	if (!HAS_SUBSTITUTION.test(ctx.stage.text)) return false;
	ctx.set.add({
		cap: "external_comm",
		kind: "data_upload",
		summary: `${ctx.exe} lookup built from command output (DNS exfiltration shape)`,
		target: `dns:${ctx.exe}`,
		carriesData: true,
	});
	return false;
}

function handleGit(ctx: StageContext): boolean {
	const { args, set, options } = ctx;
	const pushIndex = args.indexOf("push");
	const globalOptionsOnly = (arg: string, i: number, all: string[]) =>
		arg.startsWith("-") || all[i - 1] === "-C" || all[i - 1] === "-c";
	if (pushIndex >= 0 && args.slice(0, pushIndex).every(globalOptionsOnly)) {
		const remote = gitRemoteName(args, pushIndex);
		if (remote && !options.trustedGitRemotes.includes(remote)) {
			set.add({
				cap: "external_comm",
				kind: "git_push_remote",
				summary: `git push → ${remoteSummary(remote)}`,
				target: `git:${remoteSummary(remote).toLowerCase()}`,
				carriesData: true,
			});
		}
	}
	const cloneIndex = args.indexOf("clone");
	if (cloneIndex < 0) return false;
	const operands = args.slice(cloneIndex + 1).filter((arg) => !arg.startsWith("-"));
	const source = operands[0];
	if (source) ctx.downloads.push(operands[1] ?? urlBasename(source).replace(/\.git$/, ""));
	return true;
}

function handleGh(ctx: StageContext): boolean {
	if (ctx.args[0] !== "gist" || ctx.args[1] !== "create") return false;
	ctx.set.add({
		cap: "external_comm",
		kind: "paste_service",
		summary: "gh gist create (paste/exfil sink)",
		target: "host:gist.github.com",
		carriesData: true,
	});
	return false;
}

const NETWORK_API =
	/(?:requests\.|urllib|http\.client|urlopen|fetch\(|axios|XMLHttpRequest|net\.connect|socket\.|Net::HTTP|LWP|HTTP::Tiny|curl_exec|file_get_contents\(\s*['"]https?)/;

function handleInterpreter(ctx: StageContext): boolean {
	const { exe, args } = ctx;
	const flagIndex = args.findIndex(
		(arg) => arg === "-c" || arg === "-e" || arg === "--eval" || arg === "-r",
	);
	if (flagIndex < 0) {
		const script = firstOperand(args);
		if (script) ctx.reads.push(script);
		return false;
	}
	const code = args[flagIndex + 1] ?? "";
	if (!NETWORK_API.test(code)) return false;
	const carries =
		/(?:post|put|patch|body|data=|json=|send|write|sendall)/i.test(code) || ctx.stage.hasInput;
	for (const url of urlsIn(code)) {
		addEgress(ctx.set, url, ctx.options, `${exe} one-liner`, carries || urlCarriesData(url));
		addUntrustedFetch(ctx.set, url, `${exe} one-liner`, ctx.options);
	}
	return false;
}

function stageHandler(exe: string, depth: number): ((ctx: StageContext) => boolean) | null {
	if ((SHELLS.has(exe) || exe === "eval") && depth < 2) return handleNestedShell;
	if (HTTP_CLIENTS.has(exe)) return handleHttpClient;
	if (RAW_SOCKET_CLIENTS.has(exe)) return handleRawSocket;
	if (COPY_CLIENTS.has(exe)) return handleCopyClient;
	if (MAIL_CLIENTS.has(exe)) return handleMail;
	if (DNS_CLIENTS.has(exe)) return handleDns;
	if (INTERPRETERS.has(exe)) return handleInterpreter;
	if (exe === "ssh") return handleSsh;
	if (exe === "git") return handleGit;
	if (exe === "gh") return handleGh;
	return null;
}

/** Classify one pipeline stage. Returns true when the stage is a download/copy. */
function classifyStage(
	stage: ShellStage,
	set: ObservationSet,
	downloads: string[],
	reads: string[],
	options: FlowClassifierOptions,
	depth: number,
): boolean {
	const index = commandIndex(stage.words);
	if (index < 0) return false;
	const executable = stage.words[index] as string;
	const exe = basename(executable);
	// Executing a local file (`./x.sh`) reads it.
	if (/^\.{0,2}\//.test(executable)) reads.push(executable);
	const handler = stageHandler(exe, depth);
	if (!handler) return false;
	return handler({
		stage,
		exe,
		args: stage.words.slice(index + 1),
		set,
		downloads,
		reads,
		options,
		depth,
	});
}

function classifyShellCommand(
	command: string,
	set: ObservationSet,
	downloads: string[],
	reads: string[],
	options: FlowClassifierOptions,
	depth: number,
): void {
	for (const pipeline of parseStages(command)) {
		for (const stage of pipeline) {
			const transfer = classifyStage(stage, set, downloads, reads, options, depth);
			// Every non-redirect-target word may be a path the command reads. The
			// words of a download or copy stage name the transfer, not a read.
			stage.words.forEach((word, wordIndex) => {
				if (stage.redirectTargets.has(wordIndex)) return;
				for (const piece of word.split(/[=,]/)) {
					const candidate = piece.replace(/^@/, "");
					if (candidate.length < 2) continue;
					addSensitivePath(set, candidate, "shell access to");
					if (!transfer && !candidate.startsWith("-")) reads.push(candidate);
				}
			});
		}
	}
	for (const rule of CREDENTIAL_COMMAND_RULES) {
		if (rule.pattern.test(command)) {
			set.add({
				cap: "private_data",
				kind: rule.kind,
				summary: rule.label,
				target: `cmd:${rule.label}`,
				secret: true,
			});
		}
	}
	// Any reference to an exfiltration sink is external communication.
	for (const url of urlsIn(command)) {
		const destination = classifyDestination(url, options);
		if (destination?.sink) addEgress(set, url, options, "shell", true);
	}
}

function isBroadDeleteTarget(target: string): boolean {
	const t = target.replace(/^["']|["']$/g, "");
	if (
		[
			"/",
			"/*",
			"~",
			"~/",
			"~/*",
			"$HOME",
			"${HOME}",
			"$HOME/",
			"$HOME/*",
			"*",
			".",
			"./",
			"./*",
			"..",
			"../",
			".*",
			".git",
			"./.git",
		].includes(t)
	) {
		return true;
	}
	return (
		/^\/[^/]+\/?\*?$/.test(t) ||
		/^\/(?:home|Users)\/[^/]+\/?\*?$/.test(t) ||
		/^(?:~|\$HOME|\$\{HOME\})\/[^/]+\/?\*?$/.test(t) ||
		/^[A-Za-z]:[\\/]?$/.test(t)
	);
}

function destructiveSummary(command: string): string | null {
	for (const pipeline of parseStages(command)) {
		for (const stage of pipeline) {
			const index = commandIndex(stage.words);
			if (index < 0) continue;
			const exe = basename(stage.words[index] as string);
			if (exe === "rm") {
				const args = stage.words.slice(index + 1);
				const recursive = args.some((arg) => /^-[a-zA-Z]*[rR]/.test(arg) || arg === "--recursive");
				const broad = args.filter((arg) => !arg.startsWith("-")).find(isBroadDeleteTarget);
				if (recursive && broad) return `rm -r ${normalizeFlowPath(broad) || broad}`;
			}
		}
	}
	for (const rule of DESTRUCTIVE_COMMAND_RULES) {
		if (rule.pattern.test(command)) return rule.label;
	}
	return null;
}

function stringField(input: Record<string, unknown>, keys: readonly string[]): string | undefined {
	for (const key of keys) {
		const value = input[key];
		if (typeof value === "string" && value.trim()) return value;
	}
	return undefined;
}

function commandText(input: Record<string, unknown>, artifacts: readonly Artifact[]): string {
	const raw = input.command;
	if (typeof raw === "string") return raw;
	if (Array.isArray(raw) && raw.every((part) => typeof part === "string")) {
		const argv = raw as string[];
		// `["bash", "-lc", "<script>"]` carries the real command in the script.
		const inline = argv.findIndex((part) => /^-[a-z]*c$/.test(part));
		if (inline >= 0 && typeof argv[inline + 1] === "string") return argv[inline + 1] as string;
		return argv
			.map((part) => (/[\s"'$`]/.test(part) ? `'${part.replace(/'/g, "'\\''")}'` : part))
			.join(" ");
	}
	const fromArtifact = artifacts.find((artifact) => artifact.type === "command");
	return fromArtifact?.value ?? "";
}

/** `mcp__<server>__<tool>` → `{ server, tool }`; the host's generic `MCP` tool reads its input. */
export function mcpToolIdentity(
	toolName: string,
	toolInput: Record<string, unknown>,
): { server: string; tool: string } | null {
	if (toolName.startsWith("mcp__")) {
		const rest = toolName.slice(5);
		const split = rest.indexOf("__");
		if (split <= 0) return { server: rest, tool: "" };
		return { server: rest.slice(0, split), tool: rest.slice(split + 2) };
	}
	if (toolName === "MCP") {
		return {
			server: stringField(toolInput, ["server", "server_name", "serverName"]) ?? "unknown",
			tool: stringField(toolInput, ["tool", "tool_name", "toolName", "name"]) ?? "",
		};
	}
	return null;
}

const SEND_TOOL =
	/(?:^|[_\-.])(?:send|post|publish|upload|e?mail|message|notify|tweet|webhook|share|reply|comment|dm|chat_?post|create_(?:issue|comment|gist|pull_request|pr|message|post|note|page|message))(?:$|[_\-.])/i;
const WEB_READ_TOOL =
	/(?:browser|browse|navigate|playwright|puppeteer|scrape|crawl|firecrawl|web_?search|search_?web|web_?fetch|fetch_?url|http_?get|read_?url|open_?url|google_?search|brave_?search|tavily|exa_?search)/i;
const WEB_SEARCH_TOOL =
	/^(?:web_?search|search_?web|google_?search|brave_?search|tavily_?search|exa_?search)$/i;
/** Tool names that read a file (`read_file`, `get_file_contents`, `view`); writes are not reads. */
const FILE_READ_TOOL = /(?:^|_)(?:read|get|cat|view|open|download|load|show|head|tail)(?:_|$)/i;

function artifactValues(artifacts: readonly Artifact[], type: Artifact["type"]): string[] {
	return artifacts.filter((artifact) => artifact.type === type).map((artifact) => artifact.value);
}

/**
 * Classify one (already normalized) tool call.
 *
 * The result never includes the request payload itself: only which capability
 * the call contributes, a redacted summary and a target identity.
 */
export function classifyToolCallFlow(
	call: FlowToolCall,
	options: FlowClassifierOptions,
): FlowClassification {
	const set = new ObservationSet();
	const downloads: string[] = [];
	const reads: string[] = [];
	let destructive: string | null = null;
	const { toolName, toolInput, artifacts } = call;

	if (toolName === "Bash") {
		const command = commandText(toolInput, artifacts);
		if (command) {
			classifyShellCommand(command, set, downloads, reads, options, 0);
			destructive = destructiveSummary(command);
		}
	} else if (toolName === "Read" || toolName === "Grep" || toolName === "NotebookRead") {
		const paths = new Set<string>(artifactValues(artifacts, "file_path"));
		const direct = stringField(toolInput, ["file_path", "path", "notebook_path"]);
		if (direct) paths.add(direct);
		for (const path of paths) {
			addSensitivePath(set, path, toolName);
			reads.push(path);
		}
	} else if (toolName === "WebFetch") {
		const url = stringField(toolInput, ["url"]) ?? artifactValues(artifacts, "url")[0];
		if (url) {
			addUntrustedFetch(set, url, "WebFetch", options);
			addEgress(set, url, options, "WebFetch", urlCarriesData(url));
		}
	} else if (WEB_SEARCH_TOOL.test(toolName)) {
		set.add({
			cap: "untrusted_content",
			kind: "web_search",
			summary: `${toolName} results`,
			target: `tool:${toolName.toLowerCase()}`,
		});
	} else {
		const mcp = mcpToolIdentity(toolName, toolInput);
		const leaf = mcp ? mcp.tool : toolName;
		if (mcp && !options.trustedMcpServers.includes(mcp.server)) {
			set.add({
				cap: "untrusted_content",
				kind: "mcp_output",
				summary: `MCP ${mcp.server} output`,
				target: `mcp:${mcp.server}`,
			});
		}
		if (WEB_READ_TOOL.test(leaf)) {
			const url = artifactValues(artifacts, "url")[0];
			const destination = url ? classifyDestination(url, options) : null;
			set.add({
				cap: "untrusted_content",
				kind: "web_content",
				summary: `${leaf}${destination ? ` ← ${destination.host}` : ""}`,
				target: destination ? `host:${destination.host}` : `tool:${leaf.toLowerCase()}`,
			});
		}
		if (SEND_TOOL.test(leaf)) {
			set.add({
				cap: "external_comm",
				kind: mcp ? "mcp_send" : "data_upload",
				summary: mcp ? `MCP ${mcp.server}.${leaf} (sends data out)` : `${leaf} (sends data out)`,
				target: mcp ? `mcp-send:${mcp.server}:${leaf.toLowerCase()}` : `tool:${leaf.toLowerCase()}`,
				carriesData: true,
			});
		}
		if (FILE_READ_TOOL.test(leaf)) {
			for (const path of artifactValues(artifacts, "file_path")) {
				addSensitivePath(set, path, leaf);
				reads.push(path);
			}
		}
		// Any URL to an exfiltration sink in any tool input is external communication.
		for (const url of artifactValues(artifacts, "url")) {
			const destination = classifyDestination(url, options);
			if (destination?.sink) addEgress(set, url, options, leaf || toolName, true);
		}
	}

	return {
		observations: set.items,
		destructive: destructive ? bound(destructive) : null,
		downloads: [
			...new Set(downloads.map(normalizeFlowPath).filter((path) => path.length >= 2)),
		].slice(0, MAX_DOWNLOADS_PER_CALL),
		reads: [...new Set(reads.map(normalizeFlowPath).filter((path) => path.length >= 2))].slice(
			0,
			32,
		),
	};
}

/** Whether `path` names `download` or something inside it (downloads may be relative). */
export function pathWithinDownload(path: string, download: string): boolean {
	const p = normalizeFlowPath(path);
	const d = normalizeFlowPath(download);
	if (!p || !d || d === "." || d === "~" || d === "/" || d.length < 2) return false;
	if (p === d || p.startsWith(`${d}/`)) return true;
	if (d.startsWith("/") || d.startsWith("~")) return false;
	return p.endsWith(`/${d}`) || p.includes(`/${d}/`);
}

/** Label used in verdict reasons. */
export function capabilityLabel(cap: FlowCapability): string {
	if (cap === "private_data") return "private data";
	if (cap === "untrusted_content") return "untrusted content";
	return "external communication";
}

/** Exposed for tests and docs: the built-in exfiltration sink list. */
export const TOXIC_FLOW_EXFIL_SINKS: readonly string[] = EXFIL_SINK_DOMAINS;
