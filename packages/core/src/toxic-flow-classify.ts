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
 * Which paths, commands, executables, hosts and tool names count is data, not
 * code: `threats/flow/capabilities.yaml` (see `toxic-flow-capabilities.ts`),
 * passed in as `options.patterns` or taken from the core's embedded copy.
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

import { isProjectEnvPathLexical } from "./project-env.js";
import { redactTelemetryString } from "./telemetry-redaction.js";
import {
	DEFAULT_FLOW_CAPABILITIES,
	type FlowCapabilityPatterns,
	type SensitivePathPattern,
} from "./toxic-flow-capabilities.js";
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
	/**
	 * Capability patterns (`threats/flow/capabilities.yaml`); the embedded copy of
	 * the shipped file when omitted.
	 */
	patterns?: FlowCapabilityPatterns;
	/** Absolute working directory of the session; groups the project's `.env` files. */
	workingDirectory?: string;
}

export interface FlowToolCall {
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: readonly Artifact[];
}

const MAX_SUMMARY_CHARS = 96;
const MAX_OBSERVATIONS = 24;
const MAX_DOWNLOADS_PER_CALL = 8;

/** Options with the capability patterns resolved (the file's, or the embedded defaults). */
type ResolvedOptions = FlowClassifierOptions & { patterns: FlowCapabilityPatterns };

// ── Helpers ────────────────────────────────────────────────────────

function bound(text: string): string {
	const single = text.replace(/[\r\n\t]+/g, " ").replace(/[\u0000-\u001f\u007f]/g, "");
	const redacted = redactTelemetryString(single, MAX_SUMMARY_CHARS);
	return redacted;
}

/** Collapse home-directory spellings so `~/.aws/x`, `$HOME/.aws/x` and `/home/<user>/.aws/x` agree. */
export function normalizeFlowPath(raw: string): string {
	let path = raw.trim().replace(/^["'`]+|["'`]+$/g, "");
	path = path.replace(
		/^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:(?:USERPROFILE|HOME))(?=[\\/]|$)/i,
		"~",
	);
	path = path.replace(/^\/(?:home|Users)\/[^\\/]+(?=[\\/]|$)/, "~");
	path = path.replace(/^[A-Za-z]:\\Users\\[^\\]+(?=\\|$)/, "~");
	path = path.replace(/\\/g, "/");
	path = path.replace(/^\.\/+/, "");
	path = path.replace(/\/+$/, "");
	return path;
}

function sensitivePathRule(
	path: string,
	patterns: FlowCapabilityPatterns,
): SensitivePathPattern | null {
	const normalized = normalizeFlowPath(path);
	if (!normalized || normalized.length > 1024) return null;
	for (const rule of patterns.sensitivePaths) {
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

function isExfilSink(url: string, host: string, patterns: FlowCapabilityPatterns): boolean {
	const lowered = url.toLowerCase();
	for (const sink of patterns.exfilSinks) {
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
function urlCarriesData(url: string): boolean {
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

function classifyDestination(url: string, options: ResolvedOptions): Destination | null {
	const host = hostOf(url);
	if (!host) return null;
	return {
		host,
		local: isLocalHost(host),
		sink: isExfilSink(url, host, options.patterns),
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

/** Index of the executable word, skipping `sudo`, `env A=B`, `timeout 5` and the like. */
function commandIndex(words: string[], prefixes: ReadonlySet<string>): number {
	let i = 0;
	while (i < words.length) {
		const word = words[i] as string;
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) {
			i += 1;
			continue;
		}
		const base = basename(word);
		if (prefixes.has(base)) {
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

function addSensitivePath(
	set: ObservationSet,
	path: string,
	verb: string,
	options: Pick<ResolvedOptions, "patterns" | "workingDirectory">,
): void {
	const rule = sensitivePathRule(path, options.patterns);
	if (!rule) return;
	const normalized = normalizeFlowPath(path);
	// All environment files of the session's project are one credential store
	// for the bulk-access count (docs/project-env-files.md); the read is still
	// secret-grade material for exfiltration chains.
	const projectEnv = isProjectEnvPathLexical(path, options.workingDirectory);
	set.add({
		cap: "private_data",
		kind: rule.kind,
		summary: `${verb} ${normalized} (${projectEnv ? "project environment file" : rule.label})`,
		target: projectEnv ? "project-env" : `path:${normalized}`,
		secret: rule.secret,
	});
}

function addEgress(
	set: ObservationSet,
	url: string,
	options: ResolvedOptions,
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
	options: ResolvedOptions,
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

/**
 * Local file paths an HTTP client sends as the request body, so a credential
 * file uploaded in the same call (`wget --post-file=.env`, `curl -T ~/.ssh/id_rsa`,
 * `curl -d @.env`, `curl -F f=@creds.json`, PowerShell `-InFile`) is seen as a
 * secret read, not only as an egress. `@-`/`@/dev/stdin` and inline values are
 * ignored; only a referenced file path is returned.
 */
function uploadedLocalFiles(words: string[]): string[] {
	const files: string[] = [];
	const addFileArg = (value: string | undefined): void => {
		if (!value) return;
		const path = value.startsWith("@") ? value.slice(1) : value;
		const bare = path.replace(/^["']|["']$/g, "");
		if (bare && bare !== "-" && !/^\/dev\/(?:stdin|fd)/.test(bare) && !/^[a-z]+:\/\//i.test(bare)) {
			files.push(bare);
		}
	};
	for (let i = 0; i < words.length; i += 1) {
		const word = words[i] as string;
		// `--upload-file=FILE`, `--post-file=FILE`, `--data=@FILE`, `--data-binary @FILE`.
		const long =
			/^--(upload-file|post-file|data(?:-binary|-raw|-urlencode)?|form|InFile)(?:=(.*))?$/i.exec(
				word,
			);
		if (long) {
			const value = long[2] !== undefined ? long[2] : words[i + 1];
			if (/^(?:data|form)/i.test(long[1] as string)) {
				// Only the `@file` / `field=@file` forms reference a file.
				const at = value?.includes("@") ? value.slice(value.indexOf("@") + 1) : undefined;
				addFileArg(at);
			} else {
				addFileArg(value);
			}
			continue;
		}
		// Short flags that take a file: `-T FILE`, `-d @FILE`, `-F field=@FILE`.
		const short = /^-([a-zA-Z]*)([dFT])(.*)$/.exec(word);
		if (short && !word.startsWith("--")) {
			const inline = short[3];
			const value = inline && inline.length > 0 ? inline : words[i + 1];
			if (short[2] === "T") addFileArg(value);
			else if (value?.includes("@")) addFileArg(value.slice(value.indexOf("@") + 1));
		}
	}
	return files;
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
	options: ResolvedOptions;
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

/**
 * Files read inside a command substitution that feeds this stage's body, e.g.
 * `curl -d "$(cat ~/.aws/credentials)"` or `` wget --post-data=`head ~/.ssh/id_rsa` ``.
 * `uploadedLocalFiles` handles `@file`/`-T file`; this handles the substitution
 * form, so the read is seen as a secret in the same call and the egress denies.
 */
const SUBSTITUTION_FILE_READ =
	/(?:\$\(|`|<\()\s*(?:[^)`]{0,80}\|\s*)?(?:cat|head|tail|less|more|xxd|base64|openssl|type|Get-Content|gc)\s+(?:-\S+\s+){0,3}["']?([^\s"'`)|]{1,200})/gi;

function substitutionSecretReads(
	text: string,
	set: ObservationSet,
	via: string,
	options: Pick<ResolvedOptions, "patterns" | "workingDirectory">,
): void {
	SUBSTITUTION_FILE_READ.lastIndex = 0;
	let found = 0;
	for (
		let m = SUBSTITUTION_FILE_READ.exec(text);
		m !== null && found < 8;
		m = SUBSTITUTION_FILE_READ.exec(text)
	) {
		found += 1;
		if (m[1]) addSensitivePath(set, m[1], via, options);
	}
}

function handleHttpClient(ctx: StageContext): boolean {
	const { exe, args, stage, set, options } = ctx;
	// A request carries data when it has a body/upload or piped stdin. A `$( … )`
	// substitution elsewhere in the command (a cache-busting path, a header) does
	// NOT by itself make a GET an upload; a substitution inside the URL does (it
	// can place a secret in the query), and that is checked per-URL below. A plain
	// read-only GET (health check, docs fetch) therefore stays `network_egress`,
	// not `data_upload`, so it cannot complete an exfiltration chain.
	const carries = curlCarriesData(args) || stage.hasInput;
	let urls = urlsIn(stage.text);
	if (urls.length === 0) {
		const bare = args.find(
			(arg) => !arg.startsWith("-") && /^[\w-]+(?:\.[\w-]+)+(?::\d+)?(?:\/|$)/.test(arg),
		);
		if (bare) urls = [`https://${bare}`];
	}
	for (const url of urls) {
		addEgress(set, url, options, exe, carries || urlCarriesData(url) || HAS_SUBSTITUTION.test(url));
		const target = exe === "curl" || exe === "wget" ? httpDownloadTarget(exe, args, url) : "stdout";
		if (target === "stdout") addUntrustedFetch(set, url, exe, options);
		else if (!classifyDestination(url, options)?.local) ctx.downloads.push(target);
	}
	// A credential file sent as the request body is a secret read in this call.
	for (const file of uploadedLocalFiles(args)) addSensitivePath(set, file, exe, options);
	substitutionSecretReads(stage.text, set, exe, options);
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
		for (const source of operands.slice(0, -1))
			addSensitivePath(ctx.set, source, ctx.exe, ctx.options);
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

/**
 * `tftp`/`ftp` were not classified at all, so `tftp HOST -c put .env` passed as
 * a clean allow. A `put` subcommand/operand uploads (carries data); the first
 * non-flag, non-`put/get` operand is the host. A `put` of a credential file is
 * recorded as a secret read in this call too, so it denies as a one-shot exfil.
 */
function handleFtpPut(ctx: StageContext): boolean {
	const operands = ctx.args.filter((arg) => !arg.startsWith("-"));
	const host = operands.find((arg) => !/^(?:put|get|mput|mget)$/i.test(arg));
	const putIndex = ctx.args.findIndex((arg) => /^(?:put|mput)$/i.test(arg));
	const uploads = putIndex >= 0;
	if (host) {
		if (uploads || ctx.stage.hasInput) {
			addRemoteUpload(ctx.set, ctx.exe, host, "file transfer");
		} else {
			addEgress(ctx.set, `ftp://${host.replace(/^[a-z]+:\/\//i, "")}`, ctx.options, ctx.exe, false);
		}
	}
	if (uploads) {
		for (const file of ctx.args.slice(putIndex + 1).filter((arg) => !arg.startsWith("-"))) {
			addSensitivePath(ctx.set, file, ctx.exe, ctx.options);
		}
	}
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
		// `git -c remote.origin.pushurl=https://elsewhere push origin` keeps the
		// trusted remote's name but sends to wherever the override points.
		const redirected = args
			.slice(0, pushIndex)
			.some((arg, i, all) => all[i - 1] === "-c" && /^remote\.[^=]+\.(?:push)?url=/i.test(arg));
		if (remote && (redirected || !options.trustedGitRemotes.includes(remote))) {
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
	if (!ctx.options.patterns.interpreterNetworkApi.test(code)) return false;
	const carries = ctx.options.patterns.interpreterPayloadHint.test(code) || ctx.stage.hasInput;
	for (const url of urlsIn(code)) {
		addEgress(ctx.set, url, ctx.options, `${exe} one-liner`, carries || urlCarriesData(url));
		addUntrustedFetch(ctx.set, url, `${exe} one-liner`, ctx.options);
	}
	return false;
}

function stageHandler(
	exe: string,
	depth: number,
	patterns: FlowCapabilityPatterns,
): ((ctx: StageContext) => boolean) | null {
	const executables = patterns.executables;
	if ((executables.shells.has(exe) || exe === "eval") && depth < 2) return handleNestedShell;
	if (executables.httpClients.has(exe)) return handleHttpClient;
	if (executables.rawSocketClients.has(exe)) return handleRawSocket;
	if (executables.copyClients.has(exe)) return handleCopyClient;
	if (executables.mailClients.has(exe)) return handleMail;
	if (executables.dnsClients.has(exe)) return handleDns;
	if (executables.interpreters.has(exe)) return handleInterpreter;
	if (exe === "ssh") return handleSsh;
	if (exe === "tftp" || exe === "ftp" || exe === "atftp") return handleFtpPut;
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
	options: ResolvedOptions,
	depth: number,
): boolean {
	const index = commandIndex(stage.words, options.patterns.commandPrefixes);
	if (index < 0) return false;
	const executable = stage.words[index] as string;
	const exe = basename(executable);
	// Executing a local file (`./x.sh`) reads it.
	if (/^\.{0,2}\//.test(executable)) reads.push(executable);
	const handler = stageHandler(exe, depth, options.patterns);
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

/** Windows path spellings in raw command text (drive, UNC-free home variables, `~\`). */
const WINDOWS_PATH =
	/(?:[A-Za-z]:|~|\$env:(?:USERPROFILE|HOMEPATH|HOME|APPDATA|LOCALAPPDATA)|%(?:USERPROFILE|HOMEPATH|APPDATA|LOCALAPPDATA)%)\\[^\s"'|;,()<>`]{1,1000}/gi;

function windowsPathsIn(text: string): string[] {
	if (!text.includes("\\")) return [];
	return [...text.matchAll(WINDOWS_PATH)].map((match) => match[0].replace(/^@/, ""));
}

function classifyShellCommand(
	command: string,
	set: ObservationSet,
	downloads: string[],
	reads: string[],
	options: ResolvedOptions,
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
					addSensitivePath(set, candidate, "shell access to", options);
					if (!transfer && !candidate.startsWith("-")) reads.push(candidate);
				}
			});
			// POSIX word splitting reads `\` as an escape, so a Windows path
			// (`C:\Users\user\.ssh\id_rsa`, `$env:USERPROFILE\.aws\credentials`)
			// loses its separators above. Check those spellings from the raw text.
			for (const path of windowsPathsIn(stage.text)) {
				addSensitivePath(set, path, "shell access to", options);
			}
		}
	}
	for (const rule of options.patterns.credentialCommands) {
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

function isBroadDeleteTarget(target: string, patterns: FlowCapabilityPatterns): boolean {
	const t = target.replace(/^["']|["']$/g, "");
	return (
		patterns.broadDeleteTargets.has(t) ||
		patterns.broadDeletePatterns.some((pattern) => pattern.test(t))
	);
}

function destructiveSummary(command: string, patterns: FlowCapabilityPatterns): string | null {
	for (const pipeline of parseStages(command)) {
		for (const stage of pipeline) {
			const index = commandIndex(stage.words, patterns.commandPrefixes);
			if (index < 0) continue;
			const exe = basename(stage.words[index] as string);
			if (exe === "rm") {
				const args = stage.words.slice(index + 1);
				const recursive = args.some((arg) => /^-[a-zA-Z]*[rR]/.test(arg) || arg === "--recursive");
				const broad = args
					.filter((arg) => !arg.startsWith("-"))
					.find((arg) => isBroadDeleteTarget(arg, patterns));
				if (recursive && broad) return `rm -r ${normalizeFlowPath(broad) || broad}`;
			}
		}
	}
	for (const rule of patterns.destructiveCommands) {
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
function mcpToolIdentity(
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
	classifierOptions: FlowClassifierOptions,
): FlowClassification {
	const patterns = classifierOptions.patterns ?? DEFAULT_FLOW_CAPABILITIES;
	const options: ResolvedOptions = { ...classifierOptions, patterns };
	const set = new ObservationSet();
	const downloads: string[] = [];
	const reads: string[] = [];
	let destructive: string | null = null;
	const { toolName, toolInput, artifacts } = call;

	if (toolName === "Bash") {
		const command = commandText(toolInput, artifacts);
		if (command) {
			classifyShellCommand(command, set, downloads, reads, options, 0);
			destructive = destructiveSummary(command, patterns);
		}
	} else if (toolName === "Read" || toolName === "Grep" || toolName === "NotebookRead") {
		const paths = new Set<string>(artifactValues(artifacts, "file_path"));
		const direct = stringField(toolInput, ["file_path", "path", "notebook_path"]);
		if (direct) paths.add(direct);
		for (const path of paths) {
			addSensitivePath(set, path, toolName, options);
			reads.push(path);
		}
	} else if (toolName === "WebFetch") {
		const url = stringField(toolInput, ["url"]) ?? artifactValues(artifacts, "url")[0];
		if (url) {
			addUntrustedFetch(set, url, "WebFetch", options);
			addEgress(set, url, options, "WebFetch", urlCarriesData(url));
		}
	} else if (patterns.toolNames.webSearch.test(toolName)) {
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
		if (patterns.toolNames.webRead.test(leaf)) {
			const url = artifactValues(artifacts, "url")[0];
			const destination = url ? classifyDestination(url, options) : null;
			set.add({
				cap: "untrusted_content",
				kind: "web_content",
				summary: `${leaf}${destination ? ` ← ${destination.host}` : ""}`,
				target: destination ? `host:${destination.host}` : `tool:${leaf.toLowerCase()}`,
			});
		}
		if (patterns.toolNames.send.test(leaf)) {
			set.add({
				cap: "external_comm",
				kind: mcp ? "mcp_send" : "data_upload",
				summary: mcp ? `MCP ${mcp.server}.${leaf} (sends data out)` : `${leaf} (sends data out)`,
				target: mcp ? `mcp-send:${mcp.server}:${leaf.toLowerCase()}` : `tool:${leaf.toLowerCase()}`,
				carriesData: true,
			});
		}
		if (patterns.toolNames.fileRead.test(leaf)) {
			for (const path of artifactValues(artifacts, "file_path")) {
				addSensitivePath(set, path, leaf, options);
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

/** Exposed for tests and docs: the shipped exfiltration sink list. */
export const TOXIC_FLOW_EXFIL_SINKS: readonly string[] = DEFAULT_FLOW_CAPABILITIES.exfilSinks;
