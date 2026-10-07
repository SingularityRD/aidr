/**
 * Hardcoded-credential detection for MCP server configuration entries.
 *
 * MCP configs routinely carry credentials (`"env": {"GITHUB_TOKEN": "ghp_..."}`).
 * Writing the literal value into a JSON file that is synced, committed or read by
 * other tools is AIG category mcp-01 (Token Mismanagement & Secret Exposure).
 *
 * Findings identify only the LOCATION of a literal secret (env key, header name,
 * argument flag, URL component) and the kind of token. The value is never
 * returned, logged or hashed into the finding, so the result can be printed and
 * stored safely.
 *
 * A reference that the host resolves at launch (`${GITHUB_TOKEN}`, `$TOKEN`,
 * `${env:TOKEN}`, `${input:token}`, `%TOKEN%`, `op://...`) is the recommended
 * practice and is not reported.
 */

export type McpSecretLocation = "env" | "headers" | "args" | "url";

export type McpSecretKind =
	| "github_token"
	| "gitlab_token"
	| "slack_token"
	| "anthropic_key"
	| "openai_key"
	| "aws_access_key"
	| "google_api_key"
	| "npm_token"
	| "private_key"
	| "bearer_credential"
	| "credential_named_value";

export interface McpSecretFinding {
	location: McpSecretLocation;
	/** Env/header name, argument flag (or `args[i]`), or URL component. Never the value. */
	key: string;
	kind: McpSecretKind;
}

const TOKEN_FORMATS: ReadonlyArray<[McpSecretKind, RegExp]> = [
	["github_token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/],
	["gitlab_token", /\bglpat-[A-Za-z0-9_-]{20,}\b/],
	["slack_token", /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/],
	["anthropic_key", /\bsk-ant-[A-Za-z0-9_-]{20,}/],
	["openai_key", /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/],
	["aws_access_key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
	["google_api_key", /\bAIza[0-9A-Za-z_-]{35}\b/],
	["npm_token", /\bnpm_[A-Za-z0-9]{36}\b/],
	["private_key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
];

/** Names that, by convention, hold a credential. */
const CREDENTIAL_NAME =
	/(?:^|[_-])(?:token|secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|authorization|pat|session[_-]?key|x-api-key)(?:$|[_-])/i;

/** Values the host resolves at launch, or obvious placeholders. */
const REFERENCE_OR_PLACEHOLDER = [
	/^\$\{[^}]+\}$/, // ${VAR}, ${env:VAR}, ${input:id}
	/^\$[A-Za-z_][A-Za-z0-9_]*$/, // $VAR
	/^%[A-Za-z_][A-Za-z0-9_]*%$/, // %VAR%
	/^\{\{[^}]+\}\}$/, // {{secret}}
	/^(?:op|vault|keychain|secret|env):\/\//i, // secret-manager references
	/^<[^>]*>$/, // <your-token>
	/^(?:your[_-]|replace[_-]?me|change[_-]?me|placeholder|example|xxx+|todo|none|null|false|true)/i,
	/^\*+$/,
];

function isReferenceOrPlaceholder(value: string): boolean {
	const trimmed = value.trim();
	if (!trimmed) return true;
	// `Bearer ${TOKEN}` is still a reference.
	const unprefixed = trimmed.replace(/^(?:bearer|token|basic)\s+/i, "");
	return REFERENCE_OR_PLACEHOLDER.some((pattern) => pattern.test(unprefixed));
}

function tokenKind(value: string): McpSecretKind | null {
	for (const [kind, pattern] of TOKEN_FORMATS) if (pattern.test(value)) return kind;
	return null;
}

/** Classify one named value; `null` when it is not a literal credential. */
function classifyNamedValue(name: string, value: string): McpSecretKind | null {
	if (isReferenceOrPlaceholder(value)) return null;
	const known = tokenKind(value);
	if (known) return known;
	if (!CREDENTIAL_NAME.test(name)) return null;
	const unprefixed = value.trim().replace(/^(?:bearer|token|basic)\s+/i, "");
	if (unprefixed.length < 8) return null;
	// `TOKEN_URL=https://...` or `SECRET_FILE=/run/secrets/x` name a location,
	// not a credential.
	if (/^https?:\/\/[^@\s]+$/i.test(unprefixed)) return null;
	if (/^(?:\/|~[\\/]|\.{1,2}[\\/]|[A-Za-z]:[\\/])/.test(unprefixed)) return null;
	return /^(?:bearer|token|basic)\s+/i.test(value.trim())
		? "bearer_credential"
		: "credential_named_value";
}

function stringEntries(value: unknown): Array<[string, string]> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return [];
	return Object.entries(value as Record<string, unknown>).filter(
		(entry): entry is [string, string] => typeof entry[1] === "string",
	);
}

function argFindings(args: readonly string[]): McpSecretFinding[] {
	const findings: McpSecretFinding[] = [];
	for (let i = 0; i < args.length; i++) {
		const arg = args[i] ?? "";
		const flagWithValue = arg.match(/^(--?[A-Za-z][A-Za-z0-9_-]*)=(.*)$/s);
		if (flagWithValue?.[1] && flagWithValue[2] !== undefined) {
			const kind = classifyNamedValue(flagWithValue[1].replace(/^-+/, ""), flagWithValue[2]);
			if (kind) findings.push({ location: "args", key: flagWithValue[1], kind });
			continue;
		}
		const next = args[i + 1];
		if (/^--?[A-Za-z][A-Za-z0-9_-]*$/.test(arg) && next !== undefined && !next.startsWith("-")) {
			const kind = classifyNamedValue(arg.replace(/^-+/, ""), next);
			if (kind) {
				findings.push({ location: "args", key: arg, kind });
				i++;
				continue;
			}
		}
		// A recognisable token anywhere else, e.g. a positional argument.
		const kind = isReferenceOrPlaceholder(arg) ? null : tokenKind(arg);
		if (kind) findings.push({ location: "args", key: `args[${i}]`, kind });
	}
	return findings;
}

function urlFindings(url: string | null): McpSecretFinding[] {
	if (!url) return [];
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return [];
	}
	const findings: McpSecretFinding[] = [];
	if (parsed.password) {
		findings.push({ location: "url", key: "userinfo", kind: "credential_named_value" });
	}
	for (const [name, value] of parsed.searchParams) {
		const kind = classifyNamedValue(name, value);
		if (kind) findings.push({ location: "url", key: `query:${name}`, kind });
	}
	return findings;
}

/**
 * Report literal credentials in an MCP server entry. Inputs are the raw config
 * fields; anything that is not a string map / string array is ignored.
 */
export function detectMcpConfigSecrets(entry: {
	env?: unknown;
	headers?: unknown;
	args?: readonly string[];
	url?: string | null;
}): McpSecretFinding[] {
	const findings: McpSecretFinding[] = [];
	const envSources = Array.isArray(entry.env) ? entry.env : [entry.env];
	for (const source of envSources) {
		for (const [name, value] of stringEntries(source)) {
			const kind = classifyNamedValue(name, value);
			if (kind) findings.push({ location: "env", key: name, kind });
		}
	}
	for (const [name, value] of stringEntries(entry.headers)) {
		const kind = classifyNamedValue(name, value);
		if (kind) findings.push({ location: "headers", key: name, kind });
	}
	findings.push(...argFindings(entry.args ?? []), ...urlFindings(entry.url ?? null));
	return findings;
}
