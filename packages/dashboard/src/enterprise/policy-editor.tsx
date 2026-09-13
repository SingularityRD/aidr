import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { useTeam } from "./team-provider";

interface PolicyDocument {
	version: string | number;
	description?: string;
	default_action: "allow" | "deny" | "ask";
	unknown_action?: "allow" | "deny" | "ask";
	risky_action?: "allow" | "deny" | "ask";
	category_defaults?: Partial<Record<"command" | "file" | "url" | "package" | "output", "allow" | "deny" | "ask">>;
	rules: PolicyRule[];
}

interface PolicyRule {
	name: string;
	condition: {
		mcp_server?: string;
		mcp_tool?: string;
	};
	action: "allow" | "deny" | "ask";
	priority: number;
}

const POLICY_ACTIONS = ["allow", "deny", "ask"] as const;

const DEFAULT_POLICY: PolicyDocument = {
	version: "1.0",
	description: "Team security policy",
	default_action: "ask",
	unknown_action: "ask",
	risky_action: "deny",
	category_defaults: { command: "ask", file: "ask", url: "ask", package: "ask", output: "ask" },
	rules: [
		{
			name: "Block repository deletion",
			condition: { mcp_tool: "github.delete_repository" },
			action: "deny",
			priority: 100,
		},
		{
			name: "Approve filesystem server calls",
			condition: { mcp_server: "filesystem" },
			action: "ask",
			priority: 90,
		},
	],
};

interface PolicyRow {
	id: string;
	content: string;
	updated_at: string;
	updated_by: string | null;
}

interface SaveStatus {
	tone: "success" | "error";
	message: string;
}

// ── YAML helpers ──────────────────────────────────────────────────────
// Kept at module scope: as component-local functions they were recreated on
// every render, which made the load effect re-run forever (each pass issued
// another query and set a fresh parsed object, so the page never settled).

function needsQuoting(value: string): boolean {
	if (value.includes(":") || value.includes("#") || value.includes("\n")) return true;
	if (value.startsWith(" ") || value.endsWith(" ")) return true;
	// A numeric-looking string ("1.0") must stay a string across a save/load
	// round trip, otherwise the parser hands back a number.
	return /^-?\d+(\.\d+)?$/.test(value) || value === "true" || value === "false" || value === "null";
}

function objectToYaml(obj: unknown, indent = 0): string {
	const spaces = " ".repeat(indent);
	if (obj === null || obj === undefined) return "null";
	if (typeof obj === "string") {
		return needsQuoting(obj) ? `"${obj.replace(/"/g, '\\"')}"` : obj;
	}
	if (typeof obj === "number" || typeof obj === "boolean") return String(obj);
	if (Array.isArray(obj)) {
		if (obj.length === 0) return "[]";
		return obj
			.map((item) => `${spaces}- ${objectToYaml(item, indent + 2).trimStart()}`)
			.join("\n");
	}
	if (typeof obj === "object") {
		const entries = Object.entries(obj as Record<string, unknown>);
		if (entries.length === 0) return "{}";
		return entries
			.map(([key, value]) => {
				if (value === undefined) return null;
				if (Array.isArray(value)) {
					// Sequences must be written under their key. Passing indent 0
					// here (the previous behaviour) produced `rules: - name: ...`
					// followed by unindented items, which is not a rules list at all
					// and failed the editor's own validation on the default policy.
					if (value.length === 0) return `${spaces}${key}: []`;
					return `${spaces}${key}:\n${objectToYaml(value, indent + 2)}`;
				}
				if (typeof value === "object" && value !== null) {
					const nested = objectToYaml(value, indent + 2);
					if (nested === "{}") return `${spaces}${key}: {}`;
					return `${spaces}${key}:\n${nested}`;
				}
				return `${spaces}${key}: ${objectToYaml(value, 0)}`;
			})
			.filter(Boolean)
			.join("\n");
	}
	return String(obj);
}

interface YamlLine {
	indent: number;
	text: string;
}

interface ParseState {
	lines: YamlLine[];
	index: number;
}

function splitMappingLine(text: string): { key: string; value: string } {
	const separator = text.endsWith(":") ? text.length - 1 : text.indexOf(": ");
	if (separator < 0) {
		throw new Error(`Line "${text}" is not a "key: value" mapping entry.`);
	}
	const key = text.slice(0, separator).trim();
	if (!key) throw new Error(`Line "${text}" has no key before ":".`);
	return { key, value: text.slice(separator + 1).trim() };
}

function parseValue(value: string): unknown {
	const trimmed = value.trim();
	if (trimmed === "true") return true;
	if (trimmed === "false") return false;
	if (trimmed === "null" || trimmed === "~") return null;
	if (trimmed === "[]") return [];
	if (trimmed === "{}") return {};
	if (/^-?\d+$/.test(trimmed)) return parseInt(trimmed, 10);
	if (/^-?\d+\.\d+$/.test(trimmed)) return parseFloat(trimmed);
	if (
		(trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length > 1) ||
		(trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length > 1)
	) {
		return trimmed.slice(1, -1).replace(/\\"/g, '"');
	}
	return trimmed;
}

/**
 * Parse a block of lines that share `indent` into a mapping or a sequence.
 *
 * The previous implementation tracked a single `currentObject` and never
 * handled a nested mapping inside a sequence item, so `condition:` under a
 * rule became the key `"condition:"` with an empty value and the rendered
 * preview crashed on `rule.condition.tool`.
 */
function parseBlock(state: ParseState, indent: number): unknown {
	const first = state.lines[state.index];
	if (!first) return null;

	if (first.indent === indent && (first.text === "-" || first.text.startsWith("- "))) {
		const items: unknown[] = [];
		while (state.index < state.lines.length) {
			const line = state.lines[state.index];
			if (!line || line.indent !== indent) break;
			if (line.text !== "-" && !line.text.startsWith("- ")) break;

			const rest = line.text === "-" ? "" : line.text.slice(2).trim();
			state.index += 1;

			if (rest === "") {
				const next = state.lines[state.index];
				items.push(next && next.indent > indent ? parseBlock(state, next.indent) : null);
				continue;
			}

			const inlineMapping = /^[^:\s][^:]*:(\s|$)/.test(rest);
			if (!inlineMapping) {
				items.push(parseValue(rest));
				continue;
			}

			// A sequence item that starts a mapping: the first entry is on the
			// "- " line and deeper lines belong to the same mapping.
			const entry: Record<string, unknown> = {};
			const { key, value } = splitMappingLine(rest);
			const childIndent = indent + 2;
			const next = state.lines[state.index];
			if (value === "") {
				entry[key] = next && next.indent > childIndent ? parseBlock(state, next.indent) : null;
			} else {
				entry[key] = parseValue(value);
			}
			while (state.index < state.lines.length) {
				const nested = state.lines[state.index];
				if (!nested || nested.indent <= indent) break;
				if (nested.text === "-" || nested.text.startsWith("- ")) break;
				state.index += 1;
				const nestedEntry = splitMappingLine(nested.text);
				const nestedNext = state.lines[state.index];
				if (nestedEntry.value === "") {
					entry[nestedEntry.key] =
						nestedNext && nestedNext.indent > nested.indent
							? parseBlock(state, nestedNext.indent)
							: null;
				} else {
					entry[nestedEntry.key] = parseValue(nestedEntry.value);
				}
			}
			items.push(entry);
		}
		return items;
	}

	const mapping: Record<string, unknown> = {};
	while (state.index < state.lines.length) {
		const line = state.lines[state.index];
		if (!line || line.indent !== indent) break;
		if (line.text === "-" || line.text.startsWith("- ")) break;
		state.index += 1;
		const { key, value } = splitMappingLine(line.text);
		const next = state.lines[state.index];
		if (value === "") {
			mapping[key] = next && next.indent > indent ? parseBlock(state, next.indent) : null;
		} else {
			mapping[key] = parseValue(value);
		}
	}
	return mapping;
}

function parseYaml(yaml: string): unknown {
	const lines: YamlLine[] = [];
	for (const raw of yaml.split("\n")) {
		const trimmedEnd = raw.replace(/\s+$/, "");
		if (!trimmedEnd.trim()) continue;
		if (trimmedEnd.trim().startsWith("#")) continue;
		const indent = trimmedEnd.search(/\S/);
		if (trimmedEnd.includes("\t")) {
			throw new Error("Tabs are not supported for indentation; use spaces.");
		}
		lines.push({ indent, text: trimmedEnd.trim() });
	}
	if (lines.length === 0) return {};
	return parseBlock({ lines, index: 0 }, lines[0]?.indent ?? 0);
}

function isPolicyAction(value: unknown): value is PolicyDocument["default_action"] {
	return typeof value === "string" && (POLICY_ACTIONS as readonly string[]).includes(value);
}

function unsupportedKey(value: Record<string, unknown>, allowed: readonly string[]): string | null {
	return Object.keys(value).find((key) => !allowed.includes(key)) ?? null;
}

/**
 * Validate the parsed document rather than trusting it. The editor used to
 * declare any text "✓ Valid YAML" and let Save report success, so a policy the
 * engine cannot read was stored as if it were accepted.
 */
function validateDocument(yaml: string): { ok: true; document: PolicyDocument } | { ok: false; message: string } {
	let parsed: unknown;
	try {
		parsed = parseYaml(yaml);
	} catch (err) {
		return { ok: false, message: readErrorMessage(err, "Invalid YAML") };
	}

	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		return { ok: false, message: "The policy must be a mapping with version, default_action and rules." };
	}

	const document = parsed as Record<string, unknown>;
	const unsupportedDocumentField = unsupportedKey(document, ["version", "description", "default_action", "unknown_action", "risky_action", "category_defaults", "rules"]);
	if (unsupportedDocumentField) return { ok: false, message: `Unsupported policy field: ${unsupportedDocumentField}.` };
	if (document.version !== "1.0" && document.version !== 1) {
		return { ok: false, message: "The policy must use supported version 1.0." };
	}
	if (!isPolicyAction(document.default_action)) {
		return {
			ok: false,
			message: 'The policy must set default_action to "allow", "deny" or "ask".',
		};
	}
	for (const key of ["unknown_action", "risky_action"] as const) {
		if (document[key] !== undefined && !isPolicyAction(document[key])) return { ok: false, message: `${key} must be "allow", "deny" or "ask".` };
	}
	if (document.category_defaults !== undefined) {
		if (!document.category_defaults || typeof document.category_defaults !== "object" || Array.isArray(document.category_defaults)) return { ok: false, message: "category_defaults must be a mapping." };
		const defaults = document.category_defaults as Record<string, unknown>;
		const unsupportedCategory = unsupportedKey(defaults, ["command", "file", "url", "package", "output"]);
		if (unsupportedCategory) return { ok: false, message: `Unsupported category default: ${unsupportedCategory}.` };
		for (const [key, value] of Object.entries(defaults)) if (!isPolicyAction(value)) return { ok: false, message: `category_defaults.${key} must be "allow", "deny" or "ask".` };
	}
	if (!Array.isArray(document.rules)) {
		return { ok: false, message: "The policy must declare a rules list." };
	}
	for (const [index, rule] of document.rules.entries()) {
		if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
			return { ok: false, message: `Rule ${index + 1} must be a mapping.` };
		}
		const candidate = rule as Record<string, unknown>;
		const unsupportedRuleField = unsupportedKey(candidate, ["name", "condition", "action", "priority"]);
		if (unsupportedRuleField) return { ok: false, message: `Rule ${index + 1} has unsupported field: ${unsupportedRuleField}.` };
		if (typeof candidate.name !== "string" || candidate.name.trim() === "") {
			return { ok: false, message: `Rule ${index + 1} must have a name.` };
		}
		if (!isPolicyAction(candidate.action)) {
			return {
				ok: false,
				message: `Rule ${index + 1} must set action to "allow", "deny" or "ask".`,
			};
		}
		if (!candidate.condition || typeof candidate.condition !== "object" || Array.isArray(candidate.condition)) {
			return { ok: false, message: `Rule ${index + 1} condition must be a mapping.` };
		}
		const condition = candidate.condition as Record<string, unknown>;
		const unsupportedCondition = unsupportedKey(condition, ["mcp_server", "mcp_tool"]);
		if (unsupportedCondition) return { ok: false, message: `Rule ${index + 1} condition has unsupported field: ${unsupportedCondition}.` };
		if (Number(condition.mcp_server !== undefined) + Number(condition.mcp_tool !== undefined) !== 1) return { ok: false, message: `Rule ${index + 1} condition must contain exactly one of mcp_server or mcp_tool.` };
		if (condition.mcp_server !== undefined && (typeof condition.mcp_server !== "string" || !/^[a-z0-9][a-z0-9._-]{0,79}$/.test(condition.mcp_server))) return { ok: false, message: `Rule ${index + 1} mcp_server must be a lowercase server id.` };
		if (condition.mcp_tool !== undefined && (typeof condition.mcp_tool !== "string" || !/^[a-z0-9][a-z0-9._-]{0,79}\.[a-z0-9][a-z0-9_.-]{0,159}$/.test(condition.mcp_tool))) return { ok: false, message: `Rule ${index + 1} mcp_tool must use lowercase server.tool format.` };
		if (!Number.isInteger(candidate.priority) || Number(candidate.priority) < 0 || Number(candidate.priority) > 1_000) return { ok: false, message: `Rule ${index + 1} priority must be an integer from 0 to 1000.` };
	}

	return { ok: true, document: document as unknown as PolicyDocument };
}

export function PolicyEditor() {
	const { currentTeam, canEditPolicy, isLoading: teamLoading, error: teamError } = useTeam();
	const [policyYaml, setPolicyYaml] = useState("");
	const [parsedPolicy, setParsedPolicy] = useState<PolicyDocument | null>(null);
	const [isValid, setIsValid] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [loadedTeamId, setLoadedTeamId] = useState<string | null>(null);
	const [isSaving, setIsSaving] = useState(false);
	const [saveStatus, setSaveStatus] = useState<SaveStatus | null>(null);

	const teamId = currentTeam?.id ?? null;
	// The editor must not paint before the current team's stored policy has been
	// read: an empty textarea looks like "this team has no policy" and would let
	// a save overwrite a document the user never saw.
	const awaitingPolicy = Boolean(teamId) && loadedTeamId !== teamId;

	const validateAndParse = useCallback((yaml: string): boolean => {
		const validation = validateDocument(yaml);
		if (!validation.ok) {
			setIsValid(false);
			setParsedPolicy(null);
			setError(validation.message);
			return false;
		}
		setParsedPolicy(validation.document);
		setIsValid(true);
		setError(null);
		return true;
	}, []);

	// Load existing policy
	useEffect(() => {
		let cancelled = false;

		async function loadPolicy() {
			if (!teamId) {
				if (!cancelled) {
					setIsLoading(false);
					setLoadedTeamId(null);
				}
				return;
			}

			setIsLoading(true);
			setLoadError(null);

			try {
				const { data, error: loadFailure } = await supabase
					.from("team_policies")
					.select("id, content, updated_at, updated_by")
					.eq("team_id", teamId)
					.order("updated_at", { ascending: false })
					.limit(1)
					.maybeSingle();

				if (loadFailure) throw loadFailure;
				if (cancelled) return;

				const row = data as unknown as PolicyRow | null;
				if (row?.content) {
					setPolicyYaml(row.content);
					validateAndParse(row.content);
				} else {
					const defaultYaml = objectToYaml(DEFAULT_POLICY);
					setPolicyYaml(defaultYaml);
					setParsedPolicy(DEFAULT_POLICY);
					setIsValid(true);
					setError(null);
				}
			} catch (err) {
				if (!cancelled) {
					setLoadError(readErrorMessage(err, "Failed to load policy"));
				}
			} finally {
				if (!cancelled) {
					setIsLoading(false);
					setLoadedTeamId(teamId);
				}
			}
		}

		void loadPolicy();
		return () => {
			cancelled = true;
		};
	}, [teamId, validateAndParse]);

	async function handleSave() {
		if (!currentTeam || !canEditPolicy) return;

		const validation = validateDocument(policyYaml);
		if (!validation.ok) {
			setIsValid(false);
			setError(validation.message);
			setSaveStatus({ tone: "error", message: `Policy was not saved: ${validation.message}` });
			return;
		}
		setIsValid(true);
		setError(null);

		setIsSaving(true);
		setSaveStatus(null);

		try {
			const { data: userData } = await supabase.auth.getUser();
			const updatedBy = userData?.user?.id ?? null;

			// public.team_policies has no unique constraint on team_id, so the
			// previous `upsert(..., { onConflict: "team_id" })` could never
			// succeed ("no unique or exclusion constraint matching the ON
			// CONFLICT specification"). Read the newest row, then update it, or
			// insert one when the team has no policy yet.
			const existing = await supabase
				.from("team_policies")
				.select("id")
				.eq("team_id", currentTeam.id)
				.order("updated_at", { ascending: false })
				.limit(1);
			if (existing.error) throw existing.error;

			const currentRow = ((existing.data ?? []) as unknown as { id: string }[])[0];
			// updated_at is maintained by the team_policies_touch_updated_at
			// trigger on the server; tenant_id must equal team_id (enforced by the
			// team_policies_tenant_matches_team check constraint).
			const body = {
				content: policyYaml,
				tenant_id: currentTeam.id,
				updated_by: updatedBy,
			};

			let stored: { id: string }[] | null = null;
			if (currentRow) {
				const updated = await supabase
					.from("team_policies")
					.update(body)
					.eq("id", currentRow.id)
					.select("id");
				if (updated.error) throw updated.error;
				stored = (updated.data ?? []) as unknown as { id: string }[];
			} else {
				const inserted = await supabase
					.from("team_policies")
					.insert({ ...body, team_id: currentTeam.id })
					.select("id");
				if (inserted.error) throw inserted.error;
				stored = (inserted.data ?? []) as unknown as { id: string }[];
			}

			if (!stored || stored.length === 0) {
				throw new Error(
					"the database did not store any policy row (row-level security rejected the write)",
				);
			}

			setSaveStatus({ tone: "success", message: "Policy saved successfully" });
		} catch (err) {
			setSaveStatus({
				tone: "error",
				message: `Policy was not saved: ${readErrorMessage(err, "unknown error")}`,
			});
		} finally {
			setIsSaving(false);
		}
	}

	function handleReset() {
		const defaultYaml = objectToYaml(DEFAULT_POLICY);
		setPolicyYaml(defaultYaml);
		setSaveStatus(null);
		validateAndParse(defaultYaml);
	}

	if (teamLoading || isLoading || awaitingPolicy) {
		return (
			<div className="card">
				<p className="muted">Loading policy...</p>
			</div>
		);
	}

	if (!currentTeam) {
		return (
			<div className="card">
				<h2>Security Policy Editor</h2>
				{teamError ? (
					<>
						<div className="notice notice-danger" role="alert" aria-live="assertive">
							<b>Your team could not be loaded.</b>
							<div className="muted small" style={{ marginTop: 6 }}>
								{teamError}
							</div>
						</div>
						<p className="muted">
							The editor is unavailable because the team membership query failed — this is not a
							confirmed &quot;no team&quot; state.
						</p>
					</>
				) : (
					<p className="muted">
						You are not part of a team yet, so there is no team policy to author.{" "}
						<Link to="/team">Create or join a team</Link> first.
					</p>
				)}
			</div>
		);
	}

	if (!canEditPolicy) {
		return (
			<div className="card">
				<h2>Security Policy Editor</h2>
				<p className="muted">
					You don&apos;t have permission to edit team policies. A team owner, administrator or member
					can edit the policy for {currentTeam.name}; viewers have read-only access.
				</p>
			</div>
		);
	}

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between">
					<div>
						<h2 style={{ margin: 0 }}>Security Policy Editor</h2>
						<p className="muted" style={{ margin: "6px 0 0" }}>
							Define team-level security rules as code
						</p>
					</div>
					<div className="row">
						<button
							type="button"
							className="button button-secondary"
							onClick={handleReset}
							disabled={isSaving}
						>
							Reset to Default
						</button>
						<button
							type="button"
							className="button"
							onClick={() => void handleSave()}
							disabled={isSaving || !isValid || Boolean(loadError)}
						>
							{isSaving ? "Saving..." : "Save Policy"}
						</button>
					</div>
				</div>
			</div>

			{loadError ? (
				<div className="notice notice-danger" role="alert" aria-live="assertive">
					<b>Stored policy could not be loaded.</b>
					<div className="muted small" style={{ marginTop: 6 }}>
						{loadError}
					</div>
					<div className="muted small" style={{ marginTop: 6 }}>
						The editor is not showing a stored policy because the query failed. Saving is disabled
						until the stored policy can be read, so a failed read cannot overwrite it.
					</div>
				</div>
			) : null}

			<div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
				<div className="card">
					<label className="label" style={{ marginTop: 0 }}>
						Policy (YAML)
						<textarea
							className="input"
							value={policyYaml}
							onChange={(e) => {
								setPolicyYaml(e.target.value);
								setSaveStatus(null);
								validateAndParse(e.target.value);
							}}
							rows={25}
							style={{
								fontFamily: "var(--mono)",
								fontSize: "13px",
								lineHeight: "1.5",
								resize: "vertical",
								background: isValid ? undefined : "rgba(198, 43, 75, 0.08)",
							}}
							spellCheck={false}
						/>
					</label>
					<p className="muted small">
						Supported rule selectors are exact <span className="mono">mcp_server</span> and <span className="mono">mcp_tool</span> values. Category defaults support command, file, url, package and output. Conflicts use priority first, then deny &gt; ask &gt; allow.
					</p>
					<div className="row" style={{ justifyContent: "space-between" }}>
						<span className={`pill ${isValid ? "" : "notice-danger"}`}>
							{isValid ? "✓ Valid policy" : "✗ Invalid policy"}
						</span>
						<span className="muted small">{policyYaml.length} chars</span>
					</div>
				</div>

				<div className="card">
					<h4 style={{ marginTop: 0 }}>Parsed Policy</h4>
					{parsedPolicy ? (
						<div className="mono" style={{ fontSize: "13px", overflow: "auto" }}>
							<div style={{ marginBottom: "12px" }}>
								<strong>Version:</strong> {parsedPolicy.version}
							</div>
							<div style={{ marginBottom: "12px" }}>
								<strong>Default Action:</strong>{" "}
								<span className="pill">{parsedPolicy.default_action}</span>
							</div>
							<div style={{ marginBottom: "12px" }}>
								<strong>Unknown MCP:</strong>{" "}
								<span className="pill">{parsedPolicy.unknown_action ?? "ask"}</span>{" "}
								<strong>Risky MCP:</strong>{" "}
								<span className="pill">{parsedPolicy.risky_action ?? "deny"}</span>
							</div>
							<div style={{ marginBottom: "12px" }}>
								<strong>Rules ({parsedPolicy.rules?.length || 0}):</strong>
							</div>
							{parsedPolicy.rules?.map((rule) => (
								<div
									key={rule.name}
									style={{
										padding: "12px",
										border: "1px solid var(--border)",
										borderRadius: "8px",
										marginBottom: "8px",
									}}
								>
									<div className="row space-between">
										<strong>{rule.name}</strong>
										<span
											className="pill"
											style={{
												background:
													rule.action === "deny"
														? "rgba(198, 43, 75, 0.12)"
														: rule.action === "allow"
															? "rgba(11, 132, 104, 0.12)"
															: "rgba(252, 109, 38, 0.12)",
											}}
										>
											{rule.action}
										</span>
									</div>
									<div className="muted small" style={{ marginTop: "6px" }}>
										Priority: {rule.priority}
										{rule.condition.mcp_server && ` • MCP server: ${rule.condition.mcp_server}`}
										{rule.condition.mcp_tool && ` • MCP tool: ${rule.condition.mcp_tool}`}
									</div>
								</div>
							))}
						</div>
					) : (
						<p className="muted">No valid policy document to preview yet.</p>
					)}
				</div>
			</div>

			{error && (
				<div className="notice notice-danger" role="alert">
					<strong>Policy validation error:</strong> {error}
				</div>
			)}

			{saveStatus && (
				<div
					className={`notice ${saveStatus.tone === "error" ? "notice-danger" : ""}`}
					role={saveStatus.tone === "error" ? "alert" : "status"}
					aria-live="assertive"
				>
					{saveStatus.message}
				</div>
			)}
		</div>
	);
}
