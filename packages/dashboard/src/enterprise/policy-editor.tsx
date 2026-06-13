import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";
import { useTeam } from "./team-provider";

interface PolicyDocument {
	version: string;
	description?: string;
	default_action: "allow" | "deny" | "ask";
	rules: PolicyRule[];
}

interface PolicyRule {
	name: string;
	condition: {
		tool?: string;
		pattern?: string;
		threat_type?: string;
		confidence_threshold?: number;
	};
	action: "allow" | "deny" | "ask";
	priority: number;
}

const DEFAULT_POLICY: PolicyDocument = {
	version: "1.0",
	description: "Team security policy",
	default_action: "ask",
	rules: [
		{
			name: "Block known malicious URLs",
			condition: {
				threat_type: "malicious_url",
				confidence_threshold: 0.9,
			},
			action: "deny",
			priority: 100,
		},
		{
			name: "Flag suspicious file operations",
			condition: {
				tool: "file_write",
				pattern: "/etc/*|/usr/bin/*|C:\\\\Windows\\\\*",
			},
			action: "ask",
			priority: 90,
		},
	],
};

interface PolicyRow {
	content: string;
	updated_at: string;
	updated_by: string | null;
}

export function PolicyEditor() {
	const { currentTeam, canEditPolicy } = useTeam();
	const [policyYaml, setPolicyYaml] = useState("");
	const [parsedPolicy, setParsedPolicy] = useState<PolicyDocument | null>(null);
	const [isValid, setIsValid] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [isSaving, setIsSaving] = useState(false);
	const [saveStatus, setSaveStatus] = useState<string | null>(null);

	// Load existing policy
	useEffect(() => {
		async function loadPolicy() {
			if (!currentTeam) {
				setIsLoading(false);
				return;
			}

			try {
				const { data, error } = await supabase
					.from("team_policies")
					.select("content, updated_at, updated_by")
					.eq("team_id", currentTeam.id)
					.maybeSingle();

				if (error) throw error;

				const typedData = data as PolicyRow | null;

				if (typedData?.content) {
					const yaml = typedData.content;
					setPolicyYaml(yaml);
					validateAndParse(yaml);
				} else {
					// Set default policy
					const defaultYaml = objectToYaml(DEFAULT_POLICY);
					setPolicyYaml(defaultYaml);
					setParsedPolicy(DEFAULT_POLICY);
				}
			} catch (err) {
				setError(err instanceof Error ? err.message : "Failed to load policy");
			} finally {
				setIsLoading(false);
			}
		}

		void loadPolicy();
	}, [currentTeam?.id, validateAndParse, currentTeam, objectToYaml]);

	function objectToYaml(obj: unknown, indent = 0): string {
		const spaces = " ".repeat(indent);
		if (obj === null || obj === undefined) return "null";
		if (typeof obj === "string") {
			// Quote strings with special characters
			if (obj.includes(":") || obj.includes("#") || obj.includes("\n") || obj.startsWith(" ")) {
				return `"${obj.replace(/"/g, '\\"')}"`;
			}
			return obj;
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
					if (typeof value === "object" && !Array.isArray(value) && value !== null) {
						return `${spaces}${key}:\n${objectToYaml(value, indent + 2)}`;
					}
					return `${spaces}${key}: ${objectToYaml(value, 0)}`;
				})
				.filter(Boolean)
				.join("\n");
		}
		return String(obj);
	}

	function validateAndParse(yaml: string): boolean {
		try {
			const parsed = parseYaml(yaml);
			setParsedPolicy(parsed as PolicyDocument);
			setIsValid(true);
			setError(null);
			return true;
		} catch (err) {
			setIsValid(false);
			setError(err instanceof Error ? err.message : "Invalid YAML");
			return false;
		}
	}

	function parseYaml(yaml: string): unknown {
		const lines = yaml.split("\n");
		const result: Record<string, unknown> = {};
		let _currentKey: string | null = null;
		let currentArray: unknown[] | null = null;
		let currentObject: Record<string, unknown> | null = null;
		let indentLevel = 0;

		for (const line of lines) {
			const trimmed = line.trim();
			if (!trimmed || trimmed.startsWith("#")) continue;

			const spaces = line.search(/\S/);
			const indent = spaces === -1 ? 0 : spaces;

			// Handle array items
			if (trimmed.startsWith("- ")) {
				const value = trimmed.slice(2).trim();
				if (currentArray) {
					if (value.includes(": ")) {
						// Array of objects
						if (!currentObject || indent > indentLevel) {
							currentObject = {};
							currentArray.push(currentObject);
						}
						const [k, ...vParts] = value.split(": ");
						const v = vParts.join(": ").trim();
						if (currentObject && k) {
							currentObject[k] = parseValue(v);
						}
					} else {
						currentArray.push(parseValue(value));
						currentObject = null;
					}
				}
				continue;
			}

			// Handle key-value pairs
			if (trimmed.includes(": ") || trimmed.endsWith(":")) {
				const [key, ...valueParts] = trimmed.split(": ");
				const value = valueParts.join(": ").trim();

				if (indent === 0 && key) {
					_currentKey = key;
					if (value === "") {
						// Could be array or nested object
						result[key] = [];
						currentArray = result[key] as unknown[];
						currentObject = null;
					} else {
						result[key] = parseValue(value);
						currentArray = null;
						currentObject = null;
					}
					indentLevel = indent;
				} else if (currentArray && currentObject && key) {
					// Nested in array object
					currentObject[key] = parseValue(value);
				}
			}
		}

		return result;
	}

	function parseValue(value: string): unknown {
		const trimmed = value.trim();
		if (trimmed === "true") return true;
		if (trimmed === "false") return false;
		if (trimmed === "null") return null;
		if (/^\d+$/.test(trimmed)) return parseInt(trimmed, 10);
		if (/^\d+\.\d+$/.test(trimmed)) return parseFloat(trimmed);
		if (
			(trimmed.startsWith('"') && trimmed.endsWith('"')) ||
			(trimmed.startsWith("'") && trimmed.endsWith("'"))
		) {
			return trimmed.slice(1, -1).replace(/\\"/g, '"');
		}
		return trimmed;
	}

	async function handleSave() {
		if (!currentTeam || !canEditPolicy) return;
		if (!validateAndParse(policyYaml)) return;

		setIsSaving(true);
		setSaveStatus(null);

		try {
			const { data: userData } = await supabase.auth.getUser();
			const upsertData = {
				team_id: currentTeam.id,
				content: policyYaml,
				updated_at: new Date().toISOString(),
				updated_by: userData.user?.id ?? null,
			};

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const { error } = await supabase.from("team_policies").upsert(upsertData as any, {
				onConflict: "team_id",
			});

			if (error) throw error;

			setSaveStatus("Policy saved successfully");
		} catch (err) {
			setSaveStatus(err instanceof Error ? err.message : "Failed to save policy");
		} finally {
			setIsSaving(false);
		}
	}

	function handleReset() {
		const defaultYaml = objectToYaml(DEFAULT_POLICY);
		setPolicyYaml(defaultYaml);
		validateAndParse(defaultYaml);
	}

	if (!canEditPolicy) {
		return (
			<div className="card">
				<p className="muted">You don&apos;t have permission to edit team policies.</p>
			</div>
		);
	}

	if (isLoading) {
		return (
			<div className="card">
				<p className="muted">Loading policy...</p>
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
							disabled={isSaving || !isValid}
						>
							{isSaving ? "Saving..." : "Save Policy"}
						</button>
					</div>
				</div>
			</div>

			<div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
				<div className="card">
					<label className="label" style={{ marginTop: 0 }}>
						Policy (YAML)
						<textarea
							className="input"
							value={policyYaml}
							onChange={(e) => {
								setPolicyYaml(e.target.value);
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
					<div className="row" style={{ justifyContent: "space-between" }}>
						<span className={`pill ${isValid ? "" : "notice-danger"}`}>
							{isValid ? "✓ Valid YAML" : "✗ Invalid YAML"}
						</span>
						<span className="muted small">{policyYaml.length} chars</span>
					</div>
				</div>

				<div className="card">
					<h4 style={{ marginTop: 0 }}>Parsed Policy</h4>
					{parsedPolicy && (
						<div className="mono" style={{ fontSize: "13px", overflow: "auto" }}>
							<div style={{ marginBottom: "12px" }}>
								<strong>Version:</strong> {parsedPolicy.version}
							</div>
							<div style={{ marginBottom: "12px" }}>
								<strong>Default Action:</strong>{" "}
								<span className="pill">{parsedPolicy.default_action}</span>
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
										{rule.condition.tool && ` • Tool: ${rule.condition.tool}`}
										{rule.condition.threat_type && ` • Threat: ${rule.condition.threat_type}`}
										{rule.condition.confidence_threshold &&
											` • Confidence > ${rule.condition.confidence_threshold}`}
									</div>
								</div>
							))}
						</div>
					)}
				</div>
			</div>

			{error && (
				<div className="notice notice-danger">
					<strong>Parse Error:</strong> {error}
				</div>
			)}

			{saveStatus && (
				<div
					className={`notice ${saveStatus.includes("Failed") || saveStatus.includes("error") ? "notice-danger" : ""}`}
				>
					{saveStatus}
				</div>
			)}
		</div>
	);
}
