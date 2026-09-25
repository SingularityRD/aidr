/**
 * Summary of the agent permission profile templates shipped with the engine
 * (`packages/core/src/agent-profile-templates.ts`). The dashboard does not
 * depend on the engine package at runtime, so this is a display mirror; the
 * `agent-profiles-panel` test fails if it drifts from the shipped templates.
 */
export type ProfileAction = "allow" | "ask" | "deny";

export const PROFILE_TOOL_CLASSES = [
	"shell",
	"file_read",
	"file_write",
	"web_fetch",
	"mcp",
	"other",
] as const;
export type ProfileToolClass = (typeof PROFILE_TOOL_CLASSES)[number];

export interface ProfileTemplateSummary {
	name: string;
	description: string;
	default: ProfileAction;
	tools: Record<ProfileToolClass, ProfileAction>;
}

export const PROFILE_TEMPLATE_SUMMARIES: readonly ProfileTemplateSummary[] = [
	{
		name: "read-only-reviewer",
		description:
			"Code review: read the workspace and inspect git history. No writes, no network, no MCP tools.",
		default: "deny",
		tools: {
			shell: "allow",
			file_read: "allow",
			file_write: "deny",
			web_fetch: "deny",
			mcp: "deny",
			other: "deny",
		},
	},
	{
		name: "standard-developer",
		description:
			"Everyday development: read and write inside the workspace, run commands and fetch documentation; destructive and privileged commands are denied and MCP tools need approval.",
		default: "ask",
		tools: {
			shell: "allow",
			file_read: "allow",
			file_write: "allow",
			web_fetch: "allow",
			mcp: "ask",
			other: "allow",
		},
	},
	{
		name: "ci-agent",
		description:
			"Unattended CI: build and test inside the workspace, reach package registries only. Nothing asks (no one is there to approve); anything unlisted is denied.",
		default: "deny",
		tools: {
			shell: "allow",
			file_read: "allow",
			file_write: "allow",
			web_fetch: "deny",
			mcp: "deny",
			other: "deny",
		},
	},
	{
		name: "locked-down",
		description:
			"Maximum restriction: read files inside the workspace only. Every command, write, network request and MCP tool is denied.",
		default: "deny",
		tools: {
			shell: "deny",
			file_read: "allow",
			file_write: "deny",
			web_fetch: "deny",
			mcp: "deny",
			other: "deny",
		},
	},
];

/** Stable rule-family identifiers the engine reports as `matched_threat_id`. */
export const PROFILE_CHECK_LABELS: Readonly<Record<string, string>> = {
	"AGENT-PROFILE-TOOL": "Tool not allowed",
	"AGENT-PROFILE-COMMAND": "Command prefix",
	"AGENT-PROFILE-FILE": "File scope",
	"AGENT-PROFILE-NETWORK": "Network destination",
	"AGENT-PROFILE-MCP": "MCP server / tool",
	"AGENT-PROFILE-SELECTION": "Profile assignment",
	"AGENT-PROFILE-INVALID": "Invalid managed profile",
};
