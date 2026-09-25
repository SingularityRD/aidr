/**
 * Shipped agent permission profile templates. Each is a complete, valid
 * profile an operator copies into `agent-profiles.json` (or a signed tenant
 * bundle) and then narrows with `applies_to`.
 *
 * Templates never contain `applies_to`: a template applies to every connector
 * and repository until the operator scopes it.
 */
import type { AgentProfile, AgentProfileDocument } from "./agent-profile.js";

/** Credentials and AIDR's own state: never readable or writable by an agent. */
const SECRET_PATHS = [
	"**/.env",
	"**/.env.local",
	"**/.env.*.local",
	"**/.env.production",
	"*.pem",
	"*.key",
	"*.p12",
	"*.pfx",
	"id_rsa*",
	"id_ecdsa*",
	"id_ed25519*",
	"~/.ssh",
	"~/.aws",
	"~/.azure",
	"~/.gnupg",
	"~/.kube",
	"~/.config/gcloud",
	"~/.docker/config.json",
	"~/.npmrc",
	"~/.pypirc",
	"~/.netrc",
	"~/.git-credentials",
	"~/.singularity-aidr",
];

const readOnlyReviewer: AgentProfile = {
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
	tool_overrides: { TodoWrite: "allow" },
	commands: {
		allow_prefixes: [
			"git status",
			"git diff",
			"git log",
			"git show",
			"git blame",
			"git branch --list",
			"ls",
			"pwd",
			"cat",
			"head",
			"tail",
			"wc",
			"grep",
			"rg",
		],
		deny_prefixes: ["rm", "git push", "git commit", "git reset", "git checkout", "curl", "wget"],
		unmatched: "deny",
	},
	files: { read_roots: ["${workspace}"], deny: SECRET_PATHS, outside_roots: "deny" },
	network: { allow_domains: [], unmatched: "deny" },
};

const standardDeveloper: AgentProfile = {
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
	commands: {
		deny_prefixes: [
			"sudo",
			"su",
			"doas",
			"rm -rf /",
			"rm -rf ~",
			"chmod -R 777",
			"git push --force",
			"git push -f",
			"git clean -fdx",
			"dd",
			"mkfs",
			"shutdown",
			"reboot",
		],
	},
	files: {
		write_roots: ["${workspace}", "/tmp"],
		deny: SECRET_PATHS,
		outside_roots: "ask",
	},
};

const ciAgent: AgentProfile = {
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
	tool_overrides: { TodoWrite: "allow" },
	commands: {
		allow_prefixes: [
			"npm ci",
			"npm test",
			"npm run",
			"pnpm install --frozen-lockfile",
			"pnpm test",
			"pnpm run",
			"pnpm build",
			"yarn install --frozen-lockfile",
			"yarn test",
			"npx tsc",
			"pytest",
			"python -m pytest",
			"go build",
			"go test",
			"cargo build",
			"cargo test",
			"make",
			"git status",
			"git diff",
			"git log",
			"git rev-parse",
			"ls",
			"pwd",
			"cat",
			"mkdir",
			"cp",
			"mv",
		],
		deny_prefixes: [
			"git push",
			"sudo",
			"ssh",
			"scp",
			"curl",
			"wget",
			"npm publish",
			"pnpm publish",
			"yarn publish",
			"docker login",
		],
		unmatched: "deny",
	},
	files: {
		read_roots: ["${workspace}"],
		write_roots: ["${workspace}"],
		deny: [...SECRET_PATHS, "${workspace}/.github/workflows", "${workspace}/.git/config"],
		outside_roots: "deny",
	},
	network: {
		allow_domains: [
			"registry.npmjs.org",
			"registry.yarnpkg.com",
			"pypi.org",
			"files.pythonhosted.org",
			"proxy.golang.org",
			"sum.golang.org",
			"crates.io",
			"static.crates.io",
			"index.crates.io",
		],
		unmatched: "deny",
	},
};

const lockedDown: AgentProfile = {
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
	files: { read_roots: ["${workspace}"], deny: SECRET_PATHS, outside_roots: "deny" },
};

export const AGENT_PROFILE_TEMPLATES: Readonly<Record<string, AgentProfile>> = Object.freeze({
	"read-only-reviewer": readOnlyReviewer,
	"standard-developer": standardDeveloper,
	"ci-agent": ciAgent,
	"locked-down": lockedDown,
});

export const AGENT_PROFILE_TEMPLATE_NAMES = Object.keys(AGENT_PROFILE_TEMPLATES);

/** A complete document containing one template, ready to save and scope. */
export function agentProfileTemplateDocument(name: string): AgentProfileDocument | null {
	const template = AGENT_PROFILE_TEMPLATES[name];
	if (!template) return null;
	return { version: 1, profiles: [structuredClone(template)] };
}
