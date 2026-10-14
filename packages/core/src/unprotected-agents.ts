/**
 * AI coding tools on this computer that Singularity AIDR has NO connector for.
 *
 * Their commands, file changes and web requests are not inspected at all, so
 * every surface that reports protection (`aidr status`, `aidr coverage`, the
 * session banner, the posture upload) names them as "unprotected" instead of
 * staying silent. Detection only looks for files and directories the tools
 * create and for their executables on PATH; nothing is executed and no file
 * content is read. A tool that was installed and removed may still leave a
 * directory behind, so a hit means "probably present", which is the right
 * direction for a coverage warning.
 */

import { existsSync, readdirSync } from "node:fs";
import { delimiter, join } from "node:path";

export const UNSUPPORTED_AI_TOOL_IDS = [
	"windsurf",
	"jetbrains-ai",
	"cline",
	"roo-code",
	"copilot-cli",
	"gemini-cli",
	"aider",
	"amazon-q",
	"kiro",
	"zed",
] as const;
type UnsupportedAiToolId = (typeof UNSUPPORTED_AI_TOOL_IDS)[number];

/** Product names; not translated. */
const UNSUPPORTED_AI_TOOL_LABELS: Readonly<Record<UnsupportedAiToolId, string>> = {
	windsurf: "Windsurf",
	"jetbrains-ai": "JetBrains AI Assistant / Junie",
	cline: "Cline",
	"roo-code": "Roo Code",
	"copilot-cli": "GitHub Copilot CLI",
	"gemini-cli": "Gemini CLI",
	aider: "Aider",
	"amazon-q": "Amazon Q Developer",
	kiro: "Kiro",
	zed: "Zed",
};

export interface UnprotectedAiTool {
	id: UnsupportedAiToolId;
	label: string;
	/** What was found: a path or `PATH:<name>`. Local only; never uploaded. */
	evidence: string[];
}

export interface UnprotectedAiToolOptions {
	home: string;
	env?: Record<string, string | undefined>;
	platform?: NodeJS.Platform;
	/** Overridable for tests. */
	exists?: (path: string) => boolean;
	listDir?: (path: string) => string[];
}

interface ToolSignature {
	id: UnsupportedAiToolId;
	/** Paths relative to the home directory. */
	homePaths?: string[];
	/** Paths relative to %APPDATA% / %LOCALAPPDATA% (Windows) or ~/.config, ~/.local/share. */
	appPaths?: string[];
	/** Executable names looked up on PATH (PATHEXT variants on Windows). */
	binaries?: string[];
	/** Editor extension id prefixes (VS Code, Cursor, Windsurf, VS Code Server). */
	extensionPrefixes?: string[];
	/** JetBrains plugin directory prefixes. */
	jetbrainsPlugins?: string[];
}

const SIGNATURES: readonly ToolSignature[] = [
	{
		id: "windsurf",
		homePaths: [".codeium/windsurf", ".windsurf"],
		appPaths: ["Windsurf"],
		binaries: ["windsurf"],
	},
	{ id: "jetbrains-ai", homePaths: [".junie"], jetbrainsPlugins: ["ml-llm", "junie"] },
	{ id: "cline", homePaths: [".cline"], extensionPrefixes: ["saoudrizwan.claude-dev-"] },
	{ id: "roo-code", homePaths: [".roo"], extensionPrefixes: ["rooveterinaryinc.roo-cline-"] },
	{ id: "copilot-cli", homePaths: [".copilot"], binaries: ["copilot"] },
	{ id: "gemini-cli", homePaths: [".gemini"], binaries: ["gemini"] },
	{ id: "aider", homePaths: [".aider.conf.yml", ".aider"], binaries: ["aider"] },
	{ id: "amazon-q", homePaths: [".aws/amazonq"], binaries: ["qchat"] },
	{ id: "kiro", homePaths: [".kiro"], appPaths: ["Kiro"], binaries: ["kiro", "kiro-cli"] },
	{
		id: "zed",
		homePaths: [".config/zed", ".local/share/zed"],
		appPaths: ["Zed"],
		binaries: ["zed", "zeditor"],
	},
];

const EDITOR_EXTENSION_DIRS = [
	".vscode/extensions",
	".vscode-server/extensions",
	".cursor/extensions",
	".windsurf/extensions",
];

function safeList(listDir: (path: string) => string[], path: string): string[] {
	try {
		return listDir(path);
	} catch {
		return [];
	}
}

function appRoots(home: string, env: Record<string, string | undefined>, win: boolean): string[] {
	if (win) {
		return [
			env.APPDATA,
			env.LOCALAPPDATA,
			env.LOCALAPPDATA && join(env.LOCALAPPDATA, "Programs"),
		].filter((value): value is string => typeof value === "string" && value.length > 0);
	}
	return [join(home, ".config"), join(home, ".local", "share")];
}

function onPath(
	name: string,
	env: Record<string, string | undefined>,
	win: boolean,
	exists: (path: string) => boolean,
): string | null {
	const dirs = (env.PATH ?? env.Path ?? "").split(win ? ";" : delimiter).filter(Boolean);
	const extensions = win
		? (env.PATHEXT ?? ".EXE;.CMD;.BAT")
				.split(";")
				.filter(Boolean)
				.map((ext) => ext.toLowerCase())
		: [""];
	for (const dir of dirs) {
		for (const ext of extensions) {
			const candidate = join(dir, `${name}${ext}`);
			if (exists(candidate)) return candidate;
		}
	}
	return null;
}

/** JetBrains plugin directories, one per installed IDE version. */
function jetbrainsPluginDirs(
	home: string,
	env: Record<string, string | undefined>,
	win: boolean,
	listDir: (path: string) => string[],
): string[] {
	const roots = win
		? [env.APPDATA, env.LOCALAPPDATA]
				.filter((value): value is string => typeof value === "string" && value.length > 0)
				.map((root) => join(root, "JetBrains"))
		: [join(home, ".local", "share", "JetBrains"), join(home, ".config", "JetBrains")];
	const dirs: string[] = [];
	for (const root of roots) {
		for (const product of safeList(listDir, root)) {
			dirs.push(join(root, product), join(root, product, "plugins"));
		}
	}
	return dirs;
}

/** AI coding tools found on this computer that AIDR does not protect. Never throws. */
export function detectUnprotectedAiTools(options: UnprotectedAiToolOptions): UnprotectedAiTool[] {
	const env = options.env ?? {};
	const win = (options.platform ?? process.platform) === "win32";
	const exists = options.exists ?? existsSync;
	const listDir = options.listDir ?? ((path: string) => readdirSync(path));
	const home = options.home;
	const roots = appRoots(home, env, win);
	const extensionEntries = EDITOR_EXTENSION_DIRS.map((dir) => ({
		dir: join(home, dir),
		names: safeList(listDir, join(home, dir)).map((name) => name.toLowerCase()),
	}));
	let pluginDirs: string[] | null = null;
	const found: UnprotectedAiTool[] = [];
	for (const signature of SIGNATURES) {
		const evidence: string[] = [];
		try {
			for (const relative of signature.homePaths ?? []) {
				const path = join(home, ...relative.split("/"));
				if (exists(path)) evidence.push(path);
			}
			for (const relative of signature.appPaths ?? []) {
				for (const root of roots) {
					const path = join(root, relative);
					if (exists(path)) evidence.push(path);
				}
			}
			for (const binary of signature.binaries ?? []) {
				const hit = onPath(binary, env, win, exists);
				if (hit) evidence.push(`PATH:${binary}`);
			}
			for (const prefix of signature.extensionPrefixes ?? []) {
				for (const entry of extensionEntries) {
					const name = entry.names.find((candidate) => candidate.startsWith(prefix));
					if (name) evidence.push(join(entry.dir, name));
				}
			}
			if (signature.jetbrainsPlugins) {
				pluginDirs ??= jetbrainsPluginDirs(home, env, win, listDir);
				for (const dir of pluginDirs) {
					const name = safeList(listDir, dir).find((candidate) =>
						signature.jetbrainsPlugins?.some((prefix) =>
							candidate.toLowerCase().startsWith(prefix),
						),
					);
					if (name) evidence.push(join(dir, name));
				}
			}
		} catch {
			// One unreadable location never hides the other tools.
		}
		if (evidence.length > 0) {
			found.push({
				id: signature.id,
				label: UNSUPPORTED_AI_TOOL_LABELS[signature.id],
				evidence: [...new Set(evidence)],
			});
		}
	}
	return found;
}
