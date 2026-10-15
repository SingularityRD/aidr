/**
 * The developer's own project `.env` files (D11).
 *
 * Policy, documented in docs/project-env-files.md:
 *
 * - A *project environment file* is a `.env` or `.env.<name>` file (template
 *   names such as `.env.example` excluded) that lies inside the session's
 *   working directory: a relative path with no `..` escape and no shell
 *   expansion, or an absolute path under that directory. A working directory
 *   that is the filesystem root or the home directory is not a project, so
 *   nothing qualifies there.
 * - Reading one into the agent's context (`cat .env`, the Read tool) is
 *   treated like loading it (`source .env`, `dotenv`, `printenv`): no per-call
 *   prompt in balanced/relaxed. Paranoid sensitivity, or
 *   `project_env_reads: "ask"`, keeps the prompt.
 * - The read is still recorded as secret-grade private data in the session
 *   flow, so any later (or same-call) egress that carries data is an
 *   `exfil_chain` finding. `.env` files outside the working directory,
 *   `~/.aws`, `~/.ssh` and every other credential store are unaffected.
 * - All of a project's environment files count as ONE credential store toward
 *   the session's bulk-sensitive-access threshold, so `.env`, `.env.local` and
 *   `.env.test` of one project no longer exhaust it.
 */

import { lstatSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, isAbsolute, parse, relative, resolve } from "node:path";
import type { Artifact, Config, HeuristicMatch } from "./types.js";

/** `.env` and `.env.<name>`; template names never hold live secrets. */
const ENV_FILE_NAME = /^\.env(?:\.(?!(?:example|sample|template|dist|defaults?)$)[\w.-]{1,40})?$/i;

/** Rules whose only job here is "a secret file is being read". */
const PROJECT_ENV_READ_RULES = new Set(["CLT-CRED-004", "CLT-FILE-008", "LLM-FILE-001"]);

/** Shell expansion or globbing: the path the shell reads is not the one written. */
const UNRESOLVED = /[$~%*?`{}[\]]/;

/** A command that changes directory first: its relative paths are not under the session cwd. */
const DIRECTORY_CHANGE =
	/(?:^|[\s;&|(){}])(?:cd|chdir|pushd|popd|sl|Set-Location|Push-Location)(?=$|[\s;&|)])/i;

/** Shell words, without quotes and operators. */
const SHELL_TOKEN = /[^\s"'`;|&()<>=]+/g;

function samePathCase(path: string): string {
	return process.platform === "win32" ? path.toLowerCase() : path;
}

function within(root: string, path: string): boolean {
	const rel = relative(samePathCase(root), samePathCase(path));
	return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/** A working directory that is a real project: not the filesystem root, not the home directory. */
function projectRoot(workingDirectory: string | undefined): string | null {
	if (!workingDirectory || !isAbsolute(workingDirectory)) return null;
	const root = resolve(workingDirectory);
	if (root === parse(root).root) return null;
	if (samePathCase(root) === samePathCase(resolve(homedir()))) return null;
	return root;
}

/**
 * Lexical check only (no filesystem access): `path` names a project
 * environment file inside `workingDirectory`. Used to group flow targets.
 */
export function isProjectEnvPathLexical(
	path: string,
	workingDirectory: string | undefined,
): boolean {
	const root = projectRoot(workingDirectory);
	if (!root) return false;
	const trimmed = path.trim();
	if (!trimmed || UNRESOLVED.test(trimmed)) return false;
	if (!ENV_FILE_NAME.test(basename(trimmed.replace(/\\/g, "/")))) return false;
	return within(root, resolve(root, trimmed));
}

/**
 * Lexical check plus symlink resolution: a project `.env` that is a link to a
 * file outside the project (for example to `~/.aws/credentials`) is not a
 * project environment file. A missing file qualifies (there is nothing to
 * read); any other resolution error does not.
 */
function isProjectEnvFile(path: string, workingDirectory: string | undefined): boolean {
	if (!isProjectEnvPathLexical(path, workingDirectory)) return false;
	const root = projectRoot(workingDirectory) as string;
	const target = resolve(root, path.trim());
	try {
		const realRoot = realpathSync.native(root);
		const realTarget = realpathSync.native(target);
		return within(realRoot, realTarget);
	} catch (error) {
		if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") return false;
		// Nothing to read only when the name itself is absent: a dangling link
		// could be pointed at a real file outside the project later.
		try {
			lstatSync(target);
			return false;
		} catch (missing) {
			return (missing as NodeJS.ErrnoException)?.code === "ENOENT";
		}
	}
}

/** Whether project `.env` reads skip the per-call prompt under this configuration. */
export function projectEnvReadsAllowed(
	config: Pick<Config, "sensitivity"> & { project_env_reads?: Config["project_env_reads"] },
): boolean {
	const mode = config.project_env_reads ?? "auto";
	if (mode === "auto") return config.sensitivity !== "paranoid";
	return mode === "allow";
}

/**
 * The command with every project environment file reference replaced by a
 * neutral word, or null when the command changes directory (its relative
 * paths are then not under the session working directory).
 */
function withoutProjectEnvRefs(command: string, workingDirectory: string): string | null {
	if (DIRECTORY_CHANGE.test(command)) return null;
	return command.replace(SHELL_TOKEN, (token) =>
		isProjectEnvFile(token, workingDirectory) ? "project-env-file" : token,
	);
}

function patternStillMatches(match: HeuristicMatch, text: string): boolean {
	const { source, flags } = match.threat.compiledPattern;
	return new RegExp(source, flags.replace(/[gy]/g, "")).test(text);
}

/**
 * Drop the secret-file-read matches whose only subject is a project
 * environment file. A command match is dropped only when the rule no longer
 * matches once every project `.env` reference is neutralised, so
 * `cat .env ~/.aws/credentials` keeps its finding. Every other rule (writes,
 * copies, archives, encodings, exfiltration) is untouched.
 *
 * A file-tool match is dropped only for a path the call names literally. Paths
 * the extractor synthesises from a glob or a directory read
 * (`context: "credential_read"`, e.g. Grep `glob: ".env*"`) stand for files
 * nobody has looked at, possibly links out of the project, so they keep their
 * finding.
 */
export function dropProjectEnvReads(
	matches: readonly HeuristicMatch[],
	workingDirectory: string | undefined,
	artifacts: readonly Artifact[] = [],
): HeuristicMatch[] {
	if (!projectRoot(workingDirectory)) return [...matches];
	const cwd = workingDirectory as string;
	const literalPaths = new Set(
		artifacts
			.filter((a) => a.type === "file_path" && a.context !== "credential_read")
			.map((a) => a.value),
	);
	return matches.filter((match) => {
		if (!PROJECT_ENV_READ_RULES.has(match.threat.id)) return true;
		if (match.threat.matchOn.has("file_path") && !match.threat.matchOn.has("command")) {
			return !(literalPaths.has(match.artifact) && isProjectEnvFile(match.artifact, cwd));
		}
		const neutral = withoutProjectEnvRefs(match.artifact, cwd);
		return neutral === null || patternStillMatches(match, neutral);
	});
}
