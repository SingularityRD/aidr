/**
 * Deploy, list and remove canary credentials.
 *
 * Invariants:
 *   - Deploy only creates NEW files (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600). A
 *     candidate name that exists in any form, including a dangling symlink, is
 *     skipped; an existing user file is never opened for writing.
 *   - The registry records digests of the token values, never the values.
 *   - Remove deletes a decoy only while its content still matches the digest
 *     recorded at deploy time; a file someone changed is left in place.
 */

import { randomBytes } from "node:crypto";
import {
	closeSync,
	constants,
	fsyncSync,
	lstatSync,
	mkdirSync,
	openSync,
	readFileSync,
	rmdirSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { invalidateCanaryIndex } from "./detect.js";
import { CANARY_PLACEMENTS, type RandomIndex, renderCanary } from "./placements.js";
import {
	CANARY_KINDS,
	type CanaryKind,
	type CanaryRecord,
	type CanaryRegistry,
	defaultCanaryRegistryPath,
	emptyCanaryRegistry,
	readCanaryRegistry,
	sha256Hex,
	writeCanaryRegistry,
} from "./registry.js";

export interface DeployCanariesOptions {
	kinds?: readonly CanaryKind[];
	/** Root for project-scoped decoys (`env`, `db-url`). Defaults to the current directory. */
	projectDir?: string;
	/** Root for home-scoped decoys. Defaults to `$HOME`. */
	homeDir?: string;
	registryPath?: string;
	now?: () => Date;
	/** Test seam for the random source; production uses `crypto.randomInt`. */
	random?: RandomIndex;
}

export interface CanarySkip {
	kind: CanaryKind;
	reason: string;
}

export interface DeployCanariesResult {
	deployed: CanaryRecord[];
	skipped: CanarySkip[];
}

export type CanaryFileState = "intact" | "missing" | "modified" | "not_regular";

export interface CanaryStatusEntry extends CanaryRecord {
	state: CanaryFileState;
}

export interface CanaryStatusResult {
	registryPath: string;
	registry: "absent" | "ok" | "invalid";
	reason?: string;
	canaries: CanaryStatusEntry[];
}

export interface RemoveCanariesOptions {
	ids?: readonly string[];
	all?: boolean;
	registryPath?: string;
}

export interface RemovedCanary {
	id: string;
	kind: CanaryKind;
	path: string;
	/** `deleted`: the decoy was removed; any other state: the file was left as found. */
	file: "deleted" | CanaryFileState;
}

export interface RemoveCanariesResult {
	removed: RemovedCanary[];
	unknownIds: string[];
}

export function isCanaryKind(value: string): value is CanaryKind {
	return (CANARY_KINDS as readonly string[]).includes(value);
}

function defaultHome(): string {
	const envHome = process.env.HOME?.trim();
	return envHome && envHome.length > 0 ? envHome : homedir();
}

function loadRegistryForUpdate(registryPath: string): CanaryRegistry {
	const read = readCanaryRegistry(registryPath);
	if (read.status === "absent") return emptyCanaryRegistry();
	if (read.status === "invalid") {
		throw new Error(
			`The canary registry at ${registryPath} is unusable (${read.reason}); no decoy was changed.`,
		);
	}
	return read.registry;
}

function exists(path: string): boolean {
	try {
		lstatSync(path);
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
		// Unknown state: treat as present so it is never written over.
		return true;
	}
}

/** Create missing ancestors of `directory` (0700); returns the ones created, outermost first. */
function createMissingDirectories(directory: string): string[] {
	const missing: string[] = [];
	let current = directory;
	while (!exists(current)) {
		missing.unshift(current);
		const parent = dirname(current);
		if (parent === current) break;
		current = parent;
	}
	const created: string[] = [];
	for (const path of missing) {
		try {
			mkdirSync(path, { mode: 0o700 });
			created.push(path);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
				removeEmptyDirectories(created);
				throw error;
			}
		}
	}
	return created;
}

function removeEmptyDirectories(directories: readonly string[]): void {
	for (const path of [...directories].reverse()) {
		try {
			rmdirSync(path);
		} catch {
			// Not empty (the user put something there) or already gone: leave it.
		}
	}
}

/** Write `content` to a path that must not exist yet. Returns false when it already does. */
function createExclusive(path: string, content: string): boolean {
	const flags =
		constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);
	let handle: number;
	try {
		handle = openSync(path, flags, 0o600);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
		throw error;
	}
	try {
		writeSync(handle, content);
		fsyncSync(handle);
	} catch (error) {
		closeSync(handle);
		unlinkSync(path);
		throw error;
	}
	closeSync(handle);
	return true;
}

function isUnder(path: string, root: string): boolean {
	return path === root || path.startsWith(root.endsWith(sep) ? root : `${root}${sep}`);
}

export function canaryFileState(record: CanaryRecord): CanaryFileState {
	let info: ReturnType<typeof lstatSync>;
	try {
		info = lstatSync(record.path);
	} catch {
		return "missing";
	}
	if (info.isSymbolicLink() || !info.isFile()) return "not_regular";
	try {
		return sha256Hex(readFileSync(record.path)) === record.file_sha256 ? "intact" : "modified";
	} catch {
		return "missing";
	}
}

function placeCanary(
	kind: CanaryKind,
	root: string,
	now: () => Date,
	random: RandomIndex | undefined,
): { record: CanaryRecord } | { reason: string } {
	for (const candidate of CANARY_PLACEMENTS[kind].candidates) {
		const target = join(root, candidate);
		if (exists(target)) continue;
		const createdDirs = createMissingDirectories(dirname(target));
		const rendered = renderCanary(kind, random);
		let created: boolean;
		try {
			created = createExclusive(target, rendered.content);
		} catch (error) {
			removeEmptyDirectories(createdDirs);
			return { reason: `could not create ${target}: ${(error as Error).message}` };
		}
		if (!created) {
			removeEmptyDirectories(createdDirs);
			continue;
		}
		return {
			record: {
				id: `cny_${randomBytes(8).toString("hex")}`,
				kind,
				path: target,
				created_at: now().toISOString(),
				file_sha256: sha256Hex(rendered.content),
				tokens: rendered.tokens.map((token) => ({
					sha256: sha256Hex(token),
					length: token.length,
				})),
				created_dirs: createdDirs,
			},
		};
	}
	return { reason: "every candidate file name already exists; nothing was written" };
}

/** Plant one decoy per requested kind and register it. */
export function deployCanaries(options: DeployCanariesOptions = {}): DeployCanariesResult {
	const registryPath = options.registryPath ?? defaultCanaryRegistryPath();
	const registry = loadRegistryForUpdate(registryPath);
	const kinds = [...new Set(options.kinds ?? CANARY_KINDS)];
	const roots = {
		home: resolve(options.homeDir ?? defaultHome()),
		project: resolve(options.projectDir ?? process.cwd()),
	};
	const now = options.now ?? (() => new Date());
	const deployed: CanaryRecord[] = [];
	const skipped: CanarySkip[] = [];

	for (const kind of kinds) {
		const root = roots[CANARY_PLACEMENTS[kind].scope];
		const existing = registry.canaries.find(
			(record) =>
				record.kind === kind && isUnder(record.path, root) && canaryFileState(record) === "intact",
		);
		if (existing) {
			skipped.push({ kind, reason: `already deployed (${existing.id})` });
			continue;
		}
		const placed = placeCanary(kind, root, now, options.random);
		if ("record" in placed) deployed.push(placed.record);
		else skipped.push({ kind, reason: placed.reason });
	}

	if (deployed.length > 0) {
		try {
			writeCanaryRegistry(
				{ version: 1, canaries: [...registry.canaries, ...deployed] },
				registryPath,
			);
		} catch (error) {
			// An unregistered decoy would never trigger: undo what this run created.
			for (const record of deployed) deleteIfIntact(record);
			throw error;
		}
		invalidateCanaryIndex();
	}
	return { deployed, skipped };
}

function deleteIfIntact(record: CanaryRecord): RemovedCanary["file"] {
	const state = canaryFileState(record);
	if (state === "intact") {
		unlinkSync(record.path);
		removeEmptyDirectories(record.created_dirs);
		return "deleted";
	}
	if (state === "missing") removeEmptyDirectories(record.created_dirs);
	return state;
}

/** Remove the selected decoys and drop them from the registry. */
export function removeCanaries(options: RemoveCanariesOptions): RemoveCanariesResult {
	const registryPath = options.registryPath ?? defaultCanaryRegistryPath();
	const registry = loadRegistryForUpdate(registryPath);
	const wanted = new Set(options.ids ?? []);
	const known = new Set(registry.canaries.map((record) => record.id));
	const unknownIds = [...wanted].filter((id) => !known.has(id));
	const selected = registry.canaries.filter((record) => options.all || wanted.has(record.id));
	if (selected.length === 0) return { removed: [], unknownIds };

	const removed: RemovedCanary[] = selected.map((record) => ({
		id: record.id,
		kind: record.kind,
		path: record.path,
		file: deleteIfIntact(record),
	}));
	const selectedIds = new Set(selected.map((record) => record.id));
	writeCanaryRegistry(
		{ version: 1, canaries: registry.canaries.filter((record) => !selectedIds.has(record.id)) },
		registryPath,
	);
	invalidateCanaryIndex();
	return { removed, unknownIds };
}

/** Registry health plus the on-disk state of every registered decoy. */
export function canaryStatus(registryPath = defaultCanaryRegistryPath()): CanaryStatusResult {
	const read = readCanaryRegistry(registryPath);
	if (read.status === "absent") return { registryPath, registry: "absent", canaries: [] };
	if (read.status === "invalid") {
		return { registryPath, registry: "invalid", reason: read.reason, canaries: [] };
	}
	return {
		registryPath,
		registry: "ok",
		canaries: read.registry.canaries.map((record) => ({
			...record,
			state: canaryFileState(record),
		})),
	};
}
