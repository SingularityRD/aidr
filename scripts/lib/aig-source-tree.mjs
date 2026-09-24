import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

export function compareText(a, b) {
	return a < b ? -1 : a > b ? 1 : 0;
}

/** Git only reads local objects here; it must never inherit release private keys. */
export function sanitizedAigChildEnv(source = process.env) {
	return Object.fromEntries(
		Object.entries(source).filter(([name]) => !name.toUpperCase().includes("PRIVATE_KEY")),
	);
}

export function readPinnedYamlFiles({ aigRoot, cwd, ref = "HEAD" }) {
	return readPinnedFiles({
		aigRoot,
		cwd,
		ref,
		roots: ["data/vuln", "data/vuln_en", "data/fingerprints"],
		accept: (filePath) => filePath.endsWith(".yaml"),
	});
}

/** Read every tracked runtime data blob for image-startup attestation. */
export function readPinnedDataFiles({ aigRoot, cwd, ref = "HEAD" }) {
	return readPinnedFiles({
		aigRoot,
		cwd,
		ref,
		roots: ["data"],
		accept: () => true,
	});
}

function readPinnedFiles({ aigRoot, cwd, ref, roots, accept }) {
	if (!/^(?:HEAD|[a-f0-9]{40,64})$/i.test(ref)) throw new Error(`Invalid AIG Git ref: ${ref}`);
	const repositoryRoot = execFileSync("git", ["-C", aigRoot, "rev-parse", "--show-toplevel"], {
		cwd, encoding: "utf8", env: sanitizedAigChildEnv(), stdio: ["ignore", "pipe", "ignore"],
	}).trim();
	const relativeRoot = path.relative(repositoryRoot, aigRoot).replaceAll("\\", "/");
	if (relativeRoot === ".." || relativeRoot.startsWith("../")) throw new Error("AIG source is outside its Git checkout");
	const prefix = relativeRoot ? `${relativeRoot}/` : "";
	const resolvedRef = execFileSync(
		"git",
		["-C", repositoryRoot, "rev-parse", "--verify", `${ref}^{commit}`],
		{ cwd, encoding: "utf8", env: sanitizedAigChildEnv(), stdio: ["ignore", "pipe", "ignore"] },
	).trim();
	if (!/^[a-f0-9]{40,64}$/i.test(resolvedRef)) throw new Error(`Invalid resolved AIG commit: ${resolvedRef}`);
	const listing = execFileSync(
		"git",
		["-c", "core.quotepath=false", "-C", repositoryRoot, "ls-tree", "-rz", "--full-tree", resolvedRef, "--", ...roots.map((root) => `${prefix}${root}`)],
		{ cwd, env: sanitizedAigChildEnv(), stdio: ["ignore", "pipe", "ignore"], maxBuffer: 256 * 1024 * 1024 },
	);
	const entries = splitNulRecords(listing)
		.map((record) => {
			const tab = record.indexOf(0x09);
			if (tab < 1) throw new Error("Invalid git ls-tree record");
			const [mode, type, object] = record.subarray(0, tab).toString("ascii").split(" ");
			const pathBytes = record.subarray(tab + 1);
			const filePath = pathBytes.toString("utf8");
			if (!Buffer.from(filePath, "utf8").equals(pathBytes)) throw new Error("AIG Git path is not valid UTF-8");
			if (!filePath.startsWith(prefix)) throw new Error("AIG Git path is outside its source root");
			return { mode, type, object, path: filePath.slice(prefix.length) };
		})
		.filter((entry) => entry.type === "blob" && accept(entry.path))
		.sort((a, b) => compareText(a.path, b.path));
	if (entries.length === 0) return [];
	const batch = execFileSync("git", ["-C", repositoryRoot, "cat-file", "--batch"], {
		cwd,
		env: sanitizedAigChildEnv(),
		input: `${entries.map((entry) => entry.object).join("\n")}\n`,
		stdio: ["pipe", "pipe", "ignore"],
		maxBuffer: 256 * 1024 * 1024,
	});
	let offset = 0;
	const files = entries.map((entry) => {
		const headerEnd = batch.indexOf(0x0a, offset);
		if (headerEnd < 0) throw new Error(`Missing git cat-file header for ${entry.path}`);
		const header = batch.subarray(offset, headerEnd).toString("utf8").split(" ");
		const size = Number(header[2]);
		if (header[0] !== entry.object || header[1] !== "blob" || !Number.isInteger(size) || size < 0) {
			throw new Error(`Invalid git cat-file header for ${entry.path}`);
		}
		const start = headerEnd + 1;
		const end = start + size;
		if (end >= batch.length || batch[end] !== 0x0a) throw new Error(`Truncated git blob for ${entry.path}`);
		offset = end + 1;
		return { ...entry, contents: batch.subarray(start, end) };
	});
	if (offset !== batch.length) throw new Error("Unexpected trailing data from git cat-file");
	return files;
}

export function readWorktreeYamlFiles({ aigRoot }) {
	const files = [];
	for (const relativeRoot of ["data/vuln", "data/vuln_en", "data/fingerprints"]) {
		walk(path.join(aigRoot, ...relativeRoot.split("/")), relativeRoot);
	}
	return files.sort((a, b) => compareText(a.path, b.path));

	function walk(directory, relativeDirectory) {
		for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => compareText(a.name, b.name))) {
			const absolute = path.join(directory, entry.name);
			const relative = `${relativeDirectory}/${entry.name}`;
			if (entry.isDirectory()) walk(absolute, relative);
			else if (entry.isFile() && entry.name.endsWith(".yaml")) files.push({ path: relative, contents: readFileSync(absolute) });
		}
	}
}

/** Read every regular runtime data file from a worktree, byte for byte. */
export function readWorktreeDataFiles({ aigRoot }) {
	const files = [];
	walk(path.join(aigRoot, "data"), "data");
	return files.sort((a, b) => compareText(a.path, b.path));

	function walk(directory, relativeDirectory) {
		for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => compareText(a.name, b.name))) {
			const absolute = path.join(directory, entry.name);
			const relative = `${relativeDirectory}/${entry.name}`;
			if (entry.isDirectory()) walk(absolute, relative);
			else if (entry.isFile()) files.push({ path: relative, contents: readFileSync(absolute) });
		}
	}
}

export function pinnedSourceTreeDigest(files) {
	const digest = createHash("sha256");
	for (const file of files) {
		const pathBytes = Buffer.from(file.path, "utf8");
		const length = Buffer.allocUnsafe(4);
		length.writeUInt32BE(pathBytes.length);
		digest.update(length);
		digest.update(pathBytes);
		digest.update(createHash("sha256").update(file.contents).digest());
	}
	return digest.digest("hex");
}

function splitNulRecords(buffer) {
	const records = [];
	let start = 0;
	for (let index = 0; index < buffer.length; index++) {
		if (buffer[index] !== 0) continue;
		if (index > start) records.push(buffer.subarray(start, index));
		start = index + 1;
	}
	if (start !== buffer.length) throw new Error("Truncated git ls-tree output");
	return records;
}
