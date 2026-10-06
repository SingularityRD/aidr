import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

/** Bind the complete committed Git tree while exposing a modern digest. */
export function resolveGitTreeSha256(repoRoot, run = spawnSync) {
	const result = run("git", ["ls-tree", "-r", "-z", "--full-tree", "HEAD"], {
		cwd: repoRoot,
		encoding: null,
		maxBuffer: 64 * 1024 * 1024,
	});
	if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
		throw new Error("Unable to derive the committed source-tree digest.");
	}
	return `sha256:${createHash("sha256").update(result.stdout).digest("hex")}`;
}

/** Convert an npm SRI value to CycloneDX's required hexadecimal hash form. */
export function cycloneDxHashFromSri(integrity) {
	const match = String(integrity ?? "").match(/^sha(256|384|512)-([A-Za-z0-9+/]+={0,2})$/i);
	if (!match) return undefined;
	const bits = Number(match[1]);
	const encoded = match[2];
	const bytes = Buffer.from(encoded, "base64");
	if (
		bytes.byteLength !== bits / 8 ||
		bytes.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, "")
	) {
		return undefined;
	}
	return { alg: `SHA-${bits}`, content: bytes.toString("hex") };
}

/** Read package integrity entries from pnpm's pinned lockfile format. */
export function parseLockIntegrities(raw) {
	const map = new Map();
	let inPackages = false;
	let currentKey;
	const unquote = (value) => {
		const trimmed = value.trim();
		if (trimmed.startsWith("'") && trimmed.endsWith("'")) return trimmed.slice(1, -1).replace(/''/g, "'");
		if (trimmed.startsWith('"') && trimmed.endsWith('"')) return trimmed.slice(1, -1);
		return trimmed;
	};
	for (const line of raw.split(/\r?\n/)) {
		if (/^packages:\s*$/.test(line)) {
			inPackages = true;
			continue;
		}
		if (inPackages && /^snapshots:\s*$/.test(line)) break;
		const keyMatch = inPackages ? line.match(/^  (\S.*):\s*$/) : null;
		if (keyMatch) {
			currentKey = unquote(keyMatch[1]);
			continue;
		}
		if (!inPackages || !currentKey) continue;
		const inline = line.match(/^\s{4}resolution:\s*\{[^}]*integrity:\s*([^,}]+)[^}]*\}/);
		const nested = line.match(/^\s{6}integrity:\s*(\S+)\s*$/);
		const value = inline?.[1] ?? nested?.[1];
		if (value) map.set(currentKey, unquote(value));
	}
	return map;
}

export function assertPackageReleaseEvidence(repoRoot, packageDirs) {
	const missing = packageDirs.flatMap((packageDir) =>
		["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig"]
			.map((name) => path.join(packageDir, "dist", name))
			.filter((relative) => !existsSync(path.join(repoRoot, relative))),
	);
	if (missing.length > 0) throw new Error(`release package evidence is missing: ${missing.join(", ")}`);
}
