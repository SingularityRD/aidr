/**
 * Parse an exact hash-locked Python requirements file into SBOM entries.
 *
 * Accepts both layouts used in this repository: the `uv pip compile
 * --generate-hashes` form (hashes on continuation lines, e.g. the AIG bridge
 * runtime lock) and the compact form with hashes on the pin line (the privacy
 * worker locks). Every entry must be an exact `name==version` pin with at least
 * one SHA-256; anything else (ranges, URLs, markers, options) is rejected.
 */
export function parseHashLockedRequirements(raw) {
	const packages = [];
	const seen = new Set();
	let current;
	for (const line of raw.split(/\r?\n/)) {
		const value = line.trim().replace(/\s*\\$/, "").trim();
		if (!value || value.startsWith("#")) continue;
		const hash = value.match(/^--hash=sha256:([a-f0-9]{64})$/);
		if (hash) {
			if (!current) throw new Error("Python lock hash has no package");
			current.hashes.push(hash[1]);
			continue;
		}
		const [requirement, ...options] = value.split(/\s+/);
		const pin = requirement.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)$/);
		const inlineHashes = options.map((option) => option.match(/^--hash=sha256:([a-f0-9]{64})$/)?.[1]);
		if (!pin || line !== line.trimStart() || inlineHashes.some((digest) => !digest)) {
			throw new Error(`Unsupported Python runtime lock entry: ${value.slice(0, 80)}`);
		}
		if (current && current.hashes.length === 0) {
			throw new Error(`Python runtime package ${current.name} has no SHA-256 hash`);
		}
		const name = pin[1].toLowerCase().replace(/[-_.]+/g, "-");
		if (seen.has(name)) throw new Error(`Duplicate Python runtime package: ${name}`);
		seen.add(name);
		current = { name, version: pin[2], hashes: [...inlineHashes] };
		packages.push(current);
	}
	if (current && current.hashes.length === 0) {
		throw new Error(`Python runtime package ${current.name} has no SHA-256 hash`);
	}
	if (packages.length === 0) throw new Error("Python runtime lock is empty");
	return packages.map((pkg) => ({
		...pkg,
		hashes: [...new Set(pkg.hashes)].sort(),
	}));
}
