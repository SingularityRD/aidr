/** Parse the exact hash-locked runtime format installed by the AIG bridge image. */
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
		const pin = value.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)$/);
		if (!pin || line !== line.trimStart()) {
			throw new Error(`Unsupported Python runtime lock entry: ${value.slice(0, 80)}`);
		}
		if (current && current.hashes.length === 0) {
			throw new Error(`Python runtime package ${current.name} has no SHA-256 hash`);
		}
		const name = pin[1].toLowerCase().replace(/[-_.]+/g, "-");
		if (seen.has(name)) throw new Error(`Duplicate Python runtime package: ${name}`);
		seen.add(name);
		current = { name, version: pin[2], hashes: [] };
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
