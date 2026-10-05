/**
 * Resolve raw PyPI licence evidence (services/aig-bridge/pypi-runtime-licenses.json,
 * written by scripts/extract-pypi-license-metadata.py from the SHA-256-verified
 * wheels) into SPDX licences and an obligation class for the CycloneDX SBOM.
 *
 * Rule: never guess. A package is `unknown` unless its own Core Metadata (or a
 * pinned, reviewed resolution below) names a licence that this module can map
 * exactly. Legacy free-text and trove classifiers are accepted only from the
 * exact-string tables, and a conflict between them is `unknown`, not a vote.
 */

const OBLIGATION_RANK = { permissive: 0, "weak-copyleft": 1, "strong-copyleft": 2, unknown: 3 };

/** SPDX identifiers whose obligation class is settled and reviewed. */
const SPDX_OBLIGATION = new Map([
	["MIT", "permissive"],
	["MIT-0", "permissive"],
	["BSD-2-Clause", "permissive"],
	["BSD-3-Clause", "permissive"],
	["Apache-2.0", "permissive"],
	["ISC", "permissive"],
	["PSF-2.0", "permissive"],
	["0BSD", "permissive"],
	["Unlicense", "permissive"],
	["MPL-2.0", "weak-copyleft"],
	["LGPL-2.1-only", "weak-copyleft"],
	["LGPL-2.1-or-later", "weak-copyleft"],
	["LGPL-3.0-only", "weak-copyleft"],
	["LGPL-3.0-or-later", "weak-copyleft"],
	["EPL-2.0", "weak-copyleft"],
	["GPL-2.0-only", "strong-copyleft"],
	["GPL-2.0-or-later", "strong-copyleft"],
	["GPL-3.0-only", "strong-copyleft"],
	["GPL-3.0-or-later", "strong-copyleft"],
	["AGPL-3.0-only", "strong-copyleft"],
	["AGPL-3.0-or-later", "strong-copyleft"],
]);

/**
 * Exact legacy `License:` field strings seen in locked wheels. `ids` is empty
 * when the string fixes the family but not the SPDX version/variant (for
 * example "LGPLv3" does not say -only or -or-later), so no id is invented.
 */
const LEGACY_LICENSE_FIELD = new Map([
	["MIT", { ids: ["MIT"] }],
	["MIT License", { ids: ["MIT"] }],
	["BSD-3-Clause", { ids: ["BSD-3-Clause"] }],
	["Apache 2.0", { ids: ["Apache-2.0"] }],
	["Apache Software License 2.0", { ids: ["Apache-2.0"] }],
	["MPL-2.0", { ids: ["MPL-2.0"] }],
	[
		"GNU Lesser General Public License v3 (LGPLv3)",
		{ ids: [], family: "weak-copyleft", name: "GNU Lesser General Public License v3 (LGPLv3)" },
	],
]);

/** Exact trove classifiers; a classifier that cannot fix an id still fixes a family. */
const LICENSE_CLASSIFIERS = new Map([
	["License :: OSI Approved :: MIT License", { ids: ["MIT"] }],
	["License :: OSI Approved :: BSD License", { ids: [], family: "permissive" }],
	["License :: OSI Approved :: Apache Software License", { ids: [], family: "permissive", maybe: "Apache-2.0" }],
	["License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)", { ids: ["MPL-2.0"] }],
	[
		"License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
		{ ids: [], family: "weak-copyleft" },
	],
]);

/**
 * Reviewed resolutions for packages whose metadata is internally inconsistent.
 * Each is pinned to the exact licence-file digests it was reviewed against, so a
 * different wheel invalidates it instead of silently inheriting the decision.
 */
const REVIEWED_RESOLUTIONS = new Map([
	[
		"uvloop@0.22.1",
		{
			ids: ["MIT", "Apache-2.0"],
			operator: "unspecified",
			basis:
				"wheel description states 'dual-licensed under MIT and Apache 2.0'; LICENSE-MIT and LICENSE-APACHE are shipped; the licence field and classifiers each name only part of that",
			files: {
				"licenses/LICENSE-APACHE": "377025287798f9dcd819e1f826fa5fc5e2f382528691ab0528c5cf8c8c282c27",
				"licenses/LICENSE-MIT": "6dd4c399f26de043d77a2ad7e31db4cb5bf08ea8368b0a42d6e158635cc8ab62",
			},
		},
	],
]);

/** Tokenise and evaluate an SPDX licence expression; returns null if anything is unrecognised. */
export function parseSpdxExpression(expression) {
	const tokens = expression.match(/\(|\)|[A-Za-z0-9.+-]+/g);
	if (!tokens || tokens.join("") !== expression.replace(/\s+/g, "")) return null;
	let position = 0;
	const ids = new Set();
	const parseOr = () => {
		let rank = parseAnd();
		while (tokens[position]?.toUpperCase() === "OR") {
			position++;
			rank = Math.min(rank, parseAnd());
		}
		return rank;
	};
	const parseAnd = () => {
		let rank = parseTerm();
		while (tokens[position]?.toUpperCase() === "AND") {
			position++;
			rank = Math.max(rank, parseTerm());
		}
		return rank;
	};
	const parseTerm = () => {
		const token = tokens[position++];
		if (token === "(") {
			const rank = parseOr();
			if (tokens[position++] !== ")") throw new Error("unbalanced");
			return rank;
		}
		const obligation = token && SPDX_OBLIGATION.get(token);
		if (!obligation) throw new Error("unrecognised");
		ids.add(token);
		return OBLIGATION_RANK[obligation];
	};
	try {
		const rank = parseOr();
		if (position !== tokens.length) return null;
		const obligation = Object.keys(OBLIGATION_RANK).find((name) => OBLIGATION_RANK[name] === rank);
		return { ids: [...ids].sort(), obligation };
	} catch {
		return null;
	}
}

const unknown = (reason) => ({ obligation: "unknown", spdx: [], expression: null, name: null, basis: "none", reason, flags: [] });

/**
 * @param {object} entry one `packages[]` row of pypi-runtime-licenses.json
 * @returns {{obligation:string, spdx:string[], expression:string|null, name:string|null, basis:string, reason?:string, flags:string[]}}
 */
export function resolvePypiLicense(entry) {
	const meta = entry.core_metadata ?? {};
	const flags = [];
	const bundled = entry.bundled_native_libraries ?? [];
	if (bundled.length > 0) {
		flags.push(
			`bundles ${bundled.length} native librar${bundled.length === 1 ? "y" : "ies"} under *.libs/ whose own licences are not declared in the wheel metadata`,
		);
	}
	const finish = (result) => ({ ...result, flags });

	if (meta.license_expression) {
		const parsed = parseSpdxExpression(meta.license_expression);
		if (!parsed) return finish(unknown(`License-Expression "${meta.license_expression}" contains an identifier this module has not reviewed`));
		return finish({
			obligation: parsed.obligation,
			spdx: parsed.ids,
			expression: meta.license_expression,
			name: null,
			basis: "core-metadata:License-Expression",
		});
	}

	const classifiers = (meta.license_classifiers ?? []).map((value) => LICENSE_CLASSIFIERS.get(value) ?? null);
	if (classifiers.includes(null)) return finish(unknown("licence classifier is not in the reviewed table"));
	const field = meta.license_field ? LEGACY_LICENSE_FIELD.get(meta.license_field) : undefined;

	const reviewed = REVIEWED_RESOLUTIONS.get(`${entry.name}@${entry.version}`);
	const fieldIds = field?.ids ?? [];
	const classifierIds = [...new Set(classifiers.flatMap((item) => item.ids))];
	const consistent = field && classifierIds.every((id) => fieldIds.includes(id)) &&
		classifiers.every((item) => item.ids.length > 0 || !item.maybe || fieldIds.includes(item.maybe));

	if (consistent) {
		const family = fieldIds.length > 0
			? fieldIds.map((id) => SPDX_OBLIGATION.get(id)).sort((a, b) => OBLIGATION_RANK[b] - OBLIGATION_RANK[a])[0]
			: field.family;
		if (family && classifiers.every((item) => !item.family || item.family === family)) {
			return finish({
				obligation: family,
				spdx: fieldIds,
				expression: fieldIds.length === 1 ? fieldIds[0] : null,
				name: fieldIds.length === 0 ? field.name : null,
				basis: "core-metadata:License(field)+classifiers",
			});
		}
	}

	if (reviewed) {
		const shipped = new Map((entry.license_files ?? []).map((file) => [file.path, file.sha256]));
		const pinnedMatches = Object.entries(reviewed.files).every(([file, digest]) => shipped.get(file) === digest);
		if (pinnedMatches && shipped.size === Object.keys(reviewed.files).length) {
			const obligation = reviewed.ids
				.map((id) => SPDX_OBLIGATION.get(id))
				.sort((a, b) => OBLIGATION_RANK[b] - OBLIGATION_RANK[a])[0];
			return finish({ obligation, spdx: [...reviewed.ids].sort(), expression: null, name: null, basis: `reviewed:${reviewed.basis}` });
		}
		return finish(unknown("reviewed resolution no longer matches the shipped licence files; re-review"));
	}
	return finish(unknown(field ? "licence field and classifiers disagree" : "no SPDX expression and the legacy licence field is not in the reviewed table"));
}

/**
 * Bind the evidence file to the exact lock being shipped.
 * Returns the evidence per locked package, or the reasons it cannot be trusted.
 */
export function bindPypiLicenseEvidence(evidenceJson, lockDigest, lockedPackages) {
	const problems = [];
	let evidence;
	try {
		evidence = JSON.parse(evidenceJson);
	} catch {
		return { byName: new Map(), problems: ["licence evidence file is missing or not valid JSON"] };
	}
	if (evidence.source_lock_sha256 !== lockDigest) {
		problems.push("licence evidence was extracted from a different requirements-runtime.lock; re-run scripts/extract-pypi-license-metadata.py");
	}
	const byName = new Map((evidence.packages ?? []).map((entry) => [entry.name, entry]));
	for (const locked of lockedPackages) {
		const entry = byName.get(locked.name);
		if (!entry) problems.push(`no licence evidence for ${locked.name}@${locked.version}`);
		else if (entry.version !== locked.version || !locked.hashes.includes(entry.wheel_sha256)) {
			problems.push(`licence evidence for ${locked.name}@${locked.version} is not from a wheel pinned by the lock`);
			byName.delete(locked.name);
		}
	}
	return { byName, problems };
}

/** CycloneDX `licenses` array for a resolved licence, or undefined when unknown. */
export function cycloneDxLicenses(resolved) {
	if (resolved.obligation === "unknown") return undefined;
	if (resolved.expression && resolved.spdx.length > 1) return [{ expression: resolved.expression }];
	if (resolved.spdx.length > 0) return resolved.spdx.map((id) => ({ license: { id } }));
	return [{ license: { name: resolved.name } }];
}
