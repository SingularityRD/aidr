#!/usr/bin/env node
import { readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function verifyFeatureAcceptance(inventory, matrix, root = repoRoot) {
	if (inventory.decision !== "NO-GO" || matrix.decision !== "NO-GO") {
		throw new Error("Feature acceptance cannot replace the candidate-bound release GO gate");
	}
	if (matrix.schema_version !== 1 || matrix.inventory !== "FEATURE_INVENTORY.json") {
		throw new Error("Unsupported feature acceptance matrix");
	}
	const ids = inventory.features.map((feature) => feature.id);
	if (new Set(ids).size !== ids.length) throw new Error("Duplicate inventory capability ID");
	const matrixIds = Object.keys(matrix.features ?? {});
	if (ids.length !== matrixIds.length || ids.some((id) => !Object.hasOwn(matrix.features, id))) {
		throw new Error("Acceptance matrix must cover exactly the inventory capability IDs");
	}
	const canonicalRoot = realpathSync(root);
	let testPointers = 0;
	for (const feature of inventory.features) {
		const record = matrix.features[feature.id];
		if (
			feature.production_accepted !== false ||
			record?.candidateLocal !== "NOT_RUN" ||
			record?.liveHost !== "NOT_RUN" ||
			record?.customer !== "NOT_RUN" ||
			record?.decision !== "NO-GO"
		) {
			throw new Error(`${feature.id}: a test file or source path is not acceptance evidence`);
		}
		if (!Array.isArray(record.localTestSources)) throw new Error(`${feature.id}: localTestSources must be an array`);
		if (new Set(record.localTestSources).size !== record.localTestSources.length) {
			throw new Error(`${feature.id}: duplicate local test pointer`);
		}
		for (const path of record.localTestSources) {
			if (typeof path !== "string" || !/\.test\.[cm]?[jt]sx?$/.test(path)) {
				throw new Error(`${feature.id}: local pointer is not a test source`);
			}
			if (isAbsolute(path)) {
				throw new Error(`${feature.id}: local test source must be a repository-relative path: ${path}`);
			}
			const fullPath = resolve(root, path);
			let canonicalPath;
			try {
				canonicalPath = realpathSync(fullPath);
			} catch {
				throw new Error(`${feature.id}: local test source is missing or outside the repository: ${path}`);
			}
			const inside = relative(canonicalRoot, canonicalPath);
			if (
				inside === "" ||
				inside === ".." ||
				inside.startsWith(`..${sep}`) ||
				isAbsolute(inside) ||
				resolve(canonicalRoot, inside) !== canonicalPath
			) {
				throw new Error(`${feature.id}: local test source is missing or outside the repository: ${path}`);
			}
			testPointers++;
		}
	}
	return { capabilities: ids.length, localTestPointers: testPointers, productionAccepted: 0, decision: "NO-GO" };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const inventory = JSON.parse(readFileSync(resolve(repoRoot, "FEATURE_INVENTORY.json"), "utf8"));
	const matrix = JSON.parse(readFileSync(resolve(repoRoot, "FEATURE_ACCEPTANCE.json"), "utf8"));
	console.log(JSON.stringify(verifyFeatureAcceptance(inventory, matrix)));
}
