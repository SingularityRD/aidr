import { createHash } from "node:crypto";

const AUDITED_COMPATIBILITY = {
	name: "20260916000003_policy_document_draft_cas.sql",
	installedHash: "7e978767c0e454550ee35fc9f52da5bea77863ca53c0652090e8bebca291016b",
	targetHash: "bb4efd0be81d191565826d910843a0c0a2a879f77ddcb84d991d277544c070cf",
};

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function auditedLegacySql(targetSql) {
	if (typeof targetSql !== "string") return null;
	const currentHeader = "-- Compile exact submitted YAML at the Edge before applying this migration.\n";
	const legacyHeader = "-- Compile exact submitted YAML at the Edge before entering this transaction.\n";
	const bodyMarker = "-- compilation with direct table writes. Read/delete policies are unchanged.\n\n";
	const finalStatement = "grant execute on function public.save_policy_document_draft(uuid,uuid,text,text,uuid,bigint,text) to service_role;\n";
	if (!targetSql.startsWith(currentHeader) || !targetSql.includes(bodyMarker) || !targetSql.endsWith(finalStatement)) return null;
	return targetSql
		.replace(currentHeader, legacyHeader)
		.replace(bodyMarker, `${bodyMarker.slice(0, -1)}begin;\n\n`)
		.replace(finalStatement, `${finalStatement}\ncommit;\n`);
}

function auditedInstalledHash(name, targetHash, targetSql) {
	if (name !== AUDITED_COMPATIBILITY.name || targetHash !== AUDITED_COMPATIBILITY.targetHash) return null;
	if (sha256(targetSql ?? "") !== targetHash) return null;
	const legacySql = auditedLegacySql(targetSql);
	return legacySql && sha256(legacySql) === AUDITED_COMPATIBILITY.installedHash
		? AUDITED_COMPATIBILITY.installedHash
		: null;
}

export function isAuditedLegacyMigration(name, installedHash, installedSql) {
	return name === AUDITED_COMPATIBILITY.name &&
		installedHash === AUDITED_COMPATIBILITY.installedHash &&
		sha256(installedSql ?? "") === AUDITED_COMPATIBILITY.installedHash;
}

export function migrationHashesMatch(name, installedHash, targetHash, targetSql) {
	return installedHash === targetHash ||
		installedHash === auditedInstalledHash(name, targetHash, targetSql);
}

export function compatibleInstalledHashes(name, targetHash, targetSql) {
	const hashes = [targetHash];
	const installedHash = auditedInstalledHash(name, targetHash, targetSql);
	if (installedHash) hashes.push(installedHash);
	return hashes;
}
