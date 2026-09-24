/** Release builds replace this marker in dist after TypeScript compilation. */
const EMBEDDED_BUILD_FLAVOR: string = "__AIDR_EMBEDDED_BUILD_FLAVOR__";

function envTrue(v: string | undefined): boolean {
	const t = (v ?? "").trim().toLowerCase();
	return t === "1" || t === "true" || t === "yes" || t === "on" || t === "commercial";
}

export function isCommercialBuild(): boolean {
	// A commercial artifact cannot be demoted by changing its runtime environment.
	if (EMBEDDED_BUILD_FLAVOR === "commercial") return true;

	// Source/development builds retain the opt-in used by local commercial-mode tests.
	return (
		envTrue(process.env.AIDR_COMMERCIAL) ||
		envTrue(process.env.AIDR_BUILD) ||
		envTrue(process.env.AIDR_BUILD_FLAVOR)
	);
}
