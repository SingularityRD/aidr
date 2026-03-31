/**
 * Build flavor flags.
 *
 * We keep this runtime-configurable (env) so the same codebase can be used for
 * dev/open builds and for commercial distributions without changing build configs.
 */

function envTrue(v: string | undefined): boolean {
	const t = (v ?? "").trim().toLowerCase();
	return t === "1" || t === "true" || t === "yes" || t === "on" || t === "commercial";
}

export function isCommercialBuild(): boolean {
	return (
		envTrue(process.env.AIDR_COMMERCIAL) ||
		envTrue(process.env.AIDR_BUILD) ||
		envTrue(process.env.AIDR_BUILD_FLAVOR)
	);
}
