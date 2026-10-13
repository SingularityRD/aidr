// esbuild options the RELEASE builds add on top of their own: minified output
// with the original function and class names kept (`keepNames`), so
// `error.name`, `fn.name` and stack frames still read as in the source. This is
// size and casual-reading hardening only, not obfuscation; development builds
// stay readable with source maps.
//
// Minifying renames identifiers, so the build-flavour check cannot read
// `EMBEDDED_BUILD_FLAVOR = "..."` from a release bundle. `embeddedBuildFlavors`
// reads it from both forms: the readable declaration, and in a minified bundle
// the variable `isCommercialBuild` compares (keepNames records that function's
// name next to it). It returns no flavour, never a guess, when neither form
// is found.

/** Spread into a release build's esbuild options. */
export const RELEASE_MINIFY = Object.freeze({ minify: true, keepNames: true });

/** The esbuild options to add for this build: the minify options in release mode, none otherwise. */
export function releaseMinifyOptions(isRelease) {
	return isRelease ? { ...RELEASE_MINIFY } : {};
}

const READABLE = /EMBEDDED_BUILD_FLAVOR\d* = "([a-z_]+)"/gu;
/** keepNames: `__name(fn, "isCommercialBuild")`, minified as `x(fn,"isCommercialBuild")`. */
const KEPT_NAME = /[\w$]+\(([\w$]+),"isCommercialBuild"\)/gu;
const escape = (name) => name.replaceAll("$", "\\$");

/**
 * Every build flavour (`commercial`, `development`, ...) a bundle or a core
 * dist file embeds.
 * @param {string} source
 * @returns {string[]} distinct flavours, empty when none is found
 */
export function embeddedBuildFlavors(source) {
	const flavors = new Set([...source.matchAll(READABLE)].map((match) => match[1]));
	for (const [, fn] of source.matchAll(KEPT_NAME)) {
		const compared = new RegExp(`function ${escape(fn)}\\(\\)\\{return ([\\w$]+)==="commercial"`, "u").exec(source);
		if (!compared) continue;
		// `var X="…"` or, inside a lazily initialised module, `X="…"` as a statement.
		const declared = new RegExp(`(?:\\bvar |\\blet |\\bconst |[,;{])${escape(compared[1])}="([a-z_]+)"[;,}]`, "gu");
		for (const [, flavor] of source.matchAll(declared)) flavors.add(flavor);
	}
	return [...flavors];
}
