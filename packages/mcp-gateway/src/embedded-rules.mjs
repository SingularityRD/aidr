// Development placeholder. The release build (scripts/build.mjs) replaces this
// module with the repository's threat and trusted-domain rule files so the
// bundled gateway carries its detection data inside the signed artifact. When
// it is null, the gateway reads the rule directories from the source checkout.
export const EMBEDDED_RULE_SETS = null;
