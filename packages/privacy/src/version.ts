/**
 * Engine version reported in every audit summary (`audit.engineVersion`). Kept equal to
 * this package's version by `scripts/sync-manifests.mjs` (`pnpm run version`) and checked
 * by `pnpm verify:manifests` and tests/version.test.mjs.
 */
export const ENGINE_VERSION = '0.6.0';
