/**
 * MAIN-world content-script entry point (bundled by scripts/build.mjs as
 * content-main.js and injected with `world: "MAIN"` next to content.js).
 *
 * Runs in the page's own JavaScript world, so it has no extension APIs and holds no
 * data: it only installs the file-input hook (./file-input-hook.ts), which routes
 * detached and shadow-DOM file selections to the isolated guard over DOM events.
 */
import { installFileInputHook } from "./file-input-hook.js";

installFileInputHook(window);
